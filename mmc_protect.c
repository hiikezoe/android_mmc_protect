/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/hdreg.h>
#include <linux/kdev_t.h>
#include <linux/miscdevice.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/platform_device.h>

struct another_mmc_csd {
  uint8_t erase_grp_size;
  uint8_t erase_grp_mult;
  uint8_t wp_grp_size;
  uint8_t wp_grp_enable;
};

static struct bus_type *g_mmc_bus;

static struct mmc_card *
get_mmc_card(void)
{
  struct device *card_dev;

  card_dev = bus_find_device_by_name(g_mmc_bus, NULL, "mmc0:0001");
  if (!card_dev) {
    return NULL;
  }

  return mmc_dev_to_card(card_dev);
}

#define UNSTUFF_BITS(resp,start,size)                       \
  ({                                                        \
   const int __size = size;                                 \
   const u32 __mask = (__size < 32 ? 1 << __size : 0) - 1;  \
   const int __off = 3 - ((start) / 32);                    \
   const int __shft = (start) & 31;                         \
   u32 __res;                                               \
                                                            \
   __res = resp[__off] >> __shft;                           \
   if (__size + __shft > 32)                                \
   __res |= resp[__off-1] << ((32 - __shft) % 32);          \
   __res & __mask;                                          \
   })

static void
get_csd(struct mmc_card *card, struct another_mmc_csd *csd)
{
  csd->erase_grp_size = UNSTUFF_BITS(card->raw_csd, 42, 5);
  csd->erase_grp_mult = UNSTUFF_BITS(card->raw_csd, 37, 5);
  csd->wp_grp_size = UNSTUFF_BITS(card->raw_csd, 32, 5);
  csd->wp_grp_enable = UNSTUFF_BITS(card->raw_csd, 31, 1);
}

#define MMC_CMD_RETRIES 3
static int
mmc_send_status(struct mmc_card *card, u32 *status)
{
  int err;
  struct mmc_command cmd;

  BUG_ON(!card);
  BUG_ON(!card->host);

  memset(&cmd, 0, sizeof(struct mmc_command));

  cmd.opcode = MMC_SEND_STATUS;
  if (!mmc_host_is_spi(card->host)) {
    cmd.arg = card->rca << 16;
  }
  cmd.flags = MMC_RSP_SPI_R2 | MMC_RSP_R1 | MMC_CMD_AC;

  err = mmc_wait_for_cmd(card->host, &cmd, MMC_CMD_RETRIES);
  if (err) {
    return err;
  }

  /* NOTE: callers are required to understand the difference
   * between "native" and SPI format status words!
   */
  if (status) {
    *status = cmd.resp[0];
  }

  return 0;
}

static int
get_card_status(struct mmc_card *card, u32 *status)
{
  do {
    int err = mmc_send_status(card, status);
    if (err) {
      mmc_release_host(card->host);
      return err;
    }
    if (card->host->caps & MMC_CAP_WAIT_WHILE_BUSY) {
      break;
    }
    if (mmc_host_is_spi(card->host)) {
      break;
    }
  } while (R1_CURRENT_STATE(*status) == 7);

  return 0;
}

static bool
clear_write_protect(struct mmc_card *card, u32 start, u32 size)
{
  struct another_mmc_csd csd;
  struct mmc_command cmd;
  u32 write_protect_group_size;
  int error;
  unsigned int i, loop_count;

  mmc_claim_host(card->host);

  get_csd(card, &csd);

  write_protect_group_size = (csd.erase_grp_size + 1) * (csd.erase_grp_mult + 1) * (csd.wp_grp_size + 1);

  memset(&cmd, 0, sizeof(struct mmc_command));

  cmd.opcode = MMC_CLR_WRITE_PROT;
  cmd.flags = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;

  loop_count = size / write_protect_group_size;
  for (i = 0; i < loop_count; i++) {
    u32 status;
    cmd.arg = start + i * write_protect_group_size;
    error = mmc_wait_for_cmd(card->host, &cmd, MMC_CMD_RETRIES);
    if (error) {
      break;
    }
    error = get_card_status(card, &status);
    if (error) {
      break;
    }
  }

  if (error) {
    printk(KERN_ERR "Failed to clear write protect error(%x)\n", error);
  }

  mmc_release_host(card->host);

  return true;
}

static int
mmc_send_cxd_data(struct mmc_card *card, struct mmc_host *host,
                  u32 opcode, u32 arg, u32 flags, void *buf, unsigned len)
{
  struct mmc_request mrq;
  struct mmc_command cmd;
  struct mmc_data data;
  struct scatterlist sg;
  void *data_buf;

  /* dma onto stack is unsafe/nonportable, but callers to this
   * routine normally provide temporary on-stack buffers ...
   */
  data_buf = kmalloc(len, GFP_KERNEL);
  if (data_buf == NULL) {
    return -ENOMEM;
  }

  memset(&mrq, 0, sizeof(struct mmc_request));
  memset(&cmd, 0, sizeof(struct mmc_command));
  memset(&data, 0, sizeof(struct mmc_data));

  mrq.cmd = &cmd;
  mrq.data = &data;

  cmd.opcode = opcode;
  cmd.arg = arg;

  /* NOTE HACK:  the MMC_RSP_SPI_R1 is always correct here, but we
   * rely on callers to never use this with "native" calls for reading
   * CSD or CID.  Native versions of those commands use the R2 type,
   * not R1 plus a data block.
   */
  cmd.flags = flags; //MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

  data.blksz = len;
  data.blocks = 1;
  data.flags = MMC_DATA_READ;
  data.sg = &sg;
  data.sg_len = 1;

  sg_init_one(&sg, data_buf, len);

  if (opcode == MMC_SEND_CSD || opcode == MMC_SEND_CID) {
    /*
     * The spec states that CSR and CID accesses have a timeout
     * of 64 clock cycles.
     */
    data.timeout_ns = 0;
    data.timeout_clks = 64;
  } else {
    mmc_set_data_timeout(&data, card);
  }

  mmc_wait_for_req(host, &mrq);

  memcpy(buf, data_buf, len);
  kfree(data_buf);

  if (cmd.error) {
    return cmd.error;
  }
  if (data.error) {
    return data.error;
  }

  return 0;
}

#define WRITE_PROTECT_INFO_BITS 32
#define CMD31_SEND_WRITE_PROT_TYPE 31
static int
print_write_protect_status(struct mmc_card *card, char *buffer)
{
  struct another_mmc_csd csd;
  u32 write_protect_group_size;
  u32 group_count;
  u32 status;
  u32 address;
  int error;
  int ret = 0;

  mmc_claim_host(card->host);

  get_csd(card, &csd);

  write_protect_group_size = (csd.erase_grp_size + 1) * (csd.erase_grp_mult + 1) * (csd.wp_grp_size + 1);
  group_count = card->ext_csd.sectors / write_protect_group_size;

  error = get_card_status(card, &status);
  if (error) {
    mmc_release_host(card->host);
    return 0;
  }

  for (address = 0; address < group_count; address += WRITE_PROTECT_INFO_BITS) {
    u64 write_protect_status;
    error = mmc_send_cxd_data(card, card->host,
                              CMD31_SEND_WRITE_PROT_TYPE,
                              address * write_protect_group_size,
                              MMC_CMD_ADTC | MMC_RSP_R1,
                              &write_protect_status, sizeof(write_protect_status));
    if (error) {
      printk(KERN_ERR "Failed to get write protect status %x\n", error);
      mmc_release_host(card->host);
      return ret;
    }
    ret += sprintf(buffer + ret, "0x%08x (0x%016llx)\n",
                   address * write_protect_group_size, write_protect_status);
  }

  mmc_release_host(card->host);
  return ret;
}

static ssize_t
mmc_protect_show(struct device *dev, struct device_attribute *attr, char *buffer)
{
  struct mmc_card *card;
  card = get_mmc_card();
  if (!card) {
    return 0;
  }
  return print_write_protect_status(card, buffer);
}

static DEVICE_ATTR(status, S_IRUGO, mmc_protect_show, NULL);

static ssize_t
mmc_protect_clear(struct device *dev, struct device_attribute *attr,
                  const char *buf, size_t count)
{
  char *device_path;
  struct block_device *target = NULL;
  u32 start;
  u32 size;
  bool device_holding = false;
  struct mmc_card *card;

  card = get_mmc_card();
  if (!card) {
    return count;
  }

  device_path = kmalloc(PATH_MAX + count, GFP_KERNEL);
  if (!device_path) {
    return -ENOMEM;
  }

  snprintf(device_path, PATH_MAX, "/dev/block/%s", buf);
  target = lookup_bdev(device_path);
  if (!target) {
    kfree(device_path);
    return count;
  }

  if (!target->bd_part) {
    if (blkdev_get(target, FMODE_READ | FMODE_NDELAY, 0)) {
      kfree(device_path);
      return count;
    }
    device_holding = true;
  }

  start = (u32)target->bd_part->start_sect;
  size = (u32)target->bd_part->nr_sects;

  clear_write_protect(card, start, size);
  if (device_holding) {
    blkdev_put(target, FMODE_READ | FMODE_NDELAY);
  }
  kfree(device_path);

  return count;
}

static DEVICE_ATTR(clear, S_IWUGO, NULL, mmc_protect_clear);

static struct attribute *dev_attrs[] = {
  &dev_attr_status.attr,
  &dev_attr_clear.attr,
  NULL,
};

static struct attribute_group dev_attr_grp = {
  .attrs = dev_attrs,
};

static struct kobject *mmc_protect_kobj;

static struct mmc_driver mmc_driver = {
  .drv    = {
    .name = "mmc_protect",
  },
};

static int __init mmc_protect_init(void)
{
  mmc_protect_kobj = kobject_create_and_add("mmc_protect", kernel_kobj);
  if (!mmc_protect_kobj) {
    return -ENOMEM;
  }

  mmc_register_driver(&mmc_driver);
  g_mmc_bus = mmc_driver.drv.bus;
  mmc_unregister_driver(&mmc_driver);

  return sysfs_create_group(mmc_protect_kobj, &dev_attr_grp);
}

static void __exit mmc_protect_exit(void)
{
  sysfs_remove_group(mmc_protect_kobj, &dev_attr_grp);
  kobject_put(mmc_protect_kobj);
}

module_init(mmc_protect_init);
module_exit(mmc_protect_exit);
MODULE_AUTHOR("Hiroyuki Ikezoe");
MODULE_DESCRIPTION("MMC Protect Handle Driver");
MODULE_LICENSE("GPL v2");
