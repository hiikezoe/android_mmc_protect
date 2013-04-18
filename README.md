## View write protect status

    $ cat /sys/kernel/mmc_protect/status

## Clear write protect

    $ echo -n "mmcblk0p12" > /sys/kernel/mmc_protect/clear
