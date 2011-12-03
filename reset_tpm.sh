killall tpmd
service tcsd stop
rmmod tpmd_dev
rm -f /var/lib/tpm/tpm_emulator-1_2_0_7

sync
sleep 1

modprobe tpmd_dev
/usr/local/bin/tpmd
service tcsd start

tpm_takeownership
