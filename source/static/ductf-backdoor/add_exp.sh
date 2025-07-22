#!/bin/bash

nasm -f elf64 exp.S -o exp.o
ld -s exp.o -o exp
rm exp.o
mv exp rootfs/exp

pushd . && pushd rootfs
sudo find . | sudo cpio -o -H newc --owner=root:root | gzip -c > ../rootfs.cpio.gz
popd