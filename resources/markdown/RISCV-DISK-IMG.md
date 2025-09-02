# Build a disk image for RISC-V ubuntu
This is for a full-system disk image for [gem5](https://www.gem5.org/) simulations.

## Dependencies

 - A statically compiled version of [RISC-V qemu](https://risc-v-getting-started-guide.readthedocs.io/en/latest/linux-qemu.html)
 - [RISC-V Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain)

## Setup env

Note: If you are starting from scratch, you can largely follow this in-order.

```
mkdir mnt
```
## Load RISC-V disk image contents with gem5 binaries, etc.
This can also be done from within a file, see gem5 resources

```
wget https://gem5resources.blob.core.windows.net/dist-gem5-org/dist/develop/images/riscv/riscv-ubuntu-22.04.gz
gzip -d riscv-ubuntu-22.04.gz
```

## Mount the image, if error, keep retrying
```
sudo python3 util/gem5img.py mount resources/binaries/riscv-ubuntu-22.04 mnt
```

## If you need to unmount
You should unmount after you are done
```
sudo python3 util/gem5img.py umount mnt
```

## Copy appropriate system files onto image
This is important for a few files that the image will need to borrow from a real system
```
sudo cp /etc/resolv.conf mnt/etc/ --remove-destination 
sudo /bin/mount -o bind /dev/null mnt/dev/null
```

## Chroot into the image to open a shell within
Try:
```
sudo chroot mnt qemu-riscv64-static /bin/bash
```

If that does not work, you can chroot using:

```
sudo chroot mnt
```

## change permissions 
```
chmod 777 mnt
chown -R man: /var/cache/man/
```

```exit```  optional for full shell

## Update and clone repositories 

```
apt update
apt install git
```

Now, clone any repo you like

Connect with a terminal:

```
./util/term/m5term localhost 3456
```

## For gem5
For riscv, to cross compile the m5 binary, this can be done from the ~/gem5/util/m5 directory in a similar manner to how you build the gem5 binary.
```
scons riscv.CROSS_COMPILE=/home/wbuziak/../../opt/riscv/bin/riscv64-unknown-linux-gnu- build/riscv/out/m5
```

You will then want to copy this binary onto your disk image sbin/ folder, as per the [disk-image](https://www.gem5.org/documentation/general_docs/fullsystem/disks) documentation.

-----

You may also want to compile [the util/term/m5term binary](https://www.gem5.org/documentation/general_docs/fullsystem/m5term) that allows you to connect to a FS serial terminal with the following command:

```
./util/term/m5term localhost 3456
```

-----

Finally, ensure that you have a proper init script that loads your readfile contents that contain the shell commands for your benchmark. It will look something like sbin/gem5_init.sh:

```
#!/bin/sh
m5 readfile > script.sh
if [ -s script.sh ]; then
    # if the file is not empty then execute it
    chmod +x script.sh
    ./script.sh
    m5 exit
# otherwise, drop to terminal/exit simulation
else
    # Directly log in as the gem5 user
    printf "Dropping to shell as gem5 user...\n"
    exec su - gem5
fi

m5 exit
```

Note: if you experience issues, check that sbin/gem5_init.sh is fully executable.

