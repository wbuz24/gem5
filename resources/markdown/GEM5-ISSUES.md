# Issues encountered with gem5
Note: 

 - Most of these issues/fixes are geared towards the RISC-V compiled gem5 version 24.0.0.1+, though many of these solutions still apply to other ISA's and can simply swap ```riscv``` with the desired ISA.

 - The same cannot be said about different gem5 versions, as gem5 is vulnerable to major changes at any point. Most of this work utilizes the ```board``` class as opposed to the deprecated ```system``` class.

## Solved Issues

### Full-System
### Disk-Image
When running FS-mode, gem5 does not automatically point to the correct filesystem to search for the mounted disk image ([Seen here](https://stackoverflow.com/questions/63277677/gem5-full-system-linux-boot-fails-with-kernel-panic-not-syncing-vfs-unable)).

Within ```src/python/gem5/components/boards/riscv_board.py``` (or equivalent ISA's board), change the ```get_disk_device()``` function to point to ```/dev/vda1``` instead of "/dev/vda":
```
@overrides(KernelDiskWorkload)
def get_disk_device(self):
    return "/dev/vda1"
```
 
If you fail to see benchmark results / expected outputs on the terminal when running FS, it is possible that the [init script](https://www.gem5.org/documentation/gem5-stdlib/x86-full-system-tutorial) was never called. First, ensure that the script has executable permissions.

## Unsolved Issues

### Full-System
### Disk-Image
 - Issues mounting image on other devices
 - Pre-compiled [gapbs disk image](https://resources.gem5.org/resources/riscv-ubuntu-24.04-gapbs-bfs-set?version=1.0.0) from gem5 resources does not boot

### A list of dependencies can be found below
