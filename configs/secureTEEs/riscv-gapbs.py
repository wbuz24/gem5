# Copyright (c) 2021 The Regents of the University of California
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
This script shows an example of running a full system RISCV Ubuntu boot
simulation using the gem5 library. This simulation boots Ubuntu 20.04 using
2 TIMING CPU cores. The simulation ends when the startup is completed
successfully.

Usage
-----

```
scons build/RISCV/gem5.opt
./build/RISCV/gem5.opt \
    configs/example/gem5_library/riscv-ubuntu-run.py
```
"""

import m5
from m5.objects import Root

import argparse

from gem5.components.boards.riscv_board import RiscvBoard
from gem5.components.memory import DualChannelDDR4_2400
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.components.memory.secure import SecureSimpleMemory
from gem5.components.memory.secure import SecureMemorySystem
from gem5.components.cachehierarchies.classic.no_cache import NoCache
from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import PrivateL1SharedL2CacheHierarchy
from gem5.components.cachehierarchies.classic.secure_cache_hierarchy import SecurePrivateL1PrivateL2CacheHierarchy
from gem5.isas import ISA
from gem5.resources.resource import obtain_resource
from gem5.resources.resource import KernelResource
from gem5.resources.resource import DiskImageResource
from gem5.resources.resource import BootloaderResource
from gem5.simulate.simulator import Simulator
from gem5.utils.requires import requires

# args
parser = argparse.ArgumentParser()
parser.add_argument(
  "--disk-image",
  type=str,
  required=False,
  help="Input disk image",
)

args = parser.parse_args()

# This runs a check to ensure the gem5 binary is compiled for RISCV.

requires(isa_required=ISA.RISCV)

# Here we setup the parameters of the l1 and l2 caches.
cache_hierarchy = PrivateL1SharedL2CacheHierarchy(
    l1d_size="16kB", l1i_size="16kB", l2_size="256kB"
)

# Memory: Dual Channel DDR4 2400 DRAM device.
memory = SecureSimpleMemory(size="3GB")

# Here we setup the processor. We use a simple processor.
processor = SimpleProcessor(
    cpu_type=CPUTypes.ATOMIC, isa=ISA.RISCV, num_cores=1
)

# Here we setup the board. The RiscvBoard allows for Full-System RISCV
# simulations.
board = RiscvBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
)

# Here we a full system workload: "riscv-ubuntu-20.04-boot" which boots
# Ubuntu 20.04. Once the system successfully boots it encounters an `m5_exit`
# instruction which stops the simulation. When the simulation has ended you may
# inspect `m5out/system.pc.com_1.device` to see the stdout.

command = (
    f"pwd;" 
    + f"cd repos/gapbs;" \
    + f"./bfs -g 10 -n 1;" \
    + "m5 exit;" \
)

board.set_kernel_disk_workload(
    bootloader = BootloaderResource(local_path='/home/wbuziak/repos/gem5/resources/binaries/riscv-bootloader-opensbi-1.3.1-20231129'),
    kernel=KernelResource(local_path='/home/wbuziak/repos/gem5/resources/binaries/linux-kernel-6.5.5'),
    disk_image=DiskImageResource(local_path='/home/wbuziak/repos/gem5/resources/binaries/riscv-ubuntu-22.04'),
    readfile_contents=command,
)

simulator = Simulator(board=board)
simulator.run()
