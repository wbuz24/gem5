# Gem5 Resource

Gem5 is a state-of-the-art architecture simulator. It is used by researchers and industry folks to come up with custom architectures and/or custom devices in those architectures to model their performance and behavior. It has a Python front-end (where these architectures are declared) and a C++ backend (where the logic for each device is defined). The tool is powerful, but has its limitations as well. At a high level, it works by treating the hardware routines of every device as a lambda function with an associated cycle number, which it then puts into a central queue and pops the hardware routine from the queue to execute. This document aims to serve as a reference for the parts of gem5 that you will need for this semester, highlighting the appropriate documentation and providing examples for (hopefully) everything you need to be successful this semester. It is also a live document and will be updated with feedback and clarifications.

## Usage

Running gem5 is intended to be done in bash on a Linux machine. You may find workarounds to install gem5 on non-Linux machines, but, much of gem5 documentation is outdated or scattered and is largely targeted towards Ubuntu machines. With that said, gem5 is runnable on other machines and operating systems.

To run gem5, you will need to specify at least the binary (found at `build/<ISA>/gem5.<binary type>`) and a runtime configuration (a Python file typically found in the *configs* directory). In this class, most assignments will require you to use a RISC-V emulated processor, and it will be advantageous to have the `gem5.debug` binary (compiles each source file with debug flags). To compile this version of gem5, call:
`scons build/RISCV/gem5.debug -j 4`

The flag `-j 4` tells scons (the compilation tool) that you would like to compile 4 files in parallel, which may be useful as there are a lot of source files to compile (not uncommon for initial compilation to take several hours without parallelism). After the first compilation, however, gem5 caches the file state so it only needs to recompile the modified files, the files that are imported by modified files, and the files that import a modified file. This means subsequent compilations are much faster.

After the binary is compiled, you can run gem5 with the command `build/RISCV/gem5.debug configs/assignments/hello.py`. What this does is create a simulation as specified by the Python runtime file *configs/assignments/hello.py*, which creates a simple architecture with a CPU and memory, and runs the file *tests/test-progs/hello/bin/riscv/linux/hello*. When you call this command, you will see output that looks like:
```
gem5 Simulator System.  https://www.gem5.org
gem5 is copyrighted software; use the --copyright option for details.

gem5 version 23.1.0.0
gem5 compiled <compilation date/time>
gem5 started <simulation start date/time>
gem5 executing on <your machine>, pid <your pid>
command line: build/RISCV/gem5.debug configs/assignments/hello.py

Global frequency set at 1000000000000 ticks per second
warn: No dot file generated. Please install pydot to generate the dot file and pdf.
build/RISCV/mem/dram_interface.cc:690: warn: DRAM device capacity (8192 Mbytes) does not match the address range assigned (512 Mbytes)
build/RISCV/base/statistics.hh:280: warn: One of the stats is a legacy stat. Legacy stat is a stat that does not belong to any statistics::Group. Legacy stat is deprecated.
0: system.remote_gdb: listening for remote gdb on port <port>
Beginning simulation!
info: Entering event queue @ 0.  Starting simulation...
Hello world!
Exiting @ tick <tick> because exiting with last active thread context
```

Much of the output from a run is benign legacy messages, and for the most part can be ignored. The output from the application begins after "Starting simulation..." but may be mixed in with other warnings from the backend. For the most part, these are benign (but may be useful in the event of incorrect behavior).

[^1]: A minor note, we are using gem5 version 24.0.0.1 for this class. If you pull from the central gem5 repository, you may get a different version of the simulator where the syntax is distinctly different. To ensure everything is consistent, please use the gem5 repository associated with the course page and/or clone version 24.0.0.1.

## Python Front-End

Users can create and run a custom hardware by creating a Python front-end with their desired components. Let's look at *configs/assignments/hello.py*:

```
# Copyright (c) 2015 Jason Power
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

import m5
from m5.objects import *

system = System()

system.clk_domain = SrcClockDomain()
system.clk_domain.clock = "1GHz"
system.clk_domain.voltage_domain = VoltageDomain()

system.mem_mode = "timing"
system.mem_ranges = [AddrRange("512MB")]
system.cpu = RiscvTimingSimpleCPU()

system.membus = SystemXBar()

system.cpu.icache_port = system.membus.cpu_side_ports
system.cpu.dcache_port = system.membus.cpu_side_ports

system.cpu.createInterruptController()

system.mem_ctrl = MemCtrl()
system.mem_ctrl.dram = DDR3_1600_8x8()
system.mem_ctrl.dram.range = system.mem_ranges[0]
system.mem_ctrl.port = system.membus.mem_side_ports

system.system_port = system.membus.cpu_side_ports

thispath = os.path.dirname(os.path.realpath(__file__))
binary = os.path.join(
    thispath,
    "../../../",
    "tests/test-progs/hello/bin/riscv/linux/hello",
)

system.workload = SEWorkload.init_compatible(binary)

process = Process()
process.cmd = [binary]
system.cpu.workload = process
system.cpu.createThreads()

root = Root(full_system=False, system=system)
m5.instantiate()

print(f"Beginning simulation!")
exit_event = m5.simulate()
print(f"Exiting @ tick {m5.curTick()} because {exit_event.getCause()}")
```

There are a few things to note about what is going on. First, notice that we import the `m5` module. What this allows is for the Python front end to import all of the SimObjects created by the C++ backend. Every device that is to be emulated in the simulation needs a backend SimObject. For example, the declaration `system = System()` will call the constructor for the C++ object `System`, which is defined in the backend. There are three other things to note about this file:
1. The construction of the CPU,
2. The construction of the memory device, and
3. How these devices interact with the memory bus.

The CPU is declared as a `RiscvTimingSimpleCPU`. There are several CPU types in gem5, each of which has a slightly different capability. There is:
1. <ISA>AtomicSimpleCPU: a model used for fast forwarding simulations and does not model accurate timings of behaviors (will only potentially be used in the final project);
2. <ISA>TimingSimpleCPU: a very simple "single-cycle" processor with timing accurate behaviors (unlikely to be used in this course);
3. <ISA>MinorCPU: an in-order pipelined CPU that has a very simple four-stage pipeline and timing accurate behaviors (will be used/modified in the Paranoid Prediction Processor assignment); and
4. <ISA>DerivO3CPU: a seven-stage pipline, out-of-order (O3) processor that most closely resembles commodity compute devices (will be used/modified in the ISA assingment).

Beyond the processor, this file creates a memory device (`system.mem_ctrl.dram`) and a bus (`system.membus`). Recall that a bus is used to connect one or more input ports to one or more output ports and behaves as an interconnect between levels of the memory hierarchy (for coherence, etc.). Key to these devices is the syntax for connecting ports. In gem5, ports can be connected in the Python configurations merely by saying `port_a = port_b`. In this case, the processor has two ports, one to fetch data from the instruction cache and one from the data cache, both of which point to the memory side. In this particular architecture there are no caches, so both ports are connected directly to the CPU side ports of the memory bus. Then, the memory side port of the memory bus is connected to the memory controller's CPU side port, and the memory controller maintains an internal reference to the memory device itself.

The final thing to note on this particular configuration is that the path of the binary to execute gets passed as input to the `system.workload` and to the `Process` object. The full implementation of this is less important, but we can change the executable to run by changing this path. Later, we will describe how to pass variables to this runtime as input.

### Extending Your Configuration

Suppose we wanted to add a level 1 cache to our configuration. We want an instruction cache and we want a data cache. We can do this declaring the following classes in our configuration:
```
from m5.objects import Cache

class ICache(Cache):
    size = '16kB'
    assoc = 2
    tag_latency = 2
    data_latency = 2
    response_latency = 2
    mshrs = 4
    tgts_per_mshr = 20

class DCache(Cache):
    size = '64kB'
    assoc = 2
    tag_latency = 2
    data_latency = 2
    response_latency = 2
    mshrs = 4
    tgts_per_mshr = 20
```

After defining what these objects are, we need to declare instances of these objects in our simulation by declaring `system.icache = ICache()` and `system.dcache = DCache()`. Finally, we can connect these objects to the processor by declaring `system.cpu.icache_port = system.icache.cpu_side`, `system.cpu.dcache_port = system.dcache.cpu_side`. The caches can then be connected to the memory bus by calling `system.icache.mem_side = system.membus.cpu_side_ports` and `system.dcache.mem_side = system.membus.cpu_side_ports`.

Let's recap what we did. We declared what two instances of caches would look like by creating Python classes for each instance of these caches. This is because `Cache` is an m5 object declared and defined in the gem5 backend, but it is kept general with various specs left to be declared later. Then, we instantiated and connected these objects to the simulator itself by attaching the ports.

A handy tool to visualize all of the features is to look in the output directory for the simulation post run (typically *m5out* unless otherwise specified) for the *config.json* or *config.ini* files. If you have the `pydot` library installed, some gem5 versions will also output a PDF of you configured simulation as well. You can use the contents of these files to verify that complex configurations appear as expected.

### Variable Features

Suppose you wanted to see the impact of varying data cache sizes. It's tedious to have to go into the configuration every time and modify the size parameter, and it can be hard to keep track of the results. Fortunately, gem5 allows for passing custom parameters to the simulation via the command line to customize the run without having to modify the configuration. Let's modify our DCache class so that it works from a size passed by the command line:

```
from m5.objects import Cache

# Add the common scripts to our path
m5.util.addToPath("../..")
from common import SimpleOpts

class DCache(Cache):
    size = '64kB'

    SimpleOpts.add_option(
        '--dcache-size', help=f"Size of the data cache. Default: {size}"
    )

    assoc = 2
    tag_latency = 2
    data_latency = 2
    response_latency = 2
    mshrs = 4
    tgts_per_mshr = 20
```

This new declaration of the data cache enables the user to pass this flag to the launch command, and specify the cache size without needing to modify the configuration script. Now, to run our simulation with a different cache size, we can run `build/RISCV/gem5.debug configs/assignments/hello.py --dcache-size=32kB` to run with a 32kB cache. Note, this will probably overwrite our previous results, which may be undesirable. If you look at the file *configs/common/SimpleOpts.py* you'll find a whole host of additional options. One that may be useful is the `--outdir` (or `-d` for shorthand) flag, which writes all output to the directory specified (and creates a new one if the path doesn't exist). For example, we may want to label our runs by cache size by calling `build/RISCV/gem5.debug -d results/dcache-32kB configs/assignments/hello.py --dcache-size=32kB`.

## C++ Backend

All backend source files in gem5 are found in the *src* directory. There are over 7000 files and hundreds of thousands of lines of code that make up the backend source, and **you don't need to understand everything that is happening in the source to be able to meaningfully use/extend the tool**[^2]. Before working with gem5, your grad TA was the kind of person who liked to understand everything that is going on everywhere in a repository -- you need to learn to be comfortable with knowing this is impossible if you feel the same way!

[^2]: Gem5 doesn't look at every file in the *src* directory as source by default, so be sure to do your work in the files specified by the assignments. Your assignments in this course will provide scaffolding to ensure that all of the pre-created source files are visible to scons compiler.

SimObjects in the backend typically consist of four components:
1. The object header file (<class name>.hh),
2. The object source file (<class name>.cc),
3. The Python object declaration file (<Class Name>.py), and
4. The SConscript file that makes the file visible to the compiler.

For this class, you will not need to worry about creating and linking any of these files, as it is easy to mess up and not the interesting part of the work. However, a few things to note. The parameters that we needed to define to make the DCache in the Front End section (i.e., assoc, tag_latency, etc.) are all defined in the object declaration Python script (item 3). To highlight this, look at the file *src/mem/cache/BaseCache.py*, where the `Cache` class that we imported and extended in the front end is declared. Our front end needed to define all of the parameters specified by these classes that don't have default values. If you wanted to extend an object to have more flexibility based on the front-end configuration, then you can add parameters to this file.

Notice how the declaration of the class in this Python object declaration points to the C++ backend source file. This source file (and associated header file) are where the logic is defined. There are a few functions that each SimObject class need to implement in order to compile, which serve specific purposes:
1. The class needs to declare its ports (this is done for your in the scaffolding); and
2. The ports need to implement the logic for the `recvTimingReq` (processor side ports) and `recvTimingResp` (memory side ports) to implement the timing mode CPU models (i.e., all CPUs other than the <ISA>AtomicSimpleCPU). These functions serve as wrappers in most SimObjects for `handleRequest` and `handleResponse` functions in the parent SimObject for the ports.

Within these functions, any logic can be implemented. Unfortunately, there is nothing governing super complex logic that cannot realistically be handled in the appropriate amount of time. Recall that gem5 essentially models simulated timing by creating lambda functions with a time (cycle number) at which the routine should be executed. This API is accessed by calling the `schedule(EventFunctionWrapper, Cycle)` function. Your assignments should provide the appropriate scaffolding for declaring these wrappers, but it is your job to implement them when and where appropriate. It is worth mentioning that debugging this type of programming model (called event-driven programming) can be really difficult as your call stack doesn't convey all of the information leading to the current state. Given this, it's okay if you want to add the *timing accuracy* components last in your workflow.

Let's think about the implications of this particular factoid about gem5. We can perform whatever logic we want and get to make the rules for how fast it is. This is pretty nifty, but it's important to model timing based on really engineering. If not, we lose the accuracy of the simulation, which defeats the purpose of simulating the hardware in the first place. This means that the developer of the backend logic needs to be **super** careful with when and where to use timing!

## Common Bugs

Will be enumerated here as they come up!

- `collect2: fatal error: ld terminated with signal 9 [killed]`: If this happens, be sure to run scons `build/RISCV/gem5.debug --linker=gold` to your compile command. If this still doesn't fix it, run `scons build/RISCV/gem5.debug --linker=gold --limit-ld-memory-usage`

