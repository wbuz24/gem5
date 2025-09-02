# Cross compile the m5 binary
For an x86 host system running riscv, you can use the following:
```
scons x86.CROSS_COMPILE=riscv64-unknown-linux-gnu-gcc build/RISCV/out/m5
```

# Exit instructions can be included in the benchmark
Within your micro-benchmark, include gem5 exit statements that can trigger processor switches, exit conditions and [more](https://www.gem5.org/documentation/general_docs/m5ops/).

First, ensure that you ```#include <gem5/m5ops.h>``` and include ```/gem5/include/``` when compiling. Then, you can have the following statement in your benchmark source code. 

```
  #ifdef GEM5
    // gem5 exit
    m5_exit(0);
  #endif // 
```

# Catch exit instructions in the config
Within the python config file, you then catch the called m5 exit instruction, examples can be found in [FS examples](https://github.com/gem5/gem5/blob/stable/configs/example/gem5_library/x86-gapbs-benchmarks.py).

```
def handle_exit():
    print("Done booting Linux!")
    m5.stats.reset()
    processor.switch()
    yield False
    print("Dump Stats")
    m5.stats.dump()
    yield True

simulator = Simulator(
    board=board,
    on_exit_event={
        ExitEvent.EXIT: handle_exit(),
    }
)
simulator.run()
```
