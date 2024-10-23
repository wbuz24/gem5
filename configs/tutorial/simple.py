import m5
from m5.objects import *

# following tutorial
system = System()
system.clk_domain = SrcClockDomain()
system.clk_domain.clock = '16GHz'
# system power
system.clk_domain.voltage_domain = VoltageDomain() # default options

system.mem_mode = 'timing'
system.mem_ranges = [AddrRange('512MB')]

system.cpu = RiscvTimingSimpleCPU()

system.membus = SystemXBar()

# no cache right now
system.cpu.icache_port = system.membus.cpu_side_ports
system.cpu.dcache_port = system.membus.cpu_side_ports

system.cpu.createInterruptController()

# RISC-V ISA does not require these lines
# system.cpu.interrupts[0].pio = system.membus.mem_side_ports
# system.cpu.interrupts[0].int_requestor = system.membus.cpu_side_ports
# system.cpu.interrupts[0].int_responder = system.membus.mem_side_ports

# Memory controller
system.mem_ctrl = MemCtrl()
system.mem_ctrl.dram = DDR3_1600_8x8()
system.mem_ctrl.dram.range = system.mem_ranges[0]
system.mem_ctrl.port = system.membus.mem_side_ports

binary = 'tests/test-progs/hello/bin/riscv/linux/hello'

# for gem5 V21+
system.workload = SEWorkload.init_compatible(binary)

process = Process()
process.cmd = [binary]
system.cpu.workload = process
system.cpu.createThreads()

root = Root(full_system = False, system=system)
m5.instantiate()

print("Beginning simulation!")
exit_event = m5.simulate()

print('Exiting at tick {} because {}' .format(m5.curTick(), exit_event.getCause()))
