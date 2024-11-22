import m5
from m5.objects import *

m5.util.addToPath("../")
from common import SimpleOpts
from m5.objects import Cache
from caches import *

# Command line arguments
SimpleOpts.add_option("--argv", default="", type=str)
args = SimpleOpts.parse_args()

# following tutorial
system = System()
system.clk_domain = SrcClockDomain()
system.clk_domain.clock = "16GHz"
# system power
system.clk_domain.voltage_domain = VoltageDomain()  # default options

system.mem_mode = "timing"
system.mem_ranges = [AddrRange("512MB")]

system.cpu = RiscvTimingSimpleCPU()

# Connect L1 caches cpu side to CPU mem side
system.cpu.icache = L1ICache()
system.cpu.dcache = L1DCache()

system.cpu.icache.connectCPU(system.cpu)
system.cpu.dcache.connectCPU(system.cpu)

# L2 Bus cpu side to cache mem side
system.l2bus = L2XBar()

system.cpu.icache.connectBus(system.l2bus)
system.cpu.dcache.connectBus(system.l2bus)

# Connect L2 Cache cpu side to l2bus memside
system.l2cache = L2Cache(args)
system.l2cache.connectCPUSideBus(system.l2bus)

# Connect l2 cache mem side to membus cpu side
system.membus = SystemXBar()
system.l2cache.connectMemSideBus(system.membus)

# interrupt controller for CPU
system.cpu.createInterruptController()
system.system_port = system.membus.cpu_side_ports

# Memory encryption engine
system.mee = TimingEncryptionEngine() 
system.mee.cpu_side = system.membus.mem_side_ports

# Memory controller
system.mem_ctrl = MemCtrl()
system.mem_ctrl.dram = DDR3_1600_8x8() 
system.mem_ctrl.dram.range = system.mem_ranges[0]
system.mem_ctrl.port = system.mee.mem_side

# binary = 'tests/test-progs/hello/bin/riscv/linux/hello'
binary = "/home/wbuziak/repos/gem5/progs/binaries/arrflip"

# for gem5 V21+
thispath = os.path.dirname(os.path.realpath(__file__))
# binary = os.path.join(
#  thispath,
#  "../../",
##  "progs/binaries/arrflip",
# )

system.workload = SEWorkload.init_compatible(binary)

process = Process()
process.cmd = [binary, args.argv]
system.cpu.workload = process
system.cpu.createThreads()

root = Root(full_system=False, system=system)
m5.instantiate()

print("Beginning simulation!")
exit_event = m5.simulate()

print("Exiting at tick {m5.curTick()} because {exit_event.getCause()}")
