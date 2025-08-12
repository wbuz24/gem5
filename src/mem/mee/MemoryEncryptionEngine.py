# Author: Samuel Thomas
# Copyright (c) 2022 Brown University
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

from m5.params import *
from m5.proxy import *
from m5.SimObject import SimObject

class BaseMemoryEncryptionEngine(SimObject):
    type = 'BaseMemoryEncryptionEngine'
    cxx_header = "mem/mee/base.hh"
    cxx_class = 'gem5::BaseMemoryEncryptionEngine'

    # Connects to the membus
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")

    # Connects to the MemCtrl
    mem_side = RequestPort("Mem side port, sends requests for data")

    # Connects to MetadataCache (from top)
    metadata_request_port = RequestPort("Mem side port, \
                                sends requests for metadata")
    # Connects to MetadataCache (from bottom)
    metadata_response_port = ResponsePort("CPU side port, \
                                sends responses back to metadata cache")

    # Fields for BMT construction
    start_addr = Param.UInt64(0, "Default starting addr in RISCV")
    num_gb = Param.Int(8, "Number of GB in main memory")

    # Fields for Far Mem
    far_mem_mult = Param.Int(1, "Default as local memory latency")

class BaobabEncryptionEngine(SimObject):
    type = 'BaobabEncryptionEngine'
    cxx_header = 'mem/mee/baobab.hh'
    cxx_class = 'gem5::BaobabEncryptionEngine'

    # Very similar to BaseMEE, except with new way of deriving counters
    # so we are creating a new base class

    # Connects to membus
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")

    # Connects to the MemCtrl
    mem_side = RequestPort("Mem side port, sends requests for data")

    # Connects to MetadataCache (from top)
    metadata_request_port = RequestPort("Mem side port, \
                                sends requests for metadata")
    # Connects to MetadataCache (from bottom)
    metadata_response_port = ResponsePort("CPU side port, \
                                sends responses back to metadata cache")

    # Fields for BMT construction
    start_addr = Param.UInt64(2, "Default starting addr in ARM")
    num_gb = Param.UInt64(8, "Number of GB in main memory")

    # Fields for Memoization
    table_size = Param.Int(1 << 20, "Size of memoization table")
    cells_per_entry = Param.Int(16, "Number of possible counter values \
                                per entry in memoization table")

    # Misc fields
    cache_hmac = Param.Bool(True, "Should hmacs be cached?")

class TimingEncryptionEngine(SimObject):
    type = 'TimingEncryptionEngine'
    cxx_header = 'mem/mee/timing.hh'
    cxx_class = 'gem5::TimingEncryptionEngine'

    # Very similar to BaseMEE, except with new way of deriving counters
    # so we are creating a new base class

    # Connects to membus
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")

    # Connects to the MemCtrl
    mem_side = RequestPort("Mem side port, sends requests for data")

    # Connects to MetadataCache (from top)
    metadata_request_port = RequestPort("Mem side port, \
                                sends requests for metadata")
    # Connects to MetadataCache (from bottom)
    metadata_response_port = ResponsePort("CPU side port, \
                                sends responses back to metadata cache")

    # Fields for BMT construction
    start_addr = Param.UInt64(0, "Default starting addr in ARM")
    num_gb = Param.UInt64(8, "Number of GB in main memory")

    # Misc fields
    cache_hmac = Param.Bool(False, "Should hmacs be cached?")

class SecureEncryptionEngine(SimObject):
    type = 'SecureEncryptionEngine'
    cxx_header = 'mem/mee/secure.hh'
    cxx_class = 'gem5::SecureEncryptionEngine'

    # Built off of the TimingEncryption Engine 

    # Connects to membus
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")

    # Connects to the MemCtrl
    mem_side = RequestPort("Mem side port, sends requests for data")

    # Connects to MetadataCache (from top)
    metadata_request_port = RequestPort("Mem side port, \
                                sends requests for metadata")
    # Connects to MetadataCache (from bottom)
    metadata_response_port = ResponsePort("CPU side port, \
                                sends responses back to metadata cache")

    # Fields for BMT construction
    start_addr = Param.UInt64(0, "Default starting addr in ARM")
    num_gb = Param.UInt64(8, "Number of GB in main memory")

    # Misc fields
    cache_hmac = Param.Bool(False, "Should hmacs be cached?")

class TimingPointerEncryptionEngine(SimObject):
    type = 'TimingPointerEncryptionEngine'
    cxx_header = 'mem/mee/timing_pointer.hh'
    cxx_class = 'gem5::TimingPointerEncryptionEngine'

    # Very similar to BaseMEE, except with new way of deriving counters
    # so we are creating a new base class

    # Connects to membus
    cpu_side = ResponsePort("CPU side port, receives requests from LLC")

    # Connects to the MemCtrl
    mem_side = RequestPort("Mem side port, sends requests for data")

    # Connects to MetadataCache (from top)
    metadata_request_port = RequestPort("Mem side port, \
                                sends requests for metadata")
    # Connects to MetadataCache (from bottom)
    metadata_response_port = ResponsePort("CPU side port, \
                                sends responses back to metadata cache")

    # Fields for BMT construction
    start_addr = Param.UInt64(2, "Default starting addr in ARM")
    num_gb = Param.UInt64(8, "Number of GB in main memory")

    # Misc fields
    cache_hmac = Param.Bool(False, "Should hmacs be cached?")

class HuffmanEncryptionEngine(TimingEncryptionEngine):
    type = 'HuffmanEncryptionEngine'
    cxx_header = 'mem/mee/huffman.hh'
    cxx_class = 'gem5::HuffmanEncryptionEngine'

class HuffmanV2EncryptionEngine(TimingPointerEncryptionEngine):
    type = 'HuffmanV2EncryptionEngine'
    cxx_header = 'mem/mee/huffman_v2.hh'
    cxx_class = 'gem5::HuffmanV2EncryptionEngine'

class BasePtrMemoryEncryptionEngine(BaseMemoryEncryptionEngine):
    type = 'BasePtrMemoryEncryptionEngine'
    cxx_header = 'mem/mee/base_pointer.hh'
    cxx_class = 'gem5::BasePtrMemoryEncryptionEngine'

class WBMemoryEncryptionEngine(BaseMemoryEncryptionEngine):
    type = 'WBMemoryEncryptionEngine'
    cxx_header = 'mem/mee/wb.hh'
    cxx_class = 'gem5::WBMemoryEncryptionEngine'

class LeafMemoryEncryptionEngine(BaseMemoryEncryptionEngine):
    type = 'LeafMemoryEncryptionEngine'
    cxx_header = 'mem/mee/leaf.hh'
    cxx_class = 'gem5::LeafMemoryEncryptionEngine'

class StrictMemoryEncryptionEngine(BaseMemoryEncryptionEngine):
    type = 'StrictMemoryEncryptionEngine'
    cxx_header = 'mem/mee/strict.hh'
    cxx_class = 'gem5::StrictMemoryEncryptionEngine'

class AMNT(BaseMemoryEncryptionEngine):
    type = 'AMNT'
    cxx_header = 'mem/mee/amnt.hh'
    cxx_class = 'gem5::AMNT'

    # Pre-configured subtree level
    subtree_level = Param.Int(3, "Level to put the subtree")

    # Hot memory tracking values
    record_length = Param.Int(32, "Interval of writes to observe, \
                                before moving subtree")
    movement_ratio = Param.Float(0.5, "Proportion of nodes in a subtree, \
                                to observe for it to be hot")

    # For variable number of subtrees
    num_subtrees = Param.Int(1, "For multiple subtrees, how many do you want?")

class Anubis(BaseMemoryEncryptionEngine):
    type = 'Anubis'
    cxx_header = 'mem/mee/anubis.hh'
    cxx_class = 'gem5::Anubis'

    # Default shadow tree parameters
    metadata_cache_size = Param.Int(32, "Meta Cache size in kB")

class BMF(BaseMemoryEncryptionEngine):
    type = 'BMF'
    cxx_header = 'mem/mee/bmf.hh'
    cxx_class = 'gem5::BMF'

    # PRS size
    num_entries = Param.Int(512, "Number of entries in the PRS, \
                            which is 8x the size in bytes")
    threshold = Param.Int(16, "Number of accesses to become prune target")
