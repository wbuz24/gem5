# Copyright (c) 2012, 2014, 2017-2019, 2021 Arm Limited
# All rights reserved
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Copyright (c) 2002-2005 The Regents of The University of Michigan
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
#
# Tutorial author: Samuel Thomas, Brown University


""" secure memory for tutorial """

from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)
import m5
from m5.objects import *
m5.util.addToPath("../")
from common import SimpleOpts


from common.Caches import L1_DCache

from m5.objects import (
    AddrRange,
    MemCtrl,
    Port,
    SecureMemory,
    SimpleMemory,
    SecureEncryptionEngine,
)
from m5.util.convert import toMemorySize

from ...utils.override import overrides
from ..boards.abstract_board import AbstractBoard
from .abstract_memory_system import AbstractMemorySystem


class SecureMemorySystem(AbstractMemorySystem):
    """A class that implements secure memory using SimpleMemory"""

    def __init__(self, latency: str, bandwidth: str, size: str):
        """
        :param latency: the average request to response latency
        :param bandwidth: combined read and write bandwidth
        :param size: size of the memory
        """

        super().__init__()


        # Create a metadata cache
        class MetadataCache(L1_DCache):
          size = "32KiB"

        # Sets up the RAM
        self.module = SimpleMemory(latency=latency, bandwidth=bandwidth)

        # Appropriate starting address?
        # Memory encryption engine 
        self.mee = m5.objects.SecureEncryptionEngine(cache_hmac=False, num_gb=toMemorySize(size) // (1 << 30), start_addr=0)
        # Metadata Cache
        self.metadata_cache = MetadataCache()

        # Set the size
        self._size = toMemorySize(size)
        
        # Connect the MEE to RAM
        self.mee.mem_side = self.module.port

        # Connect metadata cache
        self.mee.metadata_request_port = self.metadata_cache.cpu_side
        self.metadata_cache.mem_side = self.mee.metadata_response_port

    @overrides(AbstractMemorySystem)
    def incorporate_memory(self, board: AbstractBoard) -> None:
        pass

    @overrides(AbstractMemorySystem)
    def get_mem_ports(self) -> Sequence[Tuple[AddrRange, Port]]:
        return [(self.module.range, self.mee.cpu_side)]

    @overrides(AbstractMemorySystem)
    def get_memory_controllers(self) -> List[MemCtrl]:
        return [self.module]

    @overrides(AbstractMemorySystem)
    def get_size(self) -> int:
        return self._size

    @overrides(AbstractMemorySystem)
    def set_memory_range(self, ranges: List[AddrRange]) -> None:
        if len(ranges) != 1 or ranges[0].size() != self._size:
            raise Exception(
                "Secure memory controller requires a single "
                "range which matches the memory's size. Too naughty for words!"
            )
        self.module.range = ranges[0]


def SecureSimpleMemory(size: Optional[str] = "32MB") -> AbstractMemorySystem:
    return SecureMemorySystem(size=size, bandwidth="1GiB/s", latency="150ns")
