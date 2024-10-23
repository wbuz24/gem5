/*
 * Author: Kidus Workneh, Samuel Thomas
 * Copyright (c) 2022 UC Boulder, Brown University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mem/mee/bmf.hh"

#include <array>

namespace gem5
{

BMF::BMF(const BMFParams *p) :
    BaseMemoryEncryptionEngine(p),
    blocked(false), rei_counter(0), merging(false),
    bmf_latency(0), threshold(p->threshold),
    num_prs_entries(p->num_entries)
{
    entry *e = new entry();
    e->node = integrity_levels[1];
    e->ctr = 0;
    e->tree_level = 1;

    prs.insert(std::pair<uint64_t, entry *>(integrity_levels[1], e));
}

uint64_t
BMF::calculateChildAddress(uint64_t addr, int tree_level, int index) {
    uint64_t block_num = (addr - integrity_levels[tree_level]) / BLOCK_SIZE;

    uint64_t child_block;
    uint64_t child_addr;

    child_block = (block_num * ARITY) + index;

    child_addr = (child_block * BLOCK_SIZE) +
                integrity_levels[tree_level + 1];

    return child_addr;
}


} // gem5

gem5::BMF *
gem5::BMFParams::create() const
{
    return new gem5::BMF(this);
}
