/*
 * Author: Jac McCarty, Samuel Thomas
 * Copyright (c) 2022 Bryn Mawr College, Brown University
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

/**
 * @file
 * Declares a the Anubis Memory Encryption Engine.
 */

#ifndef __MEM_MEE_ANUBIS_HH__
#define __MEM_MEE_ANUBIS_HH__

#define KB_IN_B 1024
#define ENTRY_SIZE 64

#include <queue>

#include "mem/mee/base.hh"
#include "params/Anubis.hh"
#include "params/BaseMemoryEncryptionEngine.hh"

namespace gem5 {

class MetadataResponsePort;

class Anubis : public BaseMemoryEncryptionEngine
{
    bool needsWritethrough(uint64_t addr, int tree_level) {
      return tree_level == data_level - 1;
    }

    void evictionHandling(PacketPtr pkt);

    bool handleResponse(PacketPtr pkt);

    // The equivalent of calculateAddress but in the shadow
    // table
    uint64_t calculateShaddress(uint64_t addr, int tree_level);

    // The equivalent of createMetadata but for the shadow
    // table
    void createShadowdata(uint64_t addr, int tree_level, PacketPtr child);

  public:
    Anubis(const AnubisParams *p);

    ////////////////////////////////////
    ////// ANUBIS SPECIFIC FIELDS //////
    ////////////////////////////////////

    // Dictates the size of shadow data
    uint64_t metadata_cache_size;

    // Address of the starting
    uint64_t shadow_merkle_table;
    // Size of shadow tree
    int shad_leaf_level;

    std::queue<int> free_table_index_queue;
    std::unordered_map<uint64_t, int> tracking_map;
    std::vector<uint64_t> shad_integrity_levels;
};

}

#endif //__MEM_MEE_WB_HH__
