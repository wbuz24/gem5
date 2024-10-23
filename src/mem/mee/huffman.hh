/*
 * Author: Samuel Thomas
 * Copyright (c) 2022 Brown University
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
 * Declares a Memory Encryption Engine where the Merkle tree is Huffmanized.
 */

#ifndef __MEM_MEE_HUFFMAN_HH__
#define __MEM_MEE_HUFFMAN_HH__

#include "mem/mee/timing.hh"
#include "params/TimingEncryptionEngine.hh"
#include "params/HuffmanEncryptionEngine.hh"

#define PAGE_SIZE (unsigned long long) 4096

namespace gem5 {


class HuffmanEncryptionEngine : public TimingEncryptionEngine
{
  private:
    // for tracking how much to increment by
    std::unordered_map<uint64_t, int> increment_map;

    uint64_t calculateAddress(PacketPtr pkt) {
        assert(*pkt->getPtr<uint64_t>() != 0);

        return *pkt->getPtr<uint64_t>();
    };

    // huffman specific fields
    enum { NORMAL, PQ_SORT, HUFFMAN };
    int state = NORMAL;
    uint64_t clear_index = 0;
    uint64_t max_index;

    // for PQ sorting
    uint64_t current_index = 0;
    uint64_t compare_index = 1;
    uint64_t *current_data = nullptr;

    // for huffman construction
    uint64_t pq_head_idx = 0;
    uint64_t pq_insert_idx = -1;
    uint64_t children_count = 0;
    int children_to_fetch = 8;

    // huffman specific functions
    void incrementFrequency(uint64_t addr);

    void beginHuffman();
    void handleHuffmanResponse(PacketPtr pkt);

    EventFunctionWrapper clearInactiveEvent;
    void clearInactive();

    void createClearRequest();
    void createSortRequest(uint64_t index);

    bool handleSortResponse(PacketPtr pkt);

    // override functions
    bool handleRequest(PacketPtr pkt);
    bool handleResponse(PacketPtr pkt);

    void startup();

    uint64_t getCounter(uint64_t *data) { return data[0]; };
    void setCounter(uint64_t *data, uint64_t ctr) { data[0] = ctr; };

    uint64_t getAddr(uint64_t *data) { return data[1]; };
    void setAddr(uint64_t *data, uint64_t addr) { data[1] = addr; };

    uint64_t getNext(uint64_t *data) { return data[2]; };
    void setNext(uint64_t *data, uint64_t next) { data[2] = next; };

    bool getRemoved(uint64_t *data) { return data[3] != 0; };
    void setRemoved(uint64_t *data) { data[3] = 1; };

  public:
    HuffmanEncryptionEngine(const HuffmanEncryptionEngineParams *p);
};

}

#endif //__MEM_MEE_HUFFMAN_HH__
