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

#include "mem/mee/huffman_v2.hh"

namespace gem5
{

HuffmanV2EncryptionEngine::HuffmanV2EncryptionEngine
        (const HuffmanV2EncryptionEngineParams *p) :
    TimingPointerEncryptionEngine(p), ht(nullptr)
{
    frequencies.resize(memory_size / BLOCK_SIZE);
    for (uint64_t i = 0; i < memory_size / BLOCK_SIZE; i++) {
        frequencies[i] = std::pair<uint64_t, uint64_t>(i, 0);
    }

    cells_to_clear = memory_size / BLOCK_SIZE; // TODO: adjust this?
    cells_to_sort = cells_to_clear; // TODO: adjust this?
    cells_to_huffmanize = cells_to_clear * cells_to_clear;

    max_ht_size = integrity_levels[0] - integrity_levels[data_level];
}

bool
HuffmanV2EncryptionEngine::handleRequest(PacketPtr pkt)
{
    if (pkt->isWrite()) {
        if (state == NORMAL) {
            uint64_t block_id = ((pkt->getAddr() - start_addr) / BLOCK_SIZE);
            assert(block_id < frequencies.size());
            // TODO: one write to array here
            assert(frequencies[block_id].first == block_id);
            frequencies[block_id].second++;

            // TODO: clear one item from other array here
            cells_to_clear--;

            if (cells_to_clear == 0) {
                std::cout << "Switching from normal state to sort state" << std::endl;
                state = PQ_SORT;

                // reset cells_to_clear for next normal state
                cells_to_clear = memory_size / BLOCK_SIZE;
            }
        } else if (state == PQ_SORT) {
            assert(cells_to_sort > 0);

            // TODO: how many memory reads/writes needed to sort one cell?
            // i.e., how much work do we want to do here?
            cells_to_sort--;

            if (cells_to_sort == 0) {
                // sort our frequencies here, because we know that the
                // in memory array has been sorted
                std::sort(frequencies.begin(), frequencies.end(), [](auto &left, auto &right) {
                    return left.second < right.second;
                });

                std::cout << "Switching from sort state to huffman state" << std::endl;
                state = HUFFMAN;

                // reset cells_to_sort for next pq_sort state
                cells_to_sort = cells_to_clear;
            }
        } else {
            assert(state == HUFFMAN);
            assert(ht == nullptr);

            // TODO: how many memory reads/writes are needed to reduce the
            // number of nodes
            cells_to_huffmanize--;

            if (cells_to_huffmanize == 0) {
                std::cout << "Building huffman tree!" << std::endl;

                // We have sorted the huffman tree, so we can build
                // that for ourselves and do the construction
                ht = new huffman_tree(frequencies, max_ht_size, integrity_levels[data_level - 2]);

                for (uint64_t i = 0; i < max_ht_size; i++) {
                    // update the pointer to the parent
                    uint64_t a = ht->all_nodes[i].addr;
                    uint64_t p = ht->all_nodes[i].parent;
                    const uint8_t *new_parent = (uint8_t *) &p;
                    
                    // TODO: will it work to say that we are just a leaf
                    // node? Shouldn't matter, right? Could be an error though,
                    // so check here on a crash
                    createMetadata(a, data_level - 1, false, nullptr, new_parent); 
                }

                // Clean up - excuse the weird syntax to make this work with gem5
                ht->ht_free(ht->root);
                free(ht->all_nodes);
                ht = nullptr;

                std::cout << "Switching from huffman state to normal state" << std::endl;
                state = NORMAL;

                // Reset for next huffman state
                cells_to_huffmanize = cells_to_clear * cells_to_clear;
            }

            return false;
        }
    } else if (state == HUFFMAN) {
        // block while changing tree shape
        return false;
    }

    return TimingPointerEncryptionEngine::handleRequest(pkt);
}

bool
HuffmanV2EncryptionEngine::handleResponse(PacketPtr pkt)
{
    return TimingPointerEncryptionEngine::handleResponse(pkt);
}

}


gem5::HuffmanV2EncryptionEngine *
gem5::HuffmanV2EncryptionEngineParams::create() const
{
    return new gem5::HuffmanV2EncryptionEngine(this);
}
