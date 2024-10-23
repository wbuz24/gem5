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

/**
 * @file
 * Declares a the BMF Memory Encryption Engine.
 */

#ifndef __MEM_MEE_BMF_HH__
#define __MEM_MEE_BMF_HH__

#include "mem/mee/base.hh"
#include "params/BMF.hh"
#include "params/BaseMemoryEncryptionEngine.hh"

namespace gem5 {

struct entry
{
    uint64_t node;
    uint64_t ctr;
    uint64_t children_ctrs[8];
    int tree_level;
};

class BMF : public BaseMemoryEncryptionEngine
{
    bool needsWritethrough(uint64_t addr, int tree_level) {
        return true;
    };

    bool doneWriting(PacketPtr pkt) {
        if (prs.find(pkt->req->metadata_addr) != prs.end()) {
            return true;
        }

        return BaseMemoryEncryptionEngine::doneWriting(pkt);
    };

    bool trusted(PacketPtr pkt) {
        if (prs.find(pkt->req->metadata_addr) != prs.end()) {
            return true;
        }

        return BaseMemoryEncryptionEngine::trusted(pkt);
    };

    bool handleRequest(PacketPtr pkt) {
        if (blocked) {
            return false;
        }

        rei_counter++;

        if (rei_counter == rei) {
            rei_counter = 0;

            // We block at the REI
            blocked = true;

            // Find prune target, if one exists
            entry *pc = nullptr;
            entry *mc = nullptr;
            for (auto e = prs.begin(); e != prs.end(); e++) {
                if (pc == nullptr || e->second->ctr > pc->ctr) {
                    pc = e->second;
                }

                if (mc == nullptr || e->second->ctr < mc->ctr) {
                    if (e->second->node == integrity_levels[1]) {
                        // The true BMT root cannot be the merge
                        // candidate
                        continue;
                    }

                    mc = e->second;
                }

                e->second->ctr /= 2;
            }

            bmf_latency += cache_access_latency * num_prs_entries;

            // Get largest child
            int child_index = 0;
            int largest_ctr = 0;
            for (int i = 1; i < ARITY; i++) {
                if (pc->children_ctrs[i] > largest_ctr) {
                    child_index = i;
                    largest_ctr = pc->children_ctrs[i];
                }
            }

            uint64_t child_addr =
                calculateChildAddress(pc->node, pc->tree_level, child_index);

            // We have already saturated the counters
            if (pc->ctr > (threshold / 2)) {
                // Case 1, there is space for the new PRS entry
                if (prs.size() < num_prs_entries) {
                    entry *e = new entry();
                    e->node = child_addr;
                    e->ctr = 0;
                    e->tree_level = pc->tree_level + 1;

                    prs.insert(std::pair<uint64_t, entry *>(child_addr, e));

                    assert(prs.size() <= num_prs_entries);
                } else if (prs.size() == num_prs_entries) {
                    // We need to merge to make space for prune candidate
                    std::unordered_map<uint64_t, entry *>::iterator it;
                    assert((it = prs.find(mc->node)) != prs.end());

                    entry *to_delete = it->second;
                    prs.erase(it->second->node);

                    merging = true;

                    // Persist merge target to root path
                    createMetadata(to_delete->node, to_delete->tree_level,
                        false, nullptr);

                    // Free dynamically created entry
                    delete to_delete;

                    // prune the prune target
                    entry *e = new entry();
                    e->node = child_addr;
                    e->ctr = 0;
                    e->tree_level = pc->tree_level + 1;

                    prs.insert(std::pair<uint64_t, entry *>(child_addr, e));

                    assert(prs.size() <= num_prs_entries);
                } else {
                    // We should never get here
                    assert(false);
                }
            }

            return false;
        }

        pkt->headerDelay += bmf_latency;
        bmf_latency = 0;

        return BaseMemoryEncryptionEngine::handleRequest(pkt);
    };

    bool handleResponse(PacketPtr pkt) {
        if (merging) {
            if (!pkt->req->needs_writethrough &&
                    prs.find(pkt->getAddr()) != prs.end()) {
                // Done merging!
                merging = false;
                blocked = false;
            }
            bool ret = BaseMemoryEncryptionEngine::handleResponse(pkt);

            if (!merging) {
                cpu_side_port.trySendRetry();
            }

            return ret;
        }

        std::unordered_map<uint64_t, entry *>::iterator it;
        if (pkt->isWrite() && (it = prs.find(pkt->getAddr())) != prs.end()) {
            it->second->ctr++;
        } else if (pkt->isWrite() && pkt->req->tree_level != hash_level &&
                (it = prs.find(pkt->req->parent_addr)) != prs.end()) {
            uint64_t block_num = (pkt->getAddr() -
                integrity_levels[pkt->req->tree_level]) / BLOCK_SIZE;
            it->second->children_ctrs[block_num % ARITY]++;
        }

        return BaseMemoryEncryptionEngine::handleResponse(pkt);
    }

  public:
    BMF(const BMFParams *p);

    /////////////////////////////////
    ////// BMF SPECIFIC FIELDS //////
    /////////////////////////////////
    bool blocked;
    int rei_counter;
    const int rei = 32;

    bool merging;

    const int cache_access_latency = 2000;
    int bmf_latency;
    const int threshold;
    const int num_prs_entries;

    std::unordered_map<uint64_t, entry *> prs;

    ////////////////////////////////////
    ////// BMF SPECIFIC FUNCTIONS //////
    ////////////////////////////////////
    uint64_t calculateChildAddress(uint64_t addr, int tree_level, int index);
};

}

#endif //__MEM_MEE_BMF_HH__
