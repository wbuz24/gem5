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

#include "mem/mee/anubis.hh"

namespace gem5 {

Anubis::Anubis(const AnubisParams *p) :
    BaseMemoryEncryptionEngine(p),
    metadata_cache_size(p->metadata_cache_size)
{
    shadow_merkle_table = integrity_levels[1] + ENTRY_SIZE;
    for (uint64_t i = 0;
            i < (metadata_cache_size * KB_IN_B) / ENTRY_SIZE; i++) {
        free_table_index_queue.push(i);
    }

    // compute shad_leaf_level
    shad_leaf_level = 0;
    int nodes = free_table_index_queue.size();

    int eights = 8;
    do {
        eights = eights * 8;
    } while (eights < nodes);
    nodes = eights;

    do {
        shad_leaf_level++;
        if (nodes == 4) { nodes *= 2; }
        nodes /= 8;
    } while (nodes != 1);

    int num = 0;
    int num_blocks_on_last_shad_level = 1;
    while (num < shad_leaf_level) {
        shad_integrity_levels.push_back(GB_IN_B); // for each level of the tree
        num++;
        num_blocks_on_last_shad_level *= ARITY;
    }
    shad_integrity_levels.push_back(GB_IN_B); // for shadow_merkle_table level
    // all of it is metadata already -- don't need extra level for data
    // only extra level for "hash", i.e. shadow_merkle_table

    uint64_t number_of_blocks = num_blocks_on_last_shad_level;
    shad_integrity_levels[shad_leaf_level] = shadow_merkle_table;

    // Calculate all other levels (shad_integrity_levels[0]
    // does not exist -- might need to put in that buffer-space)
    for (uint64_t i = shad_leaf_level - 1; i > 0; i--){
        // Number of blocks refers to the
        // number of blocks at the previous level
        shad_integrity_levels[i] = shad_integrity_levels[i+1] +
                                    number_of_blocks * BLOCK_SIZE;

        number_of_blocks = number_of_blocks / ARITY;
        if (number_of_blocks == 0) {
            number_of_blocks = 1;
        }

        if (i == 0) {
            assert(number_of_blocks == 1);
        }
    }
}

uint64_t
Anubis::calculateShaddress(uint64_t addr, int tree_level)
{
    bool counter = false;
    uint64_t block_num = (addr -
                shad_integrity_levels[tree_level]) / BLOCK_SIZE;

    uint64_t parent_block;
    uint64_t parent_addr;
    if (counter) { // if we're trying to calculate counter addr
        parent_block = block_num / BONSAI_COUNTER_ARITY;
    } else {
        parent_block = block_num / ARITY;
    }

    uint64_t num_blocks = (shad_integrity_levels[tree_level - 1] -
                shad_integrity_levels[tree_level]) / BLOCK_SIZE;
    assert(parent_block < num_blocks);

    parent_addr = (parent_block * BLOCK_SIZE) +
                    shad_integrity_levels[tree_level - 1];

    assert(parent_addr != addr);
    assert(parent_addr > start_addr + (num_gb * GB_IN_B));
    assert(parent_addr < start_addr + (2 * num_gb * (GB_IN_B)));

    return parent_addr;
}

void
Anubis::createShadowdata(uint64_t addr, int tree_level, PacketPtr child)
{
    RequestPtr req = std::make_shared<Request>(addr, 64, 0, 0);
    req->metadata_addr = addr;
    bool is_read = false;
    req->req_type = is_read ? Request::MetadataRead : Request::MetadataWrite;
    req->arrived = curTick();

    req->is_shad = true;
    req->tree_level = tree_level;

    MemCmd cmd = is_read ? MemCmd::ReadReq : MemCmd::WriteReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    pkt->req->child_requests.push_back(child);

    pkt->req->needs_writethrough = false;
    mem_side_port.sendPacket(pkt);
}

void
Anubis::evictionHandling(PacketPtr pkt)
{
    if (tracking_map.find(pkt->getAddr()) != tracking_map.end()) {
        free_table_index_queue.push(tracking_map.at(pkt->getAddr()));
        tracking_map.erase(pkt->getAddr());
    }

    BaseMemoryEncryptionEngine::evictionHandling(pkt);
}

bool
Anubis::handleResponse(PacketPtr pkt)
{
    if (pkt->isRead() && pkt->req->metadata_cache_miss && !pkt->req->is_shad) {
        // We have found a metadata cache miss in the BMT
        // so we need to shadow it in the in memory table
        // assert(free_table_index_queue.size() > 0);

        // Get the first available entry of our in-memory
        // table and fill it with this node's address

        if (tracking_map.find(pkt->getAddr()) == tracking_map.end()) {
            // We have found a metadata cache miss in the BMT
            // so we need to shadow it in the in memory table
            if (free_table_index_queue.size() > 0) {

                 int table_index = free_table_index_queue.front();
                 free_table_index_queue.pop();

                tracking_map.insert(std::pair<uint64_t, int>
                    (pkt->getAddr(), table_index));

                // Create the memory request that corresponds to that
                // table entry
                uint64_t shaddr = shadow_merkle_table +
                    (ENTRY_SIZE * table_index);
                assert(shaddr >= shadow_merkle_table);
                assert(shaddr < shadow_merkle_table +
                     (ENTRY_SIZE * metadata_cache_size * KB_IN_B));

                createShadowdata(shaddr, shad_leaf_level, pkt);
            } else {
                pkt->req->is_counter_fetched = true;
                return BaseMemoryEncryptionEngine::handleResponse(pkt);
            }

            // This is on the critical path of the data verification
            // so we should not continue verifying this value yet
            return true;
        }
    } else if (pkt->req->is_shad) {
        // We have received the response of a memory request
        // for the shadow table. We are done when we have
        // written up the shadow tree from leaf-to-root
        if (pkt->req->tree_level == 1 || pkt->req->is_counter_fetched) {
            assert(pkt->req->child_requests.size() == 1);
            PacketPtr child = pkt->req->child_requests[0];

            delete pkt;

            // if child is still shadow table metadata
            if (child->req->is_shad) {
                child->req->is_counter_fetched = true;
                return handleResponse(child);
            } else {
                // we have reached the tree metadata, and can safely
                // exit the shadow protocol
                return BaseMemoryEncryptionEngine::handleResponse(child);
            }
        } else {
            // We need to finish the leaf-to-root shadow tree update
            uint64_t shaddr = calculateShaddress(
                pkt->getAddr(), pkt->req->tree_level);
            createShadowdata(shaddr, pkt->req->tree_level - 1, pkt);

            return true;
        }
    }

    return BaseMemoryEncryptionEngine::handleResponse(pkt);
};

} // gem5

gem5::Anubis *
gem5::AnubisParams::create() const
{
    return new gem5::Anubis(this);
}
