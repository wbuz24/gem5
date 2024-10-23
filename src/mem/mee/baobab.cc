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

#include "mem/mee/baobab.hh"

#include "params/BaobabEncryptionEngine.hh"
#include "sim/sim_exit.hh"

namespace gem5 {

BaobabEncryptionEngine::BaobabEncryptionEngine
        (const BaobabEncryptionEngineParams *p) :
    SimObject(*p),
    cpu_side_port(p->name + ".cpu_side", this),
    mem_side_port(p->name + ".mem_side", this),
    metadata_request_port(p->name + ".metadata_request_port", this),
    metadata_response_port(p->name + ".metadata_response_port", this),
    table_size(p->table_size), cells_per_entry(p->cells_per_entry),
    memory_size(p->num_gb << 30), start_addr(p->start_addr << 30),
    cache_hmacs(p->cache_hmac),
    cipherEvent([this] { processCipherEvent(); }, name()),
    hmacEvent([this] { processHmacEvent(); }, name()),
    respondInvalidateEvent([this] { respondInvalidate(); }, name()),
    retrySendMetadataEvent([this] { retrySendMetadata(); }, name())
{
    num_memoization_entries = table_size / (cells_per_entry * BLOCK_SIZE);

    uint64_t memoization_size = num_memoization_entries * cells_per_entry *
        sizeof(uint64_t);
    memoization_table = (uint64_t *)
        malloc(sizeof(uint64_t) * memoization_size);
    eviction_entries = (uint64_t *)
        malloc(sizeof(uint64_t) * num_memoization_entries);

    memset(memoization_table, 0, sizeof(uint64_t) * memoization_size);
    memset(eviction_entries, 0, sizeof(uint64_t) * num_memoization_entries);

    // Set the number of blocks holding this counter as the max for the zero
    // counter on initialization
    bits_in_holder = 1;
    while ((1ULL << bits_in_holder) <
        ((memory_size / BLOCK_SIZE) / num_memoization_entries)) {
        bits_in_holder++;
    }

    max_counter = (1ULL << (64 - bits_in_holder - 1)) - 1;

    for (int i = 0; i < num_memoization_entries; i++) {
        uint64_t *holder = (uint64_t *) memoization_table +
                ((memoization_size / num_memoization_entries) * i);
        assert(holder < (memoization_table + memoization_size));
        *holder = (uint64_t) ((memory_size / BLOCK_SIZE) /
                num_memoization_entries) << (64 - bits_in_holder - 1);
    }

    bits_per_index = 1;
    int comparator = 2;

    // We don't want split counter indices, so let's get the next biggest
    // power of two from the number of cells per entry
    while (comparator < cells_per_entry || BLOCK_SIZE % bits_per_index != 0) {
        bits_per_index++;
        comparator <<= 1;
    }


    baobab_counter_arity = BONSAI_COUNTER_ARITY *
        (BITS_PER_CTR / bits_per_index);

    // DRAM size in bytes
    uint64_t total_size = memory_size;
    uint64_t number_of_blocks = total_size / BLOCK_SIZE;
    //round to a power of eight
    uint64_t eights = 8;
    do {
        eights = eights * 8;
    } while (eights < number_of_blocks);
    number_of_blocks = eights;
    uint64_t num_blocks_on_last_level =
                                number_of_blocks / baobab_counter_arity;

    integrity_levels.push_back(GB_IN_B); // integrity_levels[0] is unused
    uint64_t num = 1;
    while (num < num_blocks_on_last_level) {
        integrity_levels.push_back(GB_IN_B); //for each level of the tree
        num = num * ARITY;
    }
    integrity_levels.push_back(GB_IN_B); //for data
    //total levels needed for data, counters, and tree
    uint64_t number_of_levels = integrity_levels.size();
    data_level = number_of_levels;
    integrity_levels.push_back(GB_IN_B); //for hash

    std::cout << "The BMT has " << number_of_levels - 1 << " levels."
                            << std::endl;

    // If this is ARM, it needs to be 2GB... if x86, it should be 0
    // start_addr = (2UL << 30);

    // Use tree_level to tell request type
    integrity_levels[0] = start_addr + memory_size;
    //data
    integrity_levels[number_of_levels] = start_addr;
    //counters will start where HMACs end
    uint64_t num_hash_bytes = (number_of_blocks * HASH_LEN);
    integrity_levels[number_of_levels - 1] = integrity_levels[0] +
                                                    num_hash_bytes;
    //calculate all other levels from counter - 1 to 1
    number_of_blocks = num_blocks_on_last_level;
    for (uint64_t i = number_of_levels - 2; i > 0; i--) {
        // Number of blocks refers to the
        // number of blocks at the previous level
        integrity_levels[i] = integrity_levels[i+1] +
                                    number_of_blocks * BLOCK_SIZE;

        number_of_blocks = number_of_blocks / ARITY;
        if (number_of_blocks == 0) {
            number_of_blocks = 1;
        }

        if (i == 1) {
            assert(number_of_blocks == 1);
        }
    }

    // Called at the end of simulation
    registerExitCallback([this]() { dumpAccessedAddrs(); });
}

Port&
BaobabEncryptionEngine::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "mem_side") {
        return mem_side_port;
    } else if (if_name == "cpu_side") {
        return cpu_side_port;
    } else if (if_name == "metadata_request_port") {
        return metadata_request_port;
    } else if (if_name == "metadata_response_port") {
        return metadata_response_port;
    } else {
        return SimObject::getPort(if_name, idx);
    }
}

void
BaobabEncryptionEngine::processCipherEvent()
{
    assert(!cipherQueue.empty());

    PacketPtr pkt = cipherQueue.front();
    cipherQueue.pop_front();

    assert(pkt->req->is_counter_fetched);
    pkt->req->is_counter_verified = true;

    if (pkt->isRead()) {
        assert(pkt->req->is_data_returned);

        // TODO: something fun with the counter value to cipher/inv-cipher?
        assert(pkt->req->baobab_ctr != -1);

        assert(!pkt->req->is_hash_verified || cache_hmacs);
        if (pkt->req->is_hash_fetched) {
            if (hmacQueue.empty()) {
                uint64_t when = std::max(curTick(), hmac_available);
                schedule(hmacEvent, when);
                hmac_available = when + hmac_latency;
            }

            hmacQueue.push_back(pkt);
        }
    } else {
        assert(pkt->isWrite());

        if (!pkt->req->is_hash_verified) {
            assert(std::find(hmacQueue.begin(),
                    hmacQueue.end(), pkt) != hmacQueue.end());

            // hmac queue is saturated, and the hmac hasn't been written to
            // memory yet, but the counter has been fetched
            // do nothing, as this will be re-triggered by the hmac
            // queue when it is done
        } else {
            // We have a few things to do here.
            // 1) We need to create HMAC memory request
            // 2) We need to update the index in memory
            //  ---> this will lead to data hazard! buffering reads/writes
            //       will be important... done in createMetadata!
            //       * incoming reads should use this value
            //       * incoming writes should use start from this value,
            //         and future writes should  -- does the cache handle this?
            assert(pkt->req->baobab_idx != nullptr);
            const uint8_t *new_idx = (uint8_t *) pkt->req->baobab_idx;

            createMetadata(pkt->req->hash_addr, hmac_level, false, nullptr);

            if (pkt->req->different_idx) {
                uint64_t addr = pkt->req->parent_addr;
                for (int level = data_level - 1; level >= 1; level--) {
                    if (level == data_level - 1) {
                        createMetadata(addr, level, false, nullptr, new_idx);
                    } else {
                        createMetadata(addr, level, false, nullptr);
                    }

                    if (level > 1) {
                        addr = calculateAddress(addr, level, false);
                    }
                }
            }

            mem_side_port.sendPacket(pkt);
        }
    }

    if (!cipherQueue.empty() && !cipherEvent.scheduled()) {
        uint64_t when = std::max(curTick(), cipher_available);
        schedule(cipherEvent, when);
        cipher_available = when + cipher_latency;
    }
}

void
BaobabEncryptionEngine::processHmacEvent()
{
    assert(!hmacQueue.empty());

    PacketPtr pkt = hmacQueue.front();
    hmacQueue.pop_front();

    pkt->req->is_hash_verified = true;

    if (pkt->req->tree_level == data_level) {
        if (pkt->isRead()) {
            assert(pkt->req->is_data_returned);
            assert(pkt->req->is_hash_fetched);
            assert(pkt->req->is_counter_verified);

            // TODO: something fun with hmac? compare with ciphered data?
            // uint64_t ctr = pkt->req->baobab_ctr;

            cpu_side_port.sendPacket(pkt);
        } else {
            // Hello, write operation! :-)
            // TODO: do we want to store the decrypted
            // hash at some point?
            assert(pkt->isWrite());

            // Case where hmac queue was saturated, and
            // the counter has been fetched and is trusted
            // we should start the cipher
            if (pkt->req->is_counter_fetched) {
                if (std::find(cipherQueue.begin(),
                            cipherQueue.end(), pkt) == cipherQueue.end()) {
                    if (cipherQueue.empty() || !cipherEvent.scheduled()) {
                        uint64_t when = std::max(curTick(), cipher_available);
                        schedule(cipherEvent, when);
                        cipher_available = when + cipher_latency;
                    }

                    cipherQueue.push_back(pkt);
                }
            }
        }
    } else {
        // We have a tree node
        assert(pkt->req->is_data_returned);
        handleTreeResponse(pkt);
    }

    if (!hmacQueue.empty() && !hmacEvent.scheduled()) {
        uint64_t when = std::max(curTick(), hmac_available);
        schedule(hmacEvent, when);
        hmac_available = when + hmac_latency;
    }
}

void
BaobabEncryptionEngine::respondInvalidate()
{
    assert(!invalidateQueue.empty());

    PacketPtr pkt = invalidateQueue.front();
    invalidateQueue.pop_front();

    pkt->makeResponse();

    metadata_response_port.sendPacket(pkt);

    if (!invalidateQueue.empty()) {
        schedule(respondInvalidateEvent, curTick());
    }
}

void
BaobabEncryptionEngine::retrySendMetadata()
{
    assert(!metadata_request_port.blockedPackets.empty());

    PacketPtr pkt = metadata_request_port.blockedPackets.front();
    metadata_request_port.blockedPackets.pop_front();

    metadata_request_port.sendPacket(pkt);
}

void
BaobabEncryptionEngine::createMetadata(uint64_t addr, int tree_level,
    bool is_read, PacketPtr child, const uint8_t *data, bool is_wt)
{
    // Fill child fields
    if (is_read && tree_level == hmac_level) {
        child->req->hash_addr = addr;
    } else if (child != nullptr) {
        child->req->parent_addr = addr;
    }

    std::unordered_map<uint64_t, gem5::PacketPtr>::iterator it;
    if (is_read && (it = pending_metadata_writes.find(addr))
                != pending_metadata_reads.end()) {
        if (child != nullptr) {
            it->second->req->child_requests.push_back(child);
        }

        return;
    } else if (is_read && (it = pending_metadata_reads.find(addr))
                != pending_metadata_reads.end()) {
        if (child != nullptr) {
            it->second->req->child_requests.push_back(child);
        }

        return;
    } else if (!is_read && (it = pending_metadata_writes.find(addr))
                != pending_metadata_writes.end()) {
        if (child != nullptr) {
            it->second->req->child_requests.push_back(child);
        }

        return;
    }

    RequestPtr req = std::make_shared<Request>(addr, 64, 0, 0);
    req->tree_level = tree_level;
    req->metadata_addr = addr;
    req->req_type = is_read ?
                Request::RequestType::MetadataRead
                : Request::RequestType::MetadataWrite;
    req->arrived = curTick();

    MemCmd cmd = is_read ? MemCmd::ReadReq : MemCmd::WriteReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    if (pkt->isWrite() && tree_level == data_level - 1) {
        assert(data != nullptr);
        pkt->setData(data);
    }

    if (is_read) {
        pending_metadata_reads.insert
                (std::pair<uint64_t, PacketPtr>(addr, pkt));
    } else {
        if (!is_wt) {
            pkt->req->needs_writethrough = false;
        } else {
            pkt->req->req_type = Request::RequestType::MetadataWriteThrough;
        }
        pending_metadata_writes.insert(
                std::pair<uint64_t, PacketPtr>(addr, pkt));
    }

    // Add child to child_requests of parent and let child track parent
    if (child != nullptr) {
        pkt->req->child_requests.push_back(child);
    }

    if (!cache_hmacs && tree_level == hmac_level) {
        mem_side_port.sendPacket(pkt);
    } else {
        metadata_request_port.sendPacket(pkt);
    }
}

uint64_t
BaobabEncryptionEngine::getTableIndex(uint64_t addr)
{
    uint64_t index = ((addr - start_addr) / BLOCK_SIZE) %
        num_memoization_entries;

    assert(index < num_memoization_entries);

    return index;
}


uint64_t*
BaobabEncryptionEngine::getTableEntry(uint64_t addr)
{
    uint64_t index = getTableIndex(addr);
    uint64_t *entry = memoization_table + (index * cells_per_entry *
        sizeof(uint64_t));

    assert((entry - memoization_table) % (sizeof(uint64_t) *
        cells_per_entry) == 0);

    return entry;
}

uint64_t
BaobabEncryptionEngine::getMemoizedCounter(uint64_t addr, uint64_t *data)
{
    // Get the word associated with this data
    uint64_t counters_per_block = (BLOCK_SIZE / bits_per_index);
    uint64_t index = ((addr / BLOCK_SIZE) % counters_per_block) / 64;
    uint64_t word_index = ((addr / BLOCK_SIZE) % counters_per_block) / 64;
    uint64_t mask = (bits_per_index - 1) << (bits_per_index * word_index);

    uint64_t data_word = data[index];

    uint64_t entry_index = (data_word & mask) >> (bits_per_index * word_index);
    uint64_t *table_entry = getTableEntry(addr);

    return *(table_entry + (sizeof(uint64_t) * entry_index));
}

std::pair<uint64_t, uint64_t>
BaobabEncryptionEngine::getNextCounter(uint64_t addr, uint64_t old_index)
{
    uint64_t *cell;
    uint64_t current_ctrs[cells_per_entry];
    uint64_t current_holders[cells_per_entry];
    uint64_t *entry = getTableEntry(addr);

    uint64_t size_of_shift = (64 - bits_in_holder - 1);

    for (int i = 0; i < cells_per_entry; i++) {
        cell = entry + (i * sizeof(uint64_t));
        current_ctrs[i] = *(cell) & ((1ULL << size_of_shift) - 1);
        current_holders[i] = (*(cell) & ~((1ULL << size_of_shift) - 1))
                >> size_of_shift;
    }

    // Case where we are the only holder of our current cell.
    // Just increment and exit
    if (current_holders[old_index] == 1) {
        entry[old_index] = current_ctrs[old_index] + 1;

        // do not overflow maximum counter! should be rare...
        assert(entry[old_index] < max_counter);
        return std::pair<uint64_t, uint64_t>
                (current_ctrs[old_index] + 1, old_index);
    }

    uint64_t next_counter = -1; // what should the value that we return be?
    // where is the value that we return?
    uint64_t next_index = cells_per_entry;
    // if we are the largest counter, where do we go?
    uint64_t free_cell_index = cells_per_entry;
    uint64_t old_counter = current_ctrs[old_index];
    bool is_highest_counter = true;

    for (int i = 0; i < cells_per_entry; i++) {
        if (current_ctrs[i] > old_counter) {
            assert(current_holders != 0);
            is_highest_counter = false;

            if (current_ctrs[i] < next_counter) {
                next_counter = current_ctrs[i];
                next_index = i;
            }
        } else if (current_holders[i] == 0 &&
                free_cell_index == cells_per_entry) {
            free_cell_index = i;
        }
    }

    if (is_highest_counter) {
        next_counter = old_counter + 1;
        next_index = free_cell_index;

        entry[next_index] = (1ULL << size_of_shift) | next_counter;
    } else {
        entry[next_index] = (entry[next_index] & ((1ULL << size_of_shift) - 1))
            | ((current_holders[next_index] + 1) << size_of_shift);
    }

    // TODO: what happens when next_index is equal to cells_per_entry?
    // should we handle that here or in the handleResponse?
    if (next_index == cells_per_entry) {
        // Case where we block, should be rare?
        assert(false);
    }

    assert(next_counter < max_counter);

    uint64_t *old_entry = (uint64_t *) entry + (sizeof(uint64_t) * old_index);
    *old_entry = (entry[old_index] & ((1ULL << size_of_shift) - 1))
        | ((current_holders[old_index] - 1) << size_of_shift);

    return std::pair<uint64_t, uint64_t>(next_counter, next_index);
}


uint64_t *
BaobabEncryptionEngine::updateMemoryIndex(uint64_t addr,
        uint64_t *data, uint64_t idx)
{
    // Get the word associated with this data
    uint64_t counters_per_block = (BLOCK_SIZE / bits_per_index);
    uint64_t index = ((addr / BLOCK_SIZE) % counters_per_block) / 64;
    uint64_t word_index = ((addr / BLOCK_SIZE) % counters_per_block) / 64;
    uint64_t mask = (bits_per_index - 1) << (bits_per_index * word_index);

    uint64_t old_data = data[index];

    data[index] = (old_data & ~mask) |
            idx << (bits_per_index * word_index);

    // we are going to call malloc without calling free, because
    // the pointer from ret will be stored as an object of the packet
    // that will ultimately be destroyed...
    // if there is a memory leak, look here
    uint64_t *ret = (uint64_t *) malloc(8 * sizeof(uint64_t));
    ret = data;

    return ret;
}

uint64_t
BaobabEncryptionEngine::calcHashAddr(PacketPtr pkt)
{
    uint64_t addr = pkt->req->is_metadata() ?
                            pkt->req->metadata_addr : pkt->getAddr();
    uint64_t block_num = (addr -
                integrity_levels[pkt->req->tree_level]) / BLOCK_SIZE;

    // block of hash (ARITY is the hashes per block)
    uint64_t hash_block = block_num / 8;

    uint64_t hash_addr = (hash_block * BLOCK_SIZE) + integrity_levels[0];

    assert(hash_addr >= (start_addr + memory_size));
    assert(hash_addr < start_addr + (2 * memory_size));
    return hash_addr;
}

uint64_t
BaobabEncryptionEngine::calculateAddress(
                    uint64_t addr, int tree_level, bool counter)
{
    uint64_t block_num = (addr -
                integrity_levels[tree_level]) / BLOCK_SIZE;

    uint64_t parent_block;
    uint64_t parent_addr;
    if (counter) { // if we're trying to calculate counter addr
        parent_block = block_num / baobab_counter_arity;
    } else {
        parent_block = block_num / ARITY;
    }

    uint64_t num_blocks = (integrity_levels[tree_level - 1] -
                integrity_levels[tree_level]) / BLOCK_SIZE;
    assert(parent_block < num_blocks);

    parent_addr = (parent_block * BLOCK_SIZE) +
                    integrity_levels[tree_level - 1];

    assert(parent_addr != addr);
    assert(parent_addr >= start_addr + memory_size);
    assert(parent_addr < start_addr + (2 * memory_size));

    return parent_addr;
}

bool
BaobabEncryptionEngine::handleRequest(PacketPtr pkt)
{
    if (active_requests.size() >= max_active_requests) {
        return false;
    }

    // stat counting
    data_accesses.push_back(pkt->getAddr());

    auto insert = active_requests.insert(pkt);
    assert(insert.second);

    // We have a weird case where mem_ctrl re-ordering
    // can result in a the following behavior:
    //     (1) Pkt A (writeback) arrives, fully updates
    //         its leaf to root path and is blocked in
    //         mem_side_port.blockedPackets
    //     (2) Pkt B (read for same address as Pkt A)
    //         has all of it metadata put into the
    //         mem_side_port queue, and the mem_ctrl
    //         is in read state, so these get processed
    //         right away
    //     (3) Pkt B returns to the processor with stale
    //         data, which the on-chip hierarchy thinks
    //         is incorrect because we returned true on
    //         recving Pkt A
    // So we handle this case where we ensure that B has
    // the correct data here -- this requires updating
    // src/mem/abstract_mem.cc as well
    for (auto it = active_requests.begin();
                it != active_requests.end(); ++it) {
        if ((*it)->getAddr() == pkt->getAddr() && pkt->isRead() &&
                (*it)->isWrite()) {
            (*it)->writeData(pkt->getPtr<uint8_t>());
            pkt->req->is_prefill = true;
        }
    }

    uint64_t entry_index = getTableIndex(pkt->getAddr());

    if (eviction_entries[entry_index] != 0) {
        // Accesses to this memoization table entry are blocked
        return false;
    }

    pkt->req->tree_level = data_level;

    // Get counter for data
    uint64_t ctr_addr = calculateAddress(pkt->getAddr(), data_level, true);
    createMetadata(ctr_addr, data_level - 1, true, pkt);

    // Get address for HMAC, will be used now for reads and later for writes
    uint64_t hmac_addr = calcHashAddr(pkt);
    pkt->req->hash_addr = hmac_addr;

    if (pkt->isRead()) {
        // Get HMAC for data
        createMetadata(hmac_addr, hmac_level, pkt->isRead(), pkt);

        mem_side_port.sendPacket(pkt);
    } else {
        assert(pkt->isWrite());
        // HMAC will be created when the counter is fetched so that
        // the store is atomic, but value is computed now
        if (hmacQueue.empty() || !hmacEvent.scheduled()) {
            uint64_t when = std::max(curTick(), hmac_available);
            schedule(hmacEvent, when);
            hmac_available = when + hmac_latency;
        }

        hmacQueue.push_back(pkt);
    }

    return true;
}


void
BaobabEncryptionEngine::handleHmacResponse(PacketPtr pkt)
{
    assert(pkt->req->tree_level == hmac_level);

    if (pkt->isRead()) {
        pending_metadata_reads.erase(pkt->getAddr());
    } else {
        assert(pkt->isWrite());
        pending_metadata_writes.erase(pkt->getAddr());
    }

    for (auto child = pkt->req->child_requests.begin();
            child != pkt->req->child_requests.end(); ++child) {
        if ((*child)->req->is_data_returned &&
                    (*child)->req->is_counter_verified) {
            if (hmacQueue.empty() || !hmacEvent.scheduled()) {
                uint64_t when = std::max(curTick(), hmac_available);
                schedule(hmacEvent, when);
                hmac_available = when + hmac_latency;
            }

            hmacQueue.push_back(*child);
        }

        (*child)->req->is_hash_fetched = true;

        if (!pkt->req->metadata_cache_miss) {
            (*child)->req->hmac_hit = true;
        }
    }

    delete pkt;
}

void
BaobabEncryptionEngine::treeResponseHelper(std::vector<PacketPtr> children,
                uint64_t *data, uint64_t addr)
{
    for (auto child = children.begin(); child != children.end(); ++child) {
        bool deleted = false;

        if ((*child)->isRead()) {
            if ((*child)->req->tree_level == data_level) {
                if ((*child)->req->is_data_returned) {
                     if (cipherQueue.empty() || !cipherEvent.scheduled()) {
                         uint64_t when = std::max(curTick(),
                            cipher_available);
                         schedule(cipherEvent, when);
                         cipher_available = when + cipher_latency;
                     }

                     cipherQueue.push_back(*child);
                }

                uint64_t ctr = getMemoizedCounter((*child)->getAddr(),
                    data);
                (*child)->req->baobab_ctr = ctr;
                memcpy((*child)->req->baobab_idx, data, sizeof(uint64_t) * 8);
            } else {
                if (hmacQueue.empty() || !hmacEvent.scheduled()) {
                    uint64_t when = std::max(curTick(), hmac_available);
                    schedule(hmacEvent, when);
                    hmac_available = when + hmac_latency;
                }

                hmacQueue.push_back(*child);
            }
        } else if ((*child)->isWrite()) {
            if ((*child)->req->tree_level == data_level) {
                // data for us is the index in the memoization table entry
                // we need to increment the value at that entry, and
                // find an empty memoization table entry to move into
                uint64_t idx_of_idx = (((*child)->getAddr() / BLOCK_SIZE)
                    % baobab_counter_arity);
                uint64_t block_idx = idx_of_idx / 64;
                uint64_t idx_in_blk = idx_of_idx % 8;

                uint64_t d = data[block_idx];

                uint64_t old_idx = d & ((bits_per_index - 1)
                    << (bits_per_index * idx_in_blk));
                old_idx >>= (bits_per_index * idx_of_idx);

                auto ctr_pair = getNextCounter((*child)->
                    getAddr(), old_idx);
                uint64_t value = ctr_pair.first;
                uint64_t index = ctr_pair.second;

                (*child)->req->baobab_ctr = value;
                memcpy((*child)->req->baobab_idx, updateMemoryIndex(
                    (*child)->getAddr(), data, index), sizeof(uint64_t) * 8);

                if (index == old_idx) {
                    (*child)->req->different_idx = false;
                }

                if (!(*child)->req->is_hash_verified) {
                    // Case where hmac queue is super saturated, it will
                    // trigger the cipher when necessary
                    assert(std::find(hmacQueue.begin(), hmacQueue.end(),
                            *child) != hmacQueue.end());
                } else if (cipherQueue.empty()
                           || !cipherEvent.scheduled()) {
                    uint64_t when = std::max(curTick(), cipher_available);
                    schedule(cipherEvent, when);
                    cipher_available = when + cipher_latency;
                }

                cipherQueue.push_back(*child);
            } else {
                assert((*child)->req->tree_level < data_level &&
                    (*child)->req->tree_level > 0);
                assert((*child)->getAddr() == addr);

                uint64_t *new_ctr = updateMemoryIndex(addr,
                    data, (*child)->req->baobab_ctr);
                const uint8_t *new_data = (uint8_t *) new_ctr;

                createMetadata((*child)->getAddr(),
                    (*child)->req->tree_level, false, nullptr, new_data);
                delete *child;

                deleted = true;
            }
        }

        // The child isn't returned yet, tell it we are fetched and know
        // the value
        if (!deleted) {
            (*child)->req->is_counter_fetched = true;

            if ((*child)->req->tree_level != data_level) {
                // We are not dealing with the rest of the tree right now
                (*child)->req->is_hash_fetched = true;
            }
        }
    }
}

void
BaobabEncryptionEngine::handleTreeResponse(PacketPtr pkt)
{
    if (trusted(pkt)) {
        // We no longer want to buffer updates to this data
        if (pkt->isRead()) {
            pending_metadata_reads.erase(pkt->getAddr());
        } else {
            assert(pkt->isWrite());
            pending_metadata_writes.erase(pkt->getAddr());
        }

        treeResponseHelper(pkt->req->child_requests,
                        pkt->getPtr<uint64_t>(), pkt->getAddr());

        // Done with packet
        delete pkt;
    } else {
        if (pkt->req->tree_level == data_level - 1) {
            // Check to see if we are trusted to proceed
            // with a particular child
            std::vector<PacketPtr> children;
            for (auto child = pkt->req->child_requests.begin();
                    child != pkt->req->child_requests.end(); ++child) {
                if ((*child)->req->hmac_hit && std::find(cipherQueue.begin(),
                        cipherQueue.end(), *child) != cipherQueue.end()) {
                    assert(cache_hmacs);
                    (*child)->req->is_counter_fetched = true;

                    children.push_back(*child);
                    pkt->req->child_requests.erase(child);
                    --child;
                }

                if (children.size() != 0) {
                    treeResponseHelper(children, pkt->getPtr<uint64_t>());
                }
            }
        }

        // We do not trust the packet yet (requires fetching)
        // the rest of the tree

        // If we are untrusted, then this function will be called again
        // when the value is trusted, so do nothing
        assert(pkt->isRead());
        uint64_t addr = calculateAddress(pkt->getAddr(),
                pkt->req->tree_level, false);
        createMetadata(addr, pkt->req->tree_level - 1, true, pkt);
    }
}

bool
BaobabEncryptionEngine::handleResponse(PacketPtr pkt)
{
    if (pkt->req->tree_level == data_level) {
        // We have received data
        if (pkt->isRead()) {
            if (pkt->req->is_counter_fetched) {
                // If the counter hasn't been verified yet, it will
                // trigger the decryption on its verification
                assert(pkt->req->baobab_ctr != -1);

                if (cipherQueue.empty() || !cipherEvent.scheduled()) {
                    uint64_t when = std::max(curTick(), cipher_available);
                    schedule(cipherEvent, when);
                    cipher_available = when + cipher_latency;
                }

                cipherQueue.push_back(pkt);
            }

            if (pkt->req->is_hash_fetched && pkt->req->is_counter_fetched &&
                            pkt->req->is_counter_verified) {
                // I. If the hash hasn't been returned yet, it will
                // trigger the hashing on its retrieval
                // II. If the data hasn't been decrypted yet, then
                // the hash cannot be verified, the verification will
                // be scheduled by the decryption
                if (hmacQueue.empty() || !hmacEvent.scheduled()) {
                    uint64_t when = std::max(curTick(), hmac_available);
                    schedule(hmacEvent, when);
                    hmac_available = when + cipher_latency;
                }

                hmacQueue.push_back(pkt);
            }

            return true;
        } else {
            assert(pkt->isWrite());
            assert(pkt->needsResponse());

            cpu_side_port.sendPacket(pkt);
            return true;
        }
    } else {
        // We have received metadata
        if (pkt->req->tree_level == 0) {
            handleHmacResponse(pkt);
        } else {
            handleTreeResponse(pkt);
        }
    }

    return true;
}

///////////////////////////////////////////
///////// CPU SIDE PORT FUNCTIONS /////////
///////////////////////////////////////////
AddrRangeList
BaobabEncryptionEngine::CpuSidePort::getAddrRanges() const
{
    return owner->mem_side_port.getAddrRanges();
}

void
BaobabEncryptionEngine::CpuSidePort::trySendRetry()
{
    // Only send a retry if the port is now completely free
    if (needRetry) {
        sendRetryReq();
    }

    if (blockedPackets.empty()) {
        needRetry = false;
    }
}

void
BaobabEncryptionEngine::CpuSidePort::sendPacket(PacketPtr pkt)
{
    assert(pkt->req->is_counter_verified && pkt->req->is_hash_verified);

    // Debugging
    if (owner->memory.find(pkt->getAddr()) != owner->memory.end()) {
        uint64_t actual_data = owner->memory[pkt->getAddr()];
        uint64_t fetched_data = *pkt->getPtr<uint64_t>();
        assert(actual_data == fetched_data);
    }

    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
        needRetry = true;
    } else {
        assert(owner->active_requests.find(pkt) !=
                owner->active_requests.end());
        owner->active_requests.erase(pkt);

        sendRetryReq();
    }
}

void
BaobabEncryptionEngine::CpuSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->mem_side_port.sendFunctional(pkt);
}

bool
BaobabEncryptionEngine::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    return owner->handleRequest(pkt);
}

void
BaobabEncryptionEngine::CpuSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
        needRetry = false;
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();
    blockedPackets.pop_front();

    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);
}

///////////////////////////////////////////
///////// MEM SIDE PORT FUNCTIONS /////////
///////////////////////////////////////////

void
BaobabEncryptionEngine::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (pkt->isRead()) {
        pkt->headerDelay += owner->mem_read_latency;
    } else {
        pkt->headerDelay += owner->mem_write_latency;
    }

    blockedPackets.push_back(pkt);
    PacketPtr to_send = blockedPackets.front();

    while (sendTimingReq(to_send)) {
        blockedPackets.pop_front();

        // Debugging
        if (to_send->isWrite()) {
            uint64_t data = *to_send->getPtr<uint64_t>();
            owner->memory[to_send->getAddr()] = data;
        }

        if (!to_send->needsResponse() && !to_send->isResponse() &&
                to_send->req->tree_level == owner->data_level) {
            assert(owner->active_requests.find(to_send) !=
                    owner->active_requests.end());
            owner->active_requests.erase(to_send);

            assert(to_send->isWrite());
            owner->cpu_side_port.sendRetryReq();
        }

        if (!blockedPackets.empty()) {
            to_send = blockedPackets.front();
        } else {
            break;
        }
    }
}

bool
BaobabEncryptionEngine::MemSidePort::trySendPacket(PacketPtr pkt)
{
    return sendTimingReq(pkt);
}

bool
BaobabEncryptionEngine::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    if (pkt->req->is_metadata() && !(!owner->cache_hmacs &&
            pkt->req->tree_level == owner->hmac_level)) {
        owner->metadata_response_port.sendPacket(pkt);

        return true;
    } else if (pkt->req->tree_level == owner->data_level) {
        // Related to the weird case described in handleRequest
        // If we get a response from memory on a read, and a
        // write came in while we were pending, then we need
        // to have the value of the write
        for (auto it = owner->active_requests.begin();
                it != owner->active_requests.end(); ++it) {
            if ((*it)->isWrite() && (*it)->getAddr() == pkt->getAddr()) {
                assert(pkt->isRead());
                (*it)->writeData(pkt->getPtr<uint8_t>());
                pkt->req->is_prefill = true;
            }
        }

        for (auto it = blockedPackets.begin();
                it != blockedPackets.end(); ++it) {
            if ((*it)->isWrite() && (*it)->getAddr() == pkt->getAddr()) {
                assert(pkt->isRead());
                (*it)->writeData(pkt->getPtr<uint8_t>());
                pkt->req->is_prefill = true;
            }
        }
    }

    pkt->req->is_data_returned = true;

    return owner->handleResponse(pkt);
}

void
BaobabEncryptionEngine::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();

    // Try to resend it. It's possible that it fails again.
    if (trySendPacket(pkt)) {
        blockedPackets.pop_front();
        owner->cpu_side_port.trySendRetry();
    }
}

void
BaobabEncryptionEngine::MemSidePort::recvRangeChange()
{
    owner->metadata_response_port.sendRangeChange();
}

///////////////////////////////////////////////////
///////// METADATA REQUEST PORT FUNCTIONS /////////
///////////////////////////////////////////////////
bool
BaobabEncryptionEngine::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
{
    pkt->req->is_data_returned = true;
    owner->handleResponse(pkt);

    if (!blockedPackets.empty()) {
        owner->scheduleRetrySendMetadata();
    }

    return true;
}

void
BaobabEncryptionEngine::MetadataRequestPort::recvReqRetry()
{
    if (blockedPackets.empty()) {
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();

    // Try to resend it and preserve order. It's possible that it fails again.
    if (trySendPacket(pkt)) {
        blockedPackets.pop_front();
    }
}

void
BaobabEncryptionEngine::MetadataRequestPort::sendPacket(PacketPtr pkt)
{
    blockedPackets.push_back(pkt);
    PacketPtr to_send = blockedPackets.front();

    while (sendTimingReq(to_send)) {
        blockedPackets.pop_front();

        if (!blockedPackets.empty()) {
            to_send = blockedPackets.front();
        } else {
            break;
        }
    }
}

void
BaobabEncryptionEngine::MetadataRequestPort::recvRangeChange()
{
    owner->cpu_side_port.sendRangeChange();
}

bool
BaobabEncryptionEngine::MetadataRequestPort::trySendPacket(PacketPtr pkt)
{
    if (sendTimingReq(pkt)) {
        pkt->req->sent_to_mem = true;
        assert(pkt->req->is_metadata());

        return true;
    }

    return false;
}

////////////////////////////////////////////////////
///////// METADATA RESPONSE PORT FUNCTIONS /////////
////////////////////////////////////////////////////

bool
BaobabEncryptionEngine::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
{
    if (!(pkt->isRead() || pkt->isWrite())) {
        if (pkt->needsResponse()) {
            assert(pkt->isInvalidate());

            owner->scheduleInvalidate();
            owner->invalidateQueue.push_back(pkt);

            return true;
        }

        return true;
    } else if (pkt->isRead()) {
        assert(owner->pending_metadata_reads.find(pkt->getAddr()) !=
                owner->pending_metadata_reads.end());
        owner->pending_metadata_reads[pkt->getAddr()]->req->
                metadata_cache_miss = true;
    } else if (!pkt->isEviction()) {
        assert(pkt->isWrite());
        assert(owner->pending_metadata_writes.find(pkt->getAddr()) !=
                owner->pending_metadata_writes.end());
        owner->pending_metadata_writes[pkt->getAddr()]->req->
                metadata_cache_miss = true;
    } else {
        pkt->req->req_type = Request::RequestType::MetadataWrite;
    }

    owner->mem_side_port.sendPacket(pkt);

    return true;
}

void
BaobabEncryptionEngine::MetadataResponsePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
    }
}

} // gem5

gem5::BaobabEncryptionEngine *
gem5::BaobabEncryptionEngineParams::create() const
{
    return new gem5::BaobabEncryptionEngine(this);
}
