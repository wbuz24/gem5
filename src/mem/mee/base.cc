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

#include "mem/mee/base.hh"

#include "params/BaseMemoryEncryptionEngine.hh"

namespace gem5 {

BaseMemoryEncryptionEngine::BaseMemoryEncryptionEngine
        (const BaseMemoryEncryptionEngineParams *p) :
    SimObject(*p),
    cpu_side_port(p->name + ".cpu_side", this),
    mem_side_port(p->name + ".mem_side", this),
    metadata_request_port(p->name + ".metadata_request_port", this),
    metadata_response_port(p->name + ".metadata_response_port", this),
    start_addr(p->start_addr), num_gb(p->num_gb),
    far_memory_factor(p->far_mem_mult)
{
    start_addr *= GB_IN_B;

    // DRAM size in bytes
    uint64_t total_size = GB_IN_B * (uint64_t) num_gb;
    uint64_t number_of_blocks = total_size / BLOCK_SIZE;
    //round to a power of eight
    uint64_t eights = 8;
    do {
        eights = eights * 8;
    } while (eights < number_of_blocks);
    number_of_blocks = eights;
    uint64_t num_blocks_on_last_level =
                                number_of_blocks / BONSAI_COUNTER_ARITY;

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
    integrity_levels[0] = start_addr + (num_gb * GB_IN_B);
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
}

Port&
BaseMemoryEncryptionEngine::getPort(const std::string &if_name, PortID idx)
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

bool
BaseMemoryEncryptionEngine::needsWritethrough(uint64_t addr, int tree_level)
{
    return tree_level == 0;
}

bool
BaseMemoryEncryptionEngine::doneWriting(PacketPtr pkt)
{
    return pkt->req->tree_level == 1 || pkt->req->is_counter_verified;
}

bool
BaseMemoryEncryptionEngine::trusted(PacketPtr pkt)
{
    return pkt->req->tree_level == 1 || !pkt->req->metadata_cache_miss ||
        pkt->req->is_counter_fetched;
}

void
BaseMemoryEncryptionEngine::evictionHandling(PacketPtr pkt)
{
    assert(pkt->isWrite());

    pkt->req->metadata_addr = pkt->getAddr();
    pkt->req->req_type = Request::MetadataWrite;
}

void
BaseMemoryEncryptionEngine::createMetadata(uint64_t addr, int tree_level,
    bool is_read, PacketPtr child, bool is_wt)
{
    // Fill child fields
    if (tree_level == hash_level) {
        child->req->hash_addr = addr;
    } else if (child != nullptr) {
        child->req->parent_addr = addr;
    }

    std::unordered_map<uint64_t, gem5::PacketPtr>::iterator it;
    if (is_read && (it = pending_metadata_reads.find(addr))
                != pending_metadata_reads.end()) {
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

    if (is_read) {
        if (tree_level != hash_level) {
            pending_metadata_reads.insert
                (std::pair<uint64_t, PacketPtr>(addr, pkt));
        }
    } else if (!is_wt) {
        pkt->req->needs_writethrough = needsWritethrough(addr, tree_level);
    } else {
        pkt->req->req_type = Request::RequestType::MetadataWriteThrough;
    }

    // Add child to child_requests of parent and let child track parent
    if (child != nullptr) {
        pkt->req->child_requests.push_back(child);
    }

    if (tree_level == hash_level) {
        mem_side_port.sendPacket(pkt);
    } else if (!is_wt) {
        metadata_request_port.sendPacket(pkt);
    } else {
        mem_side_port.sendPacket(pkt);
    }
}

uint64_t
BaseMemoryEncryptionEngine::calculateAddress(
                    uint64_t addr, int tree_level, bool counter)
{
    uint64_t block_num = (addr -
                integrity_levels[tree_level]) / BLOCK_SIZE;

    uint64_t parent_block;
    uint64_t parent_addr;
    if (counter) { // if we're trying to calculate counter addr
        parent_block = block_num / BONSAI_COUNTER_ARITY;
    } else {
        parent_block = block_num / ARITY;
    }

    uint64_t num_blocks = (integrity_levels[tree_level - 1] -
                integrity_levels[tree_level]) / BLOCK_SIZE;
    assert(parent_block < num_blocks);

    parent_addr = (parent_block * BLOCK_SIZE) +
                    integrity_levels[tree_level - 1];

    assert(parent_addr != addr);
    assert(parent_addr >= start_addr + (num_gb * GB_IN_B));
    assert(parent_addr < start_addr + (2 * num_gb * (GB_IN_B)));

    return parent_addr;
}

uint64_t
BaseMemoryEncryptionEngine::calcHashAddr(PacketPtr pkt)
{
    uint64_t addr = pkt->req->is_metadata() ?
                            pkt->req->metadata_addr : pkt->getAddr();
    uint64_t block_num = (addr -
                integrity_levels[pkt->req->tree_level]) / BLOCK_SIZE;

    // block of hash (ARITY is the hashes per block)
    uint64_t hash_block = block_num / 8;

    uint64_t hash_addr = (hash_block * BLOCK_SIZE) + integrity_levels[0];

    assert(hash_addr >= start_addr + (num_gb * GB_IN_B));
    assert(hash_addr < start_addr + (2 * num_gb * (GB_IN_B)));
    return hash_addr;
}

bool
BaseMemoryEncryptionEngine::handleRequest(PacketPtr pkt)
{
    assert(pkt->isRead() || pkt->isWrite());

    if (pkt->isRead()) {
        pkt->req->req_type = Request::DataRead;
    } else {
        pkt->req->req_type = Request::DataWrite;
    }

    pkt->req->metadata_addr = pkt->getAddr();

    int num_active_reads = 0;
    int num_active_writes = 0;

    for (auto it = active_requests.begin();
            it != active_requests.end(); ++it) {
        if ((*it)->isRead()) {
            num_active_reads++;
        } else {
            assert((*it)->isWrite());
            num_active_writes++;
        }

        if (num_active_reads >= max_active_reads
                || num_active_writes >= max_active_writes) {
            return false;
        }
    }

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
        if ((*it)->getAddr() == pkt->getAddr() &&
                pkt->isRead() && (*it)->isWrite()) {
            (*it)->writeData(pkt->getPtr<uint8_t>());
            pkt->req->is_prefill = true;
         }
    }

    // We are dealing with data
    pkt->req->tree_level = data_level;

    // 1. Create HMAC request for this data - R/W depending
    //    on data request type
    uint64_t hash_addr = calcHashAddr(pkt);
    createMetadata(hash_addr, 0, pkt->isRead(), pkt);

    // 2. Create counter for this request OR put self in
    //    the queue of an existing counter
    //        * Note: we should check for a write counter
    //                first - if it is in the WPQ then it
    //                is the most up-to-date version that
    //                hasn't been sent to memory yet, and
    //                we trust its value because it is on
    //                chip
    uint64_t parent_addr = calculateAddress(pkt->getAddr(),
        pkt->req->tree_level, true);
    createMetadata(parent_addr, data_level - 1, true, pkt);

    return true;
}

bool
BaseMemoryEncryptionEngine::handleResponse(PacketPtr pkt)
{
    // HMAC fetches do not impact the verification step
    if (pkt->req->tree_level == 0) {
        delete pkt;
        return true;
    }

    if (pkt->req->needs_writethrough) {
        createMetadata(pkt->getAddr(), pkt->req->tree_level, false, pkt, true);
    } else if (pkt->req->is_metadata() && pkt->isWrite()) {
        // We have a write response in the tree (not batched)
        if (pkt->req->req_type == Request::MetadataWriteThrough) {
            for (auto p = pkt->req->child_requests.begin();
                    p != pkt->req->child_requests.end(); ++p) {
                (*p)->req->needs_writethrough = false;

                handleResponse(*p);
            }

            delete pkt;
        } else if (doneWriting(pkt)) {
            for (auto p = pkt->req->child_requests.begin();
                    p != pkt->req->child_requests.end(); ++p) {
                (*p)->req->is_counter_verified = true;

                handleResponse(*p);
            }

            delete pkt;
        } else {
            uint64_t parent_addr = calculateAddress(pkt);
            createMetadata(parent_addr, pkt->req->tree_level - 1, false, pkt);
        }
    } else if (pkt->req->is_metadata() && pkt->isRead()) {
        if (trusted(pkt)) {
            pending_metadata_reads.erase(pkt->getAddr());

            for (auto p = pkt->req->child_requests.begin();
                    p != pkt->req->child_requests.end(); ++p) {
                (*p)->req->is_counter_fetched = true;

                handleResponse(*p);
            }

            delete pkt;
        } else {
            uint64_t parent_addr = calculateAddress(pkt);
            createMetadata(parent_addr, pkt->req->tree_level - 1, true, pkt);
        }
    } else {
        assert(!pkt->req->is_metadata());

        if (pkt->isRead()) {
            pkt->headerDelay += aes_latency + hmac_latency;
            mem_side_port.sendPacket(pkt);
        } else if (pkt->req->is_counter_fetched &&
                !pkt->req->is_counter_verified) {

            assert(pkt->isWrite());
            uint64_t parent_addr = calculateAddress(pkt->getAddr(),
                pkt->req->tree_level, true);
            createMetadata(parent_addr, pkt->req->tree_level - 1, false, pkt);
        } else {
            assert(pkt->isWrite());
            assert(pkt->req->is_counter_verified);

            pkt->headerDelay += aes_latency + hmac_latency;
            mem_side_port.sendPacket(pkt);
        }
    }


    return true;
}

///////////////////////////////////////////
///////// CPU SIDE PORT FUNCTIONS /////////
///////////////////////////////////////////
AddrRangeList
BaseMemoryEncryptionEngine::CpuSidePort::getAddrRanges() const
{
    return owner->mem_side_port.getAddrRanges();
}

void
BaseMemoryEncryptionEngine::CpuSidePort::trySendRetry()
{
    // Only send a retry if the port is now completely free
    sendRetryReq();

    if (blockedPackets.empty()) {
        needRetry = false;
    }
}

void
BaseMemoryEncryptionEngine::CpuSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
    }
}

void
BaseMemoryEncryptionEngine::CpuSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->mem_side_port.sendFunctional(pkt);
}

bool
BaseMemoryEncryptionEngine::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    if (owner->handleRequest(pkt)) {
        return true;
    }

    needRetry = true;
    return false;
}

void
BaseMemoryEncryptionEngine::CpuSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
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
BaseMemoryEncryptionEngine::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (pkt->req->is_shad) {
        pkt->headerDelay += 20000;
    } else if (pkt->isRead()) {
        pkt->headerDelay += owner->far_memory_factor *owner->mem_read_latency;
    } else {
        pkt->headerDelay += owner->far_memory_factor *owner->mem_write_latency;
    }

    blockedPackets.push_back(pkt);
    PacketPtr to_send = blockedPackets.front();

    if (sendTimingReq(to_send)) {
        blockedPackets.pop_front();
        to_send->req->sent_to_mem = true;

        if (to_send->req->needs_writethrough) {
            to_send->req->needs_writethrough = false;
        }

        if (!to_send->req->is_metadata()) {
            assert(owner->active_requests.find(to_send) !=
                owner->active_requests.end());
            owner->active_requests.erase(to_send);

            owner->cpu_side_port.trySendRetry();

            // Writes won't respond, so stuff blocked by them
            // will stay blocked
            PacketPtr next = blockedPackets.front();
            while (next && trySendPacket(next)) {
                blockedPackets.pop_front();
                next = blockedPackets.front();
                owner->cpu_side_port.trySendRetry();
            }
        }
    }
}

bool
BaseMemoryEncryptionEngine::MemSidePort::trySendPacket(PacketPtr pkt)
{
    if (sendTimingReq(pkt)) {
        pkt->req->sent_to_mem = true;

        if (pkt->req->needs_writethrough) {
            pkt->req->needs_writethrough = false;
        }

        if (!pkt->req->is_metadata()) {
            assert(owner->active_requests.find(pkt) !=
                owner->active_requests.end());
            owner->active_requests.erase(pkt);
        }

        return true;
    }

    return false;
}

bool
BaseMemoryEncryptionEngine::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    if (pkt->req->tree_level == 0) {
        return owner->handleResponse(pkt);
    }

    if (pkt->req->is_metadata()) {
        owner->metadata_response_port.sendPacket(pkt);
    } else {
        assert(pkt->req->tree_level == owner->data_level);
        assert(pkt->isResponse());

        // Related to the weird case described in handleRequest
        // If we get a response from memory on a read, and a
        // write came in while we were pending, then we need
        // to have the value of the write
        for (auto it = owner->active_requests.begin();
                it != owner->active_requests.end(); ++it) {
            if ((*it)->getAddr() == pkt->getAddr()) {
                    assert((*it)->isWrite());
                    (*it)->writeData(pkt->getPtr<uint8_t>());
                }
            }

        for (auto it = blockedPackets.begin();
                it != blockedPackets.end(); ++it) {
            if ((*it)->getAddr() == pkt->getAddr()) {
                assert((*it)->isWrite());
                (*it)->writeData(pkt->getPtr<uint8_t>());
            }
        }

        owner->cpu_side_port.sendPacket(pkt);
    }

    recvReqRetry();

    return true;
}

void
BaseMemoryEncryptionEngine::MemSidePort::recvReqRetry()
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
BaseMemoryEncryptionEngine::MemSidePort::recvRangeChange()
{
    owner->metadata_response_port.sendRangeChange();
}

///////////////////////////////////////////////////
///////// METADATA REQUEST PORT FUNCTIONS /////////
///////////////////////////////////////////////////
bool
BaseMemoryEncryptionEngine::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
{
    pkt->req->is_data_returned = true;
    owner->handleResponse(pkt);

    recvReqRetry();

    return true;
}

void
BaseMemoryEncryptionEngine::MetadataRequestPort::recvReqRetry()
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
BaseMemoryEncryptionEngine::MetadataRequestPort::sendPacket(PacketPtr pkt)
{
    assert(pkt->req->req_type != Request::RequestType::MetadataWriteThrough);
    assert(pkt->req->metadata_addr
                            > owner->start_addr + (GB_IN_B * owner->num_gb));

    blockedPackets.push_back(pkt);
    PacketPtr to_send = blockedPackets.front();

    if (sendTimingReq(to_send)) {
        blockedPackets.pop_front();
    }
}

void
BaseMemoryEncryptionEngine::MetadataRequestPort::recvRangeChange()
{
    owner->cpu_side_port.sendRangeChange();
}

bool
BaseMemoryEncryptionEngine::MetadataRequestPort::trySendPacket(PacketPtr pkt)
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
BaseMemoryEncryptionEngine::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
{
    pkt->req->metadata_cache_miss = true;

    if (pkt->isEviction()) {
        owner->evictionHandling(pkt);
    }

    owner->mem_side_port.sendPacket(pkt);

    return true;
}

}; // gem5

gem5::BaseMemoryEncryptionEngine *
gem5::BaseMemoryEncryptionEngineParams::create() const
{
    return new gem5::BaseMemoryEncryptionEngine(this);
}
