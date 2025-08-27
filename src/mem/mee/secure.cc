/*
 * Author: Will Buziak
 * Copyright (c) 2025 Colorado School of Mines 
 * All rights reserved.
 *
 * Based on the work by:
 * Author: Samuel Thomas
 * Copyright (c) 2022 Brown University
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

#include "mem/mee/secure.hh"

#include "params/SecureEncryptionEngine.hh"

namespace gem5 {

SecureEncryptionEngine::SecureEncryptionEngine
        (const SecureEncryptionEngineParams *p) :
    SimObject(*p),
    cpu_side_port(p->name + ".cpu_side", this),
    mem_side_port(p->name + ".mem_side", this),
    metadata_request_port(p->name + ".metadata_request_port", this),
    metadata_response_port(p->name + ".metadata_response_port", this),
    memory_size(p->num_gb << 30), start_addr(p->start_addr << 30),
    cache_hmacs(p->cache_hmac),
    cipherEvent([this] { processCipherEvent(); }, name()),
    hmacEvent([this] { processHmacEvent(); }, name()),
    respondInvalidateEvent([this] { respondInvalidate(); }, name()),
    retrySendMetadataEvent([this] { retrySendMetadata(); }, name()),
    stats(*this)
{
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
}

Port&
SecureEncryptionEngine::getPort(const std::string &if_name, PortID idx)
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
SecureEncryptionEngine::processCipherEvent()
{
    assert(!cipherQueue.empty());

    PacketPtr pkt = cipherQueue.front();
    cipherQueue.pop_front();

    assert(pkt->req->is_counter_fetched);
    pkt->req->is_counter_verified = true;

    if (pkt->isRead()) {
        assert(pkt->req->is_data_returned);
        assert(!pkt->req->is_hash_verified);
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
            createMetadata(pkt->req->hash_addr, hmac_level, false, nullptr);

            uint64_t addr = pkt->req->parent_addr;
            for (int level = data_level - 1; level >= 1; level--) {
                createMetadata(addr, level, false, nullptr);

                if (level > 1) {
                    addr = calculateAddress(addr, level, false);
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
SecureEncryptionEngine::processHmacEvent()
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
                    if (cipherQueue.empty()) {
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
SecureEncryptionEngine::respondInvalidate()
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
SecureEncryptionEngine::retrySendMetadata()
{
    assert(!metadata_request_port.blockedPackets.empty());

    PacketPtr pkt = metadata_request_port.blockedPackets.front();
    metadata_request_port.blockedPackets.pop_front();

    metadata_request_port.sendPacket(pkt);
}

void
SecureEncryptionEngine::createMetadata(uint64_t addr, int tree_level,
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

    if (pkt->isWrite() && tree_level == data_level - 1 && data) {
        assert(data != nullptr);
        pkt->setData(data);
    }

    if (is_read) {
        stats.metadata_reads++;
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
SecureEncryptionEngine::calcHashAddr(PacketPtr pkt)
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
SecureEncryptionEngine::calculateAddress(
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
    assert(parent_addr >= start_addr + memory_size);
    assert(parent_addr < start_addr + (2 * memory_size));

    return parent_addr;
}

bool
SecureEncryptionEngine::updateEpmp(uint32_t pmp_index, uint8_t this_cfg, Addr this_addr)
{
    // add pmpCfg within the ePMPTable
    stats.pmp_accesses++;
    epmpTable[pmp_index].pmpCfg = this_cfg;
    epmpTable[pmp_index].rawAddr = this_addr;

    printf("Is this printing?\n");
    return 1;
}

bool
SecureEncryptionEngine::handleRequest(PacketPtr pkt)
{

    printf("Sanity Check"); 
    if (active_requests.size() >= max_active_requests) {
        return false;
    }

    printf("PacketPtr->Addr: %ld\n\n", pkt->getAddr());

    stats.data_accesses++;

    auto insert = active_requests.insert(pkt);
    assert(insert.second);
    //if (!insert.second) return false;
    assert(start_addr == 0);

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
SecureEncryptionEngine::handleHmacResponse(PacketPtr pkt)
{
    assert(pkt->req->tree_level == 0);

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
    }

    delete pkt;
}

void
SecureEncryptionEngine::handleTreeResponse(PacketPtr pkt)
{
    if (trusted(pkt)) {
        // We no longer want to buffer updates to this data
        if (pkt->isRead()) {
            pending_metadata_reads.erase(pkt->getAddr());
        } else {
            assert(pkt->isWrite());
            pending_metadata_writes.erase(pkt->getAddr());
        }

        for (auto child = pkt->req->child_requests.begin();
                child != pkt->req->child_requests.end(); ++child) {
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
                } else {
                    if (hmacQueue.empty() || !hmacEvent.scheduled()) {
                        uint64_t when = std::max(curTick(), hmac_available);
                        schedule(hmacEvent, when);
                        hmac_available = when + hmac_latency;
                    }

                    hmacQueue.push_back(*child);
                }
            } else if ((*child)->isWrite()) {
                // We have fetched the counter associated with this data,
                // so we can cipher
                if ((*child)->req->tree_level == data_level) {
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
                    assert((*child)->getAddr() == pkt->getAddr());

                    createMetadata((*child)->getAddr(),
                        (*child)->req->tree_level, false, nullptr);
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

        // Done with packet
        delete pkt;
    } else {
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
SecureEncryptionEngine::handleResponse(PacketPtr pkt)
{
    if (pkt->req->tree_level == data_level) {
        // We have received data
        if (pkt->isRead()) {
            if (pkt->req->is_counter_fetched) {
                // If the counter hasn't been verified yet, it will
                // trigger the decryption on its verification
                if (cipherQueue.empty() || !cipherEvent.scheduled()) {
                    uint64_t when = std::max(curTick(), cipher_available);
                    schedule(cipherEvent, when);
                    cipher_available = when + cipher_latency;
                }

                cipherQueue.push_back(pkt);
            }

            if (pkt->req->is_hash_fetched && pkt->req->is_counter_verified) {
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
SecureEncryptionEngine::CpuSidePort::getAddrRanges() const
{
    return owner->mem_side_port.getAddrRanges();
}

void
SecureEncryptionEngine::CpuSidePort::trySendRetry()
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
SecureEncryptionEngine::CpuSidePort::sendPacket(PacketPtr pkt)
{
    assert(pkt->req->is_counter_verified && pkt->req->is_hash_verified);

    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
        needRetry = true;
    } else {
        assert(owner->active_requests.find(pkt) !=
                owner->active_requests.end());
        owner->active_requests.erase(pkt);
        trySendRetry();

        owner->metadata_request_port.recvReqRetry();
    }
}

void
SecureEncryptionEngine::CpuSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->mem_side_port.sendFunctional(pkt);
}

bool
SecureEncryptionEngine::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    printf("\n\nrecvTimingReq\n\n");
    return owner->handleRequest(pkt);
}

void
SecureEncryptionEngine::CpuSidePort::recvRespRetry()
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
SecureEncryptionEngine::MemSidePort::sendPacket(PacketPtr pkt)
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

        if (!to_send->needsResponse() && !to_send->isResponse() &&
                to_send->req->tree_level == owner->data_level) {
            assert(owner->active_requests.find(to_send) !=
                owner->active_requests.end());
            owner->active_requests.erase(to_send);

            assert(to_send->isWrite());
            //owner->cpu_side_port.sendRetryReq();
        }

        if (!blockedPackets.empty()) {
            to_send = blockedPackets.front();
        } else {
            break;
        }
    }
}

bool
SecureEncryptionEngine::MemSidePort::trySendPacket(PacketPtr pkt)
{
    return sendTimingReq(pkt);
}

bool
SecureEncryptionEngine::MemSidePort::recvTimingResp(PacketPtr pkt)
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
SecureEncryptionEngine::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();

    // Try to resend it. It's possible that it fails again.
    while (sendTimingReq(pkt)) {
        owner->cpu_side_port.trySendRetry();
        // hopefully fix issues with large arrays
        if (!pkt->needsResponse() && !pkt->isResponse() && pkt->req->tree_level == owner->data_level) {
          assert(owner->active_requests.find(pkt) != owner->active_requests.end());
          owner->active_requests.erase(pkt);

        }
        blockedPackets.pop_front();
        if (!blockedPackets.empty()) {
          pkt = blockedPackets.front();
        }
        else break;
    }
}

void
SecureEncryptionEngine::MemSidePort::recvRangeChange()
{
    owner->metadata_response_port.sendRangeChange();
}

///////////////////////////////////////////////////
///////// METADATA REQUEST PORT FUNCTIONS /////////
///////////////////////////////////////////////////
bool
SecureEncryptionEngine::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
{
    pkt->req->is_data_returned = true;
    owner->handleResponse(pkt);

    if (!blockedPackets.empty()) {
        owner->scheduleRetrySendMetadata();
    }

    return true;
}

void
SecureEncryptionEngine::MetadataRequestPort::recvReqRetry()
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
SecureEncryptionEngine::MetadataRequestPort::sendPacket(PacketPtr pkt)
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
SecureEncryptionEngine::MetadataRequestPort::recvRangeChange()
{
    owner->cpu_side_port.sendRangeChange();
}

bool
SecureEncryptionEngine::MetadataRequestPort::trySendPacket(PacketPtr pkt)
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
SecureEncryptionEngine::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
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
SecureEncryptionEngine::MetadataResponsePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
    }
}

SecureEncryptionEngine::MEEStats::MEEStats(SecureEncryptionEngine &secure) :
    statistics::Group(&secure), m(secure),

    ADD_STAT(data_accesses, statistics::units::Count::get(),
             "number of times we make a data request to memory"),
    ADD_STAT(metadata_reads, statistics::units::Count::get(),
             "number of times we make a metadata read req"),
    ADD_STAT(pmp_accesses, statistics::units::Count::get(),
             "number of times we make a pmp update")
{
}

void
SecureEncryptionEngine::MEEStats::regStats()
{
    using namespace statistics;

    statistics::Group::regStats();
}

} // gem5

gem5::SecureEncryptionEngine *
gem5::SecureEncryptionEngineParams::create() const
{
    return new gem5::SecureEncryptionEngine(this);
}
