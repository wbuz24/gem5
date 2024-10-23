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

#include "mem/mee/huffman.hh"

namespace gem5
{

HuffmanEncryptionEngine::HuffmanEncryptionEngine
        (const HuffmanEncryptionEngineParams *p) :
    TimingEncryptionEngine(p),
    clearInactiveEvent([this] { clearInactive(); }, name())
{
    max_index = (p->num_gb * GB_IN_B) / PAGE_SIZE;
}

void
HuffmanEncryptionEngine::startup()
{
    schedule(clearInactiveEvent, curTick());
}

void
HuffmanEncryptionEngine::incrementFrequency(uint64_t addr)
{
    std::unordered_map<uint64_t, int>::iterator it;
    if ((it = increment_map.find(addr)) != increment_map.end()) {
        it->second++;
        return;
    }

    RequestPtr req = std::make_shared<Request>(addr, 64, 0, 0);
    req->is_increment = true;
    req->metadata_addr = addr;
    req->arrived = curTick();

    MemCmd cmd = MemCmd::ReadReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    increment_map.insert(std::pair<uint64_t, int>(addr, 1));

    mem_side_port.sendPacket(pkt);
}

void
HuffmanEncryptionEngine::beginHuffman()
{
    // fetch first eight nodes from PQ and set
    // parent to current node index

    RequestPtr req = std::make_shared<Request>(0, 64, 0, 0);
    req->is_huffman = true;
    req->arrived = curTick();

    MemCmd cmd = MemCmd::ReadReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    // send packet for first child to memory
    mem_side_port.sendPacket(pkt);
}

void
HuffmanEncryptionEngine::handleHuffmanResponse(PacketPtr pkt)
{
    if (pkt->isRead()) {
        uint64_t *data = pkt->getPtr<uint64_t>();
       	children_count += getCounter(data);

	setRemoved(data);
	children_to_fetch--;

        // get the next node
	uint64_t next_addr = getAddr(data);

	if (children_to_fetch == 0) {
	    // We need to store the newly created
	    // node in place of this node


	    // reset children_to_fetch
	    children_to_fetch = 8;
	}
    }
}

void
HuffmanEncryptionEngine::clearInactive()
{
    if (state == NORMAL) {
        // If the mem_side_port (i.e., memory bandwidth) is not overly
        // occupied, try to clear the inactive queue
        if (mem_side_port.blockedPackets.size() < 8) { // TODO: parameterize?
            createClearRequest();
        }
    } else if (state == PQ_SORT) {
        // For now, let's do bubble sort (slow, but requires no additional
        // space)

        // Do nothing, process is started from createClearRequest
        // New frequencies will go to the now active PQ (other queue)
    }

    schedule(clearInactiveEvent, curTick() + mem_write_latency);
}

void
HuffmanEncryptionEngine::createSortRequest(uint64_t index)
{
    RequestPtr req = std::make_shared<Request>(index, 64, 0, 0);
    req->is_sort = true;

    req->arrived = curTick();

    MemCmd cmd = MemCmd::ReadReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    mem_side_port.sendPacket(pkt);
}

void
HuffmanEncryptionEngine::createClearRequest()
{
    if (clear_index == max_index) {
        state = PQ_SORT;
        clear_index = 0;

        createSortRequest(current_index);
        createSortRequest(compare_index);

        return;
    }

    RequestPtr req = std::make_shared<Request>(clear_index, 64, 0, 0);
    req->is_clear = true;
    req->arrived = curTick();

    MemCmd cmd = MemCmd::WriteReq;
    PacketPtr pkt = new Packet(req, cmd, 64);
    pkt->allocate();

    uint64_t *data = (uint64_t *) malloc(sizeof(uint64_t) * 8);
    setAddr(data, clear_index);
    setCounter(data, 0);
    setNext(data, clear_index == max_index - 1 ? 0 : clear_index + 1);

    pkt->setData(reinterpret_cast<const uint8_t *>(data));

    mem_side_port.sendPacket(pkt);

    clear_index++;
}

bool
HuffmanEncryptionEngine::handleRequest(PacketPtr pkt)
{
    if (state == HUFFMAN) {
        return false;
    }

    if (pkt->isWrite()) {
        incrementFrequency(pkt->getAddr());
    }

    return TimingEncryptionEngine::handleRequest(pkt);
}

bool
HuffmanEncryptionEngine::handleSortResponse(PacketPtr pkt)
{
    if (pkt->getAddr() == current_index) {
        current_data = pkt->getPtr<uint64_t>();

        delete pkt;
    } else {
        assert(pkt->getAddr() == compare_index);

        uint64_t *compare_data = pkt->getPtr<uint64_t>();

        if (getCounter(current_data) > getCounter(compare_data)) {
            // We need to swap these values (i.e., bubble sort)
            RequestPtr req = std::make_shared<Request>(compare_index, 64, 0, 0);
            req->arrived = curTick();

            MemCmd cmd = MemCmd::WriteReq;
            PacketPtr wpkt = new Packet(req, cmd, 64);
            wpkt->allocate();

            wpkt->setData(reinterpret_cast<const uint8_t *>(&current_data));
 
            mem_side_port.sendPacket(wpkt);

            current_data = compare_data;
        }

        if (compare_index == max_index) {
            // We need to flush the data at the current index (it has been
            // buffered, but may be stale in memory if we've made a swap)
            RequestPtr req = std::make_shared<Request>(current_index, 64, 0, 0);
            req->arrived = curTick();

            MemCmd cmd = MemCmd::WriteReq;
            PacketPtr wpkt = new Packet(req, cmd, 64);
            wpkt->allocate();

	    // set next ptr to being the next index
	    setNext(current_data, current_index + 1);

            wpkt->setData(reinterpret_cast<const uint8_t *>(current_data)); 
            mem_side_port.sendPacket(wpkt);

	    current_data = nullptr;

            current_index++;
            compare_index = current_index + 1;

            if (current_index == max_index) {
                // We are done sorting, last element
                // is sorted trivially
                state = HUFFMAN;

                beginHuffman();
            }
        } else {
            compare_index++;
            createSortRequest(compare_index);
        }
    }

    return true;
}

bool
HuffmanEncryptionEngine::handleResponse(PacketPtr pkt)
{
    if (pkt->req->is_clear) {
        delete pkt;

        return true;
    }

    if (pkt->req->is_sort) {
        if (pkt->isWrite()) {
            delete pkt;

            return true;
        }

        return handleSortResponse(pkt);
    }

    if (state == HUFFMAN && pkt->req->is_huffman) {
        handleHuffmanResponse(pkt);

	delete pkt;
	return true;
    } else if (pkt->req->is_increment && pkt->isRead()) {
        uint64_t map_idx = (pkt->getAddr() - start_addr) / PAGE_SIZE;
        assert(increment_map.find(map_idx) != increment_map.end());

        uint64_t *data = pkt->getPtr<uint64_t>();

        uint64_t ctr = getCounter(data);
        uint64_t addr = getAddr(data);

        RequestPtr req = std::make_shared<Request>(pkt->getAddr(), 64, 0, 0);
        req->is_increment = true;
        req->metadata_addr = pkt->getAddr();
        req->arrived = curTick();

        MemCmd cmd = MemCmd::WriteReq;
        PacketPtr wpkt = new Packet(req, cmd, 64);
        wpkt->allocate();

        setCounter(data, ctr + increment_map.find(map_idx)->second);
        wpkt->setData(reinterpret_cast<const uint8_t *>(data));
 
        mem_side_port.sendPacket(wpkt);

        increment_map.erase(map_idx);
        delete pkt;

        return true;
    } else if (pkt->req->is_increment && pkt->isWrite()) {
        // increment operation is done
        delete pkt;

        return true;
    } else if (pkt->req->is_clear) {
        delete pkt;

        return true;
    }

    return TimingEncryptionEngine::handleResponse(pkt);
}

}


gem5::HuffmanEncryptionEngine *
gem5::HuffmanEncryptionEngineParams::create() const
{
    return new gem5::HuffmanEncryptionEngine(this);
}
