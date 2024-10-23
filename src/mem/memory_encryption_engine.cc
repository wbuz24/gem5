
#include "mem/memory_encryption_engine.hh"

#include "mem/packet.hh"

#define HASH_LEVEL 0
#define HASH_LEN 8
#define ROOT_LEVEL 1
#define BONSAI_COUNTER_ARITY 64
#define ARITY 8
#define BLOCK_SIZE 64
#define GB_IN_B (1ULL << 30)
namespace gem5
{

namespace memory
{

MemoryEncryptionEngine::MemoryEncryptionEngine
                            (const MemoryEncryptionEngineParams *params) :
    SimObject(*params),
    cpu_side_port(params->name + ".cpu_side", this),
    mem_side_port(params->name + ".mem_side", this),
    metadata_request_port(params->name + ".metadata_request_port", this),
    metadata_response_port(params->name + ".metadata_response_port", this),
    secure(params->secure), num_gb(params->num_gb),
    metadata_caches(params->metadata_caches),
    strict_persistence(params->strict_persist),
    leaf_persistence(params->leaf_persist),
    strict_outside_flex(true),
    max_flex_index(params->max_flex_index),
    verificationEvent([this] { processVerificationEvent(); }, name()),
    start_addr(params->start_addr), needsRetry(false),
    // hashEvent([this] { processHashEvent(); }, name()),
    // decrypt_available(0), hash_available(0), events_scheduled(false),
    enable_sched(params->enable_sched),
    enable_physalloc(params->enable_physalloc),
    moveRatio(params->move_ratio),
    active_requests(0),
    max_active_requests(params->max_active_requests),
    stats(*this)
{
    start_addr *= GB_IN_B;

    flexibilitree_level = params->flex_level;

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
    std::cout << "The flex tree is at level "
                            << flexibilitree_level << std::endl;
    std::cout << "The flex list is "
                            << max_flex_index << " items long" << std::endl;

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

    flexibilitree = integrity_levels[flexibilitree_level];

    if (params->prev_amnt != 0) {
        flexibilitree = params->prev_amnt;
    }

    stats.subtreeAddr = flexibilitree;
    next_subtree = flexibilitree;
    flexibilitree_moving = 0;

    for (int i = 0; i < max_flex_index; i++) {
        flexibilitree_candidates.push_back(0);
    }
};

Port&
MemoryEncryptionEngine::getPort(const std::string &if_name, PortID idx)
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
MemoryEncryptionEngine::createMetadata(
    uint64_t addr, int tree_level, bool is_read, bool is_wt = false)
{
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
    // pkt->setData("hello sam");

    if (is_read) {
        pending_metadata_reads.insert({addr, pkt});
    } else if (!is_wt) {
        pending_metadata_writes.insert({addr, pkt});

        // Determine if pkt needs write through
        if (strict_persistence) {
            pkt->req->needs_writethrough = true;
        } else if (leaf_persistence && tree_level == data_level - 1) {
            pkt->req->needs_writethrough = true;
        } else if (flexibilitree_level != -1 && flexibilitree_moving) {
            pkt->req->needs_writethrough = true;
        } else if (tree_level != hash_level && flexibilitree_level != -1) {
            pkt->req->needs_writethrough = true;

            if (tree_level <= flexibilitree_level &&
                                        in_flex_tree(addr, tree_level)) {
                pkt->req->needs_writethrough = false;

                if (tree_level == data_level - 1) {
                    // Set ``dirty bit'' for this counter
                    dirty_counters.emplace(pkt->req->metadata_addr);
                    // We need to write through on counters
                    pkt->req->needs_writethrough = true;
                }
            }
        }
    } else {
        pkt->req->req_type = Request::RequestType::MetadataWriteThrough;
    }

    // push_front() equivalent for request queue
    // (things behind depend on what is in front)
    if (tree_level != hash_level) {
        request_queue.insert(request_queue.begin(), pkt);
    }

    if (tree_level == hash_level) {
        mem_side_port.sendPacket(pkt);
    } else if (!is_wt) {
        metadata_request_port.sendPacket(pkt);
    } else {
        if (pkt->isRead()) {
            pkt->headerDelay += mem_read_latency;
        } else {
            assert(pkt->isWrite());
            pkt->headerDelay += mem_write_latency;
        }
        needsRetry = !mem_side_port.trySendPacket(pkt);
    }
}

void
MemoryEncryptionEngine::centralLoop()
{
    PacketPtr front = request_queue.front();

    // Ensure that hash will be fetched for the data
    if (!front->req->is_hash_fetched) {
        bool read_found =
                pending_metadata_reads.find(front->req->hash_addr)
                != pending_metadata_reads.end();
        bool write_found =
                pending_metadata_writes.find(front->req->hash_addr)
                != pending_metadata_writes.end();

        // Create and Request Hash
        if (front->isRead() && !read_found) {
            // Template: createMetadata(addr, tree_level, is_read)
            // createMetadata should create/send
            // packet + add to pending structures
            createMetadata(front->req->hash_addr, hash_level, true);
        } else if (front->isWrite() && !write_found) {
            createMetadata(front->req->hash_addr, hash_level, false);
        }
    } else if (front->isRead() && front->req->is_data_returned) {
        if (front->req->is_counter_verified && front->req->is_hash_verified) {
            doneWithFront();
            cpu_side_port.sendPacket(front);

            return;
        } else {
            // If the packet is a read with data that has been returned and the
            // hash has been fetched, verify that the hash of the data matches
            // the stored hash in the hash packet
            hashQueue.push_back(front);
        }
    }

    // Ensure that counter will be fetched for the data
    if (!front->req->is_counter_fetched) {
        bool read_found =
                pending_metadata_reads.find(front->req->parent_addr)
                != pending_metadata_reads.end();

        if (!read_found) {
            // This will create a read request for the counter
            // Once the counter is verified (either cache hit or via tree),
            // front will be marked counter_fetch
            assert(front->req->tree_level == data_level);
            createMetadata(front->req->parent_addr, data_level - 1, true);
        }
    } else if (front->isRead()) {
        // Read request where the counter has already been fetched
        // We should verify the counter
        if (!front->req->is_counter_verified && front->req->is_data_returned) {
            decryptQueue.push_back(front);
        }
    } else if (!front->req->is_counter_verified) {
        // Write request where counter has been fetched, but tree has not
        // necessarily been updated
        bool write_found =
                pending_metadata_writes.find(front->req->parent_addr)
                != pending_metadata_writes.end();

        if (!write_found) {
            // (Common case) We should create a
            // counter request to update the tree
            createMetadata(front->req->parent_addr, data_level - 1, false);
        } else {
            // (Corner case) ...do nothing?
        }
    } else if (front->req->is_hash_fetched) {
        // Write request where counter has been
        // fetched and the tree has been updated...
        if (!front->req->sent_to_mem) {
            mem_side_port.sendPacket(front);
        }

        if (front->req->is_data_returned) {
            doneWithFront();
        } else if (!front->needsResponse()) {
            doneWithFront();

            return;
        }
    }

    if (!hashQueue.empty() || !decryptQueue.empty()) {
        scheduleVerification();
    }

    // Reads should be sent to memory
    if (front->isRead()
            && !front->req->sent_to_mem && !front->req->is_metadata()) {
        assert(!front->req->is_metadata());
        mem_side_port.sendPacket(front);
    } else if (front->isWrite()
            && front->req->is_data_returned && !front->req->is_metadata()) {
        assert(!front->req->is_metadata());
        cpu_side_port.sendPacket(front);
    }
}

void
MemoryEncryptionEngine::doneWithFront()
{
    PacketPtr front = request_queue.front();

    assert(front->req->tree_level != hash_level);

    // pop front equivalent
    request_queue.erase(request_queue.begin());
    request_queue.shrink_to_fit();

    if (flexibilitree_level != -1 && front->isWrite()
                && front->req->metadata_addr == flexibilitree
                && flexibilitree_moving) {
        // We are done with persisting the subtree... is this enough to know?
        flexibilitree_moving--;
        if (flexibilitree_moving == 0) {
            flexibilitree = next_subtree;
            dirty_counters.clear();
        }
    }

    if (front->req->is_metadata()) {
        // This is a tree level that we have just verified...
        // Clear and delete
        if (front->isRead()) {
            pending_metadata_reads.erase(front->req->metadata_addr);
        } else if (front->req->req_type
                        != Request::RequestType::MetadataWriteThrough) {
            assert(front->isWrite());
            pending_metadata_writes.erase(front->req->metadata_addr);
        }

        delete front;
    } else {
        assert(active_requests > 0);
        active_requests--;

        cpu_side_port.trySendRetry();
    }

    if (!request_queue.empty()) {
        if (request_queue.front()->req->tree_level == data_level) {
            centralLoop();
        } else {
            PacketPtr next_front = request_queue.front();
            assert(next_front->req->tree_level != hash_level);
            if (next_front->isRead()) {
                handleTreeReadResp(next_front);
            } else {
                assert(next_front->isWrite());
                handleTreeWriteResp(next_front);
            }
        }
    }
}

void
MemoryEncryptionEngine::handleRequest(PacketPtr pkt)
{
    bool start_procedure = false;

    if (request_queue.empty()) {
        start_procedure = true;
    } else if (needsRetry) {
        assert(!request_queue.empty());
        assert(request_queue.front()->req->req_type
                            == Request::RequestType::MetadataWriteThrough);
        assert(!request_queue.front()->req->sent_to_mem);
        needsRetry = !mem_side_port.trySendPacket(request_queue.front());
    } else if (!mem_side_port.blockedPackets.empty()) {
        PacketPtr blocked = mem_side_port.blockedPackets.front();
        if (mem_side_port.trySendPacket(blocked)) {
            mem_side_port.blockedPackets.pop_front();
        }
    }

    pkt->req->arrived = curTick();
    pkt->req->tree_level = data_level;
    pkt->req->hash_addr = calcHashAddr(pkt);
    pkt->req->parent_addr = calculateAddress(pkt->getAddr(), data_level, true);
    if (pkt->isRead()) {
        pkt->req->req_type = Request::DataRead;
    } else {
        assert(pkt->isWrite());
        pkt->req->req_type = Request::DataWrite;
    }

    assert(pkt->req->tree_level != hash_level);
    request_queue.push_back(pkt);

    if (start_procedure) {
        centralLoop();
    }
}

void
MemoryEncryptionEngine::handleHashResp(PacketPtr pkt)
{
    // Mark all pending requests with this pkt as hash parent as hash fetched
    for (int i = 0; i < request_queue.size(); i++) {
        if (request_queue[i]->req->hash_addr == pkt->req->metadata_addr) {
            if (pkt->isRead() && request_queue[i]->isRead()) {
                request_queue[i]->req->is_hash_fetched = true;
            } else if (pkt->isWrite() && request_queue[i]->isWrite()) {
                request_queue[i]->req->is_hash_fetched = true;
            }
        }
    }

    PacketPtr front = request_queue.front();

    // Only do further processing if the data is
    // in the front (i.e., no more dependencies)
    if (front->req->is_hash_fetched && front->req->tree_level == data_level) {
        if (front->isRead() && !front->req->is_hash_verified) {
            hashQueue.push_back(front);

            scheduleVerification();
        } else {
            assert(front->isWrite());

            // We have a write, we are done if the
            // counter has already been verified (written)
            if (front->req->is_counter_verified) {
                doneWithFront();
                mem_side_port.sendPacket(front);
            }
        }
    }

    // Safe to delete and clean-up
    if (pkt->isRead()) {
        pending_metadata_reads.erase(pkt->req->metadata_addr);
    } else {
        assert(pkt->isWrite());
        pending_metadata_writes.erase(pkt->req->metadata_addr);
    }

    delete pkt;
}

void
MemoryEncryptionEngine::handleTreeReadResp(PacketPtr pkt)
{
    // Check if we can trust this value
    if (!pkt->req->metadata_cache_miss || pkt->req->is_counter_fetched
                    || pkt->req->tree_level == 1
                    || (flexibilitree_level != -1
                    && pkt->req->metadata_addr == flexibilitree)) {
        for (int i = 0; i < request_queue.size(); i++) {
            if (request_queue[i]->req->parent_addr
                    == pkt->req->metadata_addr) {
                request_queue[i]->req->is_counter_fetched = true;
            }
        }

        // Remove ourselves from the request queue
        // We are the front because we don't depend on anything
        assert(request_queue.front() == pkt);
        doneWithFront();
    } else {
        // Tree node is not yet trusted... must request parent to verify
        pkt->req->parent_addr =
                    calculateAddress(pkt->req->metadata_addr,
                    pkt->req->tree_level, false);
        bool read_found =
                    pending_metadata_reads.find(pkt->req->parent_addr)
                    != pending_metadata_reads.end();

        if (!read_found) {
            // This will create a read request for the counter
            // Once the counter is verified (either cache hit or via tree),
            // front will be marked counter_fetch
            createMetadata(pkt->req->parent_addr,
                            pkt->req->tree_level - 1, true);
        }
    }
}

void
MemoryEncryptionEngine::handleTreeWriteResp(PacketPtr pkt)
{
    // Handle case where pkt might still need a write to memory
    if (pkt->req->needs_writethrough) {
        assert(!pkt->req->metadata_cache_miss);

        createMetadata(pkt->req->metadata_addr,
                            pkt->req->tree_level, false, true);

        return;
    }

    if (pkt->req->req_type == Request::RequestType::MetadataWriteThrough) {
        assert(request_queue.front() == pkt);

        int found_index = -1;

        for (int i = 1; i < request_queue.size(); i++) {
            if (request_queue[i]->req->metadata_addr
                                    == pkt->req->metadata_addr) {
                found_index = i;
                break;
            }
        }

        assert(found_index != -1);
        assert(request_queue[found_index]->req->metadata_addr
                                        == pkt->req->metadata_addr);
        assert(request_queue[found_index]->req->needs_writethrough);

        request_queue[found_index]->req->needs_writethrough = false;

        // Remove ourselves from the request queue
        // We are the front because we don't depend on anything
        assert(request_queue.front() == pkt);
        doneWithFront();
    } else if (pkt->req->tree_level == 1 || pkt->req->is_counter_verified
                || (flexibilitree_level != -1
                && pkt->req->metadata_addr == flexibilitree)) {
        for (int i = 0; i < request_queue.size(); i++) {
            if (request_queue[i]->req->parent_addr ==
                    pkt->req->metadata_addr && request_queue[i]->isWrite()) {
                // Note, with reads, we use verified to notify
                // that the write has occurred
                request_queue[i]->req->is_counter_verified = true;
            } else if (request_queue[i]->req->parent_addr
                    == pkt->req->metadata_addr) {
                assert(request_queue[i]->isRead());
                request_queue[i]->req->is_counter_fetched = true;
            }
        }

        // Remove ourselves from the request queue
        // We are the front because we don't depend on anything
        assert(request_queue.front() == pkt);
        doneWithFront();
    } else {
        // Tree node is not yet trusted... must request parent to verify
        pkt->req->parent_addr =
                calculateAddress(pkt->req->metadata_addr,
                pkt->req->tree_level, false);
        bool write_found = pending_metadata_writes.find(pkt->req->parent_addr)
                    != pending_metadata_writes.end();

        if (!write_found) {
            // This will create a write request for the counter
            // Once the counter is verified (either cache hit or via tree),
            // front will be marked counter_fetch
            createMetadata(pkt->req->parent_addr,
                    pkt->req->tree_level - 1, false);
        }
    }
}

void
MemoryEncryptionEngine::processVerificationEvent()
{
    while (!hashQueue.empty()) {
        PacketPtr front = hashQueue.front();
        hashQueue.pop_front();

        assert(front->req->tree_level == data_level);

        if (!front->req->is_hash_verified) {
            front->req->is_hash_verified = true;

            if (front->isRead()) {
                if (front->req->is_counter_verified
                        && front == request_queue.front()
                        && front->req->is_data_returned) {
                    doneWithFront();
                    cpu_side_port.sendPacket(front);
                }
            } else {
                assert(front->isWrite());
            }
        }
    }

    while (!decryptQueue.empty()) {
        PacketPtr front = decryptQueue.front();
        decryptQueue.pop_front();

        assert(front->req->tree_level == data_level);
        assert(front->isRead());

        if (!front->req->is_counter_verified) {
            // Note, is_counter_verified is used in reads to say that
            // it is safe to send the packet on-chip... in writes it is
            // used to say that the parent has been successfully written
            front->req->is_counter_verified = true;

            if (front->isRead()) {
                if (front == request_queue.front()
                            && front->req->is_data_returned) {
                    if (front->req->is_hash_verified) {
                        doneWithFront();
                        cpu_side_port.sendPacket(front);
                    }
                }
            } else {
                // We should never be ``verifying'' the parent of a write
                assert(false);
            }
        }
    }
}

uint64_t
MemoryEncryptionEngine::calculateAddress(
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
    assert(parent_addr > start_addr + (num_gb * GB_IN_B));
    assert(parent_addr < start_addr + (2 * num_gb * (GB_IN_B)));
    return parent_addr;
}

uint64_t
MemoryEncryptionEngine::calcHashAddr(PacketPtr pkt)
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
MemoryEncryptionEngine::in_flex_tree(uint64_t addr, int tree_level, bool track)
{
    if (tree_level == flexibilitree_level) {
        bool to_return = false;

        if (addr == flexibilitree) {
            if (track) {
                stats.flexibilitreeHits++;
            }
            to_return = true;
        } else {
            if (track) {
                stats.flexibilitreeMisses++;
            }
        }

        // HW implementation: Add this as a possible flex tree
        if (track &&
                flexibilitree_index < flexibilitree_candidates.size()) {
            flexibilitree_candidates[flexibilitree_index] = addr;
            flexibilitree_index++;

            if (flexibilitree_index == max_flex_index) {
                moveFlexTree();
            }
        }

        return to_return;
    } else if (tree_level < flexibilitree_level) {
        return false;
    }

    return in_flex_tree(
            calculateAddress(addr, tree_level, false), tree_level - 1, track);
}

bool
MemoryEncryptionEngine::_in_flex_tree(uint64_t addr, int tree_level)
{
    if (tree_level == flexibilitree_level) {
        if (addr == flexibilitree) {
            return true;
        } else {
            return false;
        }
    }

    return _in_flex_tree(
            calculateAddress(addr, tree_level, false), tree_level - 1);
}

void
MemoryEncryptionEngine::moveFlexTree(
    uint64_t physical_start_addr,
    bool context_switch
)
{
    if (flexibilitree_level == -1) {
        return;
    } else if (physical_start_addr != 0xdeadbeef) {
            return;
    }

    std::unordered_map<uint64_t, int> candidate_map;
    uint64_t most_frequented_addr = flexibilitree;
    int max_accesses = 0;

    // Determine most common candidate
    for (int i = 0; i < max_flex_index; i++) {
        if (candidate_map.find(flexibilitree_candidates[i])
                                            == candidate_map.end()) {
            candidate_map.emplace(flexibilitree_candidates[i], 1);
        } else {
            candidate_map[flexibilitree_candidates[i]]++;
        }

        if (candidate_map[flexibilitree_candidates[i]] > max_accesses) {
            most_frequented_addr = flexibilitree_candidates[i];
            max_accesses = candidate_map[flexibilitree_candidates[i]];
        }
    }

    flexibilitree_index = 0;

    // Prepare all necessary fields to compute the move
    uint64_t flex_block_num = (flexibilitree -
                        integrity_levels[flexibilitree_level]) / BLOCK_SIZE;
    uint64_t num_blocks;
    if (flexibilitree_level == 1) {
        num_blocks = 1;
    } else {
        num_blocks = (integrity_levels[flexibilitree_level - 1] -
                        integrity_levels[flexibilitree_level]) / BLOCK_SIZE;
    }
    uint64_t num_counters = (integrity_levels[data_level - 2] -
                        integrity_levels[data_level - 1]) / BLOCK_SIZE;
    uint64_t starting_counter_index = flex_block_num *
                        (num_counters / num_blocks);
    uint64_t ending_counter_index = (flex_block_num + 1) *
                        (num_counters / num_blocks);

    // Check if we got hint from OS
    if (physical_start_addr != 0xdeadbeef) {
        if ((enable_physalloc && !context_switch)
                            || (enable_sched && context_switch)) {
            // We got a hint! Use the hint!

            uint64_t region_size = (GB_IN_B * num_gb) / num_blocks;
            uint64_t subtree_index = physical_start_addr / region_size;

            most_frequented_addr = integrity_levels[flexibilitree_level]
                            + (subtree_index * BLOCK_SIZE);
        }
    }

    // Stat counting
    if (most_frequented_addr == flexibilitree) {
        stats.flexibilitreeMaintains++;
        return;
    } else if (moveRatio > 0
                && ((1.0 * max_accesses) / max_flex_index) < moveRatio) {
        stats.flexibilitreeMaintains++;
        return;
    }

    stats.flexibilitreeChanges++;
    next_subtree = most_frequented_addr;
    stats.subtreeAddr = next_subtree;

    if (context_switch) {
        stats.movesFromCS++;
    } else if (physical_start_addr != 0xdeadbeef) {
        stats.movesFromPA++;
    } else {
        stats.movesFromHW++;
    }

    for (int i = starting_counter_index; i < ending_counter_index; i++) {
        uint64_t addr = (i * BLOCK_SIZE) + integrity_levels[data_level - 1];
        if (_in_flex_tree(addr, data_level - 1)
                        && dirty_counters.find(addr) != dirty_counters.end()) {
            flexibilitree_moving++;
            createMetadata(addr, data_level - 1, false);
        }
    }

    if (flexibilitree_moving == 0) {
        flexibilitree = next_subtree;
    }
}

void
MemoryEncryptionEngine::count_contextswitches()
{
    stats.contextSwitches++;
}

AddrRangeList
MemoryEncryptionEngine::CpuSidePort::getAddrRanges() const
{
    return owner->mem_side_port.getAddrRanges();
}

void
MemoryEncryptionEngine::CpuSidePort::trySendRetry()
{
    if (needRetry) {
        // Only send a retry if the port is now completely free
        sendRetryReq();

        if (blockedPackets.empty()) {
            needRetry = false;
        }
    }
}

void
MemoryEncryptionEngine::CpuSidePort::sendPacket(PacketPtr pkt)
{
    if (!sendTimingResp(pkt)) {
        blockedPackets.push_back(pkt);
    }
}

void
MemoryEncryptionEngine::CpuSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->mem_side_port.sendFunctional(pkt);
}

bool
MemoryEncryptionEngine::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    if (owner->active_requests == owner->max_active_requests) {
        needRetry = true;
        return false;
    }

    owner->active_requests++;

    assert(pkt->getAddr() >= owner->start_addr);
    assert(pkt->getAddr() < owner->start_addr + (owner->num_gb * GB_IN_B));

    if (owner->secure && (pkt->isRead() || pkt->isWrite())) {
        owner->handleRequest(pkt);
    } else {
        owner->mem_side_port.sendPacket(pkt);
    }

    return true;
}

bool
MemoryEncryptionEngine::MetadataResponsePort::recvTimingReq(PacketPtr pkt)
{
    // We have missed in the metadata cache
    pkt->req->metadata_cache_miss = true;

    // Clean up requisite fields -- for non-Simple Cache
    if (pkt->isEviction() && !pkt->isCleanEviction()) {
        assert(pkt->isWrite());
        pkt->req->metadata_addr = pkt->getAddr();
        pkt->req->req_type = Request::RequestType::MetadataWrite;
    }

    if (pkt->isRead() || pkt->isWrite()) {
        owner->mem_side_port.sendPacket(pkt);
    } else if (pkt->needsResponse()) {
        assert(pkt->needsResponse());
        // Handle invalidation requests, etc... -- for non-Simple Cache
        pkt->makeResponse();
        owner->metadata_response_port.sendPacket(pkt);
    }

    return true;
}

void
MemoryEncryptionEngine::CpuSidePort::recvRespRetry()
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

void
MemoryEncryptionEngine::MemSidePort::sendPacket(PacketPtr pkt)
{
    if (pkt->isRead()) {
        pkt->headerDelay += owner->mem_read_latency;
    } else {
        pkt->headerDelay += owner->mem_write_latency;
    }

    if (!sendTimingReq(pkt)) {
        blockedPackets.push_back(pkt);
    } else {
        pkt->req->sent_to_mem = true;

        if (pkt->req->needs_writethrough) {
            pkt->req->needs_writethrough = false;
        }
    }
}

bool
MemoryEncryptionEngine::MemSidePort::trySendPacket(PacketPtr pkt)
{
    if (sendTimingReq(pkt)) {
        if (strcmp(name().c_str(), "system.mees.mem_side") == 0) {
            pkt->req->sent_to_mem = true;
        } else if (strcmp(name().c_str(), "system.mee.mem_side") == 0) {
            pkt->req->sent_to_mem = true;
        }

        return true;
    }

    return false;
}

void
MemoryEncryptionEngine::MetadataRequestPort::sendPacket(PacketPtr pkt)
{
    assert(pkt->req->req_type != Request::RequestType::MetadataWriteThrough);
    assert(pkt->req->metadata_addr
                            > owner->start_addr + (GB_IN_B * owner->num_gb));
    if (!sendTimingReq(pkt)) {
        blockedPackets.push_back(pkt);
    }
}

bool
MemoryEncryptionEngine::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    if (!owner->secure) {
        owner->cpu_side_port.sendPacket(pkt);
        return true;
    }

    if (pkt->req->req_type == Request::RequestType::MetadataWriteThrough) {
        owner->metadata_request_port.recvTimingResp(pkt);
    } else if (pkt->req->tree_level == owner->hash_level) {
        owner->handleHashResp(pkt);
    } else if (pkt->req->is_metadata()) {
        owner->metadata_response_port.sendPacket(pkt);
    } else if (pkt->isRead() || pkt->isWrite()) {
        pkt->req->is_data_returned = true;

        if (owner->request_queue.size() == 0) {
            assert(pkt->isWrite());
            owner->cpu_side_port.sendPacket(pkt);
        } else if (owner->request_queue.front() == pkt) {
            // Handles case where data is returned after counter and hash
            owner->centralLoop();
        } else if (pkt->isWrite()) {
            assert(std::find(owner->request_queue.begin(),
                        owner->request_queue.end(), pkt)
                        == owner->request_queue.end());
            owner->cpu_side_port.sendPacket(pkt);
        }
    }

    return true;
}

bool
MemoryEncryptionEngine::MetadataRequestPort::recvTimingResp(PacketPtr pkt)
{
    pkt->req->is_data_returned = true;

    if (pkt->req->tree_level == owner->hash_level) {
        owner->handleHashResp(pkt);
    } else if (pkt->req->is_metadata()) {
        if (pkt->isRead()) {
            owner->handleTreeReadResp(pkt);
        } else {
            assert(pkt->isWrite());
            owner->handleTreeWriteResp(pkt);
        }
    }

    return true;
}

void
MemoryEncryptionEngine::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();
    blockedPackets.pop_front();

    // Try to resend it. It's possible that it fails again.
    if (pkt->isResponse()) {
        sendPacket(pkt);
    }
}

void
MemoryEncryptionEngine::MetadataRequestPort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    if (blockedPackets.empty()) {
        return;
    }

    // Grab the blocked packet.
    PacketPtr pkt = blockedPackets.front();
    while (!blockedPackets.empty()) {
        assert(pkt->req->metadata_addr > owner->start_addr +
                            (GB_IN_B * owner->num_gb));

        if (pkt->isResponse()) {
            blockedPackets.pop_front();
        } else if (trySendPacket(pkt)) {
            blockedPackets.pop_front();
            pkt = blockedPackets.front();
        } else {
            return;
        }
    }
}

void
MemoryEncryptionEngine::MemSidePort::recvRangeChange()
{
    if (strcmp(name().c_str(), "system.mees.metadata_request_port") == 0) {
        owner->cpu_side_port.sendRangeChange();
    } else if (strcmp(name().c_str(),
                    "system.mee.metadata_request_port") == 0) {
        owner->cpu_side_port.sendRangeChange();
    } else {
        owner->metadata_response_port.sendRangeChange();
    }
}

MemoryEncryptionEngine::MEEStats::MEEStats(MemoryEncryptionEngine &mee) :
    statistics::Group(&mee), m(mee),

    ADD_STAT(flexibilitreeHits, statistics::units::Count::get(),
             "times where we stopped early because we hit the flexibilitree"),
    ADD_STAT(flexibilitreeMisses, statistics::units::Count::get(),
             "times where we missed the flexibilitree"),
    ADD_STAT(flexibilitreeChanges, statistics::units::Count::get(),
             "times the flexibilitree moved (expensive op)"),
    ADD_STAT(flexibilitreeMaintains, statistics::units::Count::get(),
             "times the flexibilitree stays the same"),
    ADD_STAT(contextSwitches, statistics::units::Count::get(),
             "number of OS context switches"),
    ADD_STAT(subtreeAddr, statistics::units::Count::get(),
             "final addr of subtree")
{
}

void
MemoryEncryptionEngine::MEEStats::regStats()
{
    using namespace statistics;

    statistics::Group::regStats();
}

} // namespace memory
} // namespace gem5

gem5::memory::MemoryEncryptionEngine*
gem5::MemoryEncryptionEngineParams::create() const
{
    return new gem5::memory::MemoryEncryptionEngine(this);
}
