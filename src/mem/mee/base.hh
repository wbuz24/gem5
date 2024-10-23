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
 * Declares a basic Memory Encryption Engine interface BaseMEE.
 */

#ifndef __MEM_MEE_BASE_HH__
#define __MEM_MEE_BASE_HH__

#define GB_IN_B (1ULL << 30)
#define BLOCK_SIZE 64
#define ARITY 8
#define BONSAI_COUNTER_ARITY 64
#define HASH_LEN 8

#include <set>

#include "mem/port.hh"
#include "sim/sim_object.hh"

namespace gem5 {

struct BaseMemoryEncryptionEngineParams;

class BaseMemoryEncryptionEngine : public SimObject
{
  private:
    class CpuSidePort : public ResponsePort
    {
      private:
        BaseMemoryEncryptionEngine *owner;
        bool needRetry;

      public:
        CpuSidePort
                (const std::string &name, BaseMemoryEncryptionEngine *owner) :
            ResponsePort(name, owner), owner(owner), needRetry(false)
          {  };

        AddrRangeList getAddrRanges() const override;
        void trySendRetry();
        void sendPacket(PacketPtr pkt);

      protected:
        Tick recvAtomic(PacketPtr pkt) override {
              return owner->mem_side_port.sendAtomic(pkt); };
        void recvFunctional(PacketPtr pkt) override;

        bool recvTimingReq(PacketPtr pkt) override;
        bool recvTimingSnoopResp(PacketPtr pkt) override {
          return owner->mem_side_port.sendTimingSnoopResp(pkt);
        }

        void recvRespRetry() override;

      public:
        std::list<PacketPtr> blockedPackets;
    };

    class MemSidePort : public RequestPort
    {
      private:
        BaseMemoryEncryptionEngine *owner;

      public:
        MemSidePort(const std::string &name,
                BaseMemoryEncryptionEngine *owner) :
            RequestPort(name, owner), owner(owner)
          {  };

        bool isSnooping() const override { return true; }
        void sendPacket(PacketPtr pkt);
        bool trySendPacket(PacketPtr pkt);

      protected:
        Tick recvAtomicSnoop(PacketPtr pkt) override {
          return owner->cpu_side_port.sendAtomicSnoop(pkt);
        };
        void recvFunctionalSnoop(PacketPtr pkt) override {
          owner->cpu_side_port.sendTimingSnoopReq(pkt);
        }

        bool recvTimingResp(PacketPtr pkt) override;
        void recvTimingSnoopReq(PacketPtr pkt) override {
          owner->cpu_side_port.sendTimingSnoopReq(pkt);
        }
        void recvReqRetry() override;
        void recvRangeChange() override;

        void recvRetrySnoopResp() override {
          owner->cpu_side_port.sendRetrySnoopResp();
        }

      public:
        std::list<PacketPtr> blockedPackets;
    };

    class MetadataRequestPort : public MemSidePort
    {
      private:
        BaseMemoryEncryptionEngine *owner;

      public:
        MetadataRequestPort(const std::string &name,
                                  BaseMemoryEncryptionEngine *owner) :
          MemSidePort(name, owner), owner(owner) {  };

        bool recvTimingResp(PacketPtr pkt) override;
        void recvTimingSnoopReq(PacketPtr pkt) override { return; }
        void recvReqRetry() override;
        void sendPacket(PacketPtr pkt);

        void recvRangeChange() override;
        bool trySendPacket(PacketPtr pkt);
    };

    class MetadataResponsePort : public CpuSidePort
    {
      private:
        BaseMemoryEncryptionEngine *owner;

      public:
        MetadataResponsePort(const std::string &name,
                                  BaseMemoryEncryptionEngine *owner) :
          CpuSidePort(name, owner), owner(owner) {  };

        bool recvTimingReq(PacketPtr pkt) override;
    };

  public:
    CpuSidePort cpu_side_port;
    MemSidePort mem_side_port;

    // Connects to metadata cache from above to send requests to the metadata
    // cache and receive its responses
    MetadataRequestPort metadata_request_port;

    // Connects to the metadata cache from below to receive requests from
    // metadata cache and misses send the responses from memory back to the
    // cache
    MetadataResponsePort metadata_response_port;


    ////////////////////////////////////////
    /////// Encryption Engine fields ///////
    ////////////////////////////////////////

    // Tree construction helpers and fields
    uint64_t start_addr;
    int num_gb;

    std::vector<uint64_t> integrity_levels;
    int data_level;
    const int hash_level = 0;

    // Enforce maximum data parallelism - there will be many additional memory
    // requests created as a result of metadata, so we enforce no more than 64
    // data requests should come in at a time
    // const int max_active_requests = 32;
    const int max_active_reads = 4;
    const int max_active_writes = 8;

    // Timing constants
    const int mem_read_latency = 305000; // Izraelevitz, et. al
    const int mem_write_latency = 391000; // Hirofuchi, et. al
    const int aes_latency = 80000;
    const int hmac_latency = 2000;

    int far_memory_factor;

    // Central batching indices (addr, PktPtr)
    // the protocols for determining whether
    // a value belongs in these indices is
    // as follows:
    //      (1) a node that has not yet
    //          been written to memory
    //          should be in the
    //          pending_metadata_writes
    //      (2) if a node is in the
    //          pending_metadata_writes
    //          object, then it should
    //          not be in the
    //          pending_metadata_reads
    //          object (can use trusted
    //          value from the write)
    //      (3) a node should remain in
    //          pending_metadata_reads
    //          until it is verified
    //   --> this means that there
    //       should ~never~ be a case
    //       where a node is trying to
    //       be read and written at the
    //       same time... but it is
    //       subject to a race condition
    //       due to asymmetric timing of
    //       reads and writes in memory
    //   --> in BaseMEE, writes are not
    //       batched (but some papers
    //       do batch writes)
    std::unordered_map<uint64_t, PacketPtr> pending_metadata_reads;
    std::unordered_map<uint64_t, PacketPtr> pending_metadata_writes;

    std::set<PacketPtr> active_requests;

  public:
    ////////////////////////////////////////////
    /////// Encryption Engine Functions ////////
    ////////////////////////////////////////////

    BaseMemoryEncryptionEngine(const BaseMemoryEncryptionEngineParams *p);

    Port &getPort(const std::string &if_name, PortID idx);

    // Determines whether the metadata being created
    // needs to be written through to memory
    //     * note: in BaseMEE, only HMACs need to be
    //             written through, and they are not
    //             cached which makes this trivially
    //             true
    virtual bool needsWritethrough(uint64_t addr, int tree_level);

    // Determines whether the write can stop (i.e.,
    // has the leaf-to-root update completed)
    virtual bool doneWriting(PacketPtr pkt);

    // Determines whether the read can stop (i.e.,
    // a cache hit, the parent is validated, or
    // the true root is reached)
    virtual bool trusted(PacketPtr pkt);

    virtual void evictionHandling(PacketPtr pkt);

    // Create the appropriate metadata field given
    // the input - in most cases, this is done
    // with the parent of a particular node to help
    // verify it
    void createMetadata(uint64_t addr, int tree_level,
        bool is_read, PacketPtr child, bool is_wt = false);

    // Compute the address of the parent BMT node for
    // a given address (tree level could be inferred,
    // but we parameterize it for simplicity and for
    // readability)
    virtual uint64_t calculateAddress(PacketPtr pkt) {
      return calculateAddress(pkt->getAddr(), pkt->req->tree_level,
        pkt->req->tree_level == data_level);
    }
    uint64_t calculateAddress(uint64_t addr, int tree_level, bool counter);
    uint64_t calcHashAddr(PacketPtr pkt);

    // Handle incoming data - all data (R/W) should
    // have a request created for a counter read and
    // an HMAC read/write (depending on request type)
    //    * note: HMACs are the hash of the decrypted
    //            data
    //    * note: counters are always read first (in
    //            order to decrypt or to fetch-and-
    //            increment on R/W respectively)
    bool handleRequest(PacketPtr pkt);


    // Handle data/metadata responses
    //     * metadata is handled in the appropriate
    //       helper function
    //     * data must be verified, so we merely
    //       forward it along at this point
    //          --> in this implementation, we do
    //              not compare the decrypted data
    //              against the HMAC after fetch..
    //              for simplicity, we add
    //              encryption and HMAC latency to
    //              memory header latency in the
    //              data
    virtual bool handleResponse(PacketPtr pkt);
};

};

#endif // __MEM_MEE_BASE_HH__
