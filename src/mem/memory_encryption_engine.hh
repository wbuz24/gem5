#ifndef __MEM_MEMORY_ENCRYPTION_ENGINE_HPP__
#define __MEM_MEMORY_ENCRYPTION_ENGINE_HPP__

#include <set>

#include "base/statistics.hh"
#include "mem/packet.hh"
#include "mem/port.hh"
#include "params/MemoryEncryptionEngine.hh"
#include "sim/sim_object.hh"

namespace gem5
{

namespace memory
{

class MemoryEncryptionEngine : public SimObject
{
  private:
    class CpuSidePort : public ResponsePort
    {
      private:
        MemoryEncryptionEngine *owner;
        bool needRetry;

      public:
        CpuSidePort
                (const std::string &name, MemoryEncryptionEngine *owner) :
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
        MemoryEncryptionEngine *owner;

      public:
        MemSidePort(const std::string &name, MemoryEncryptionEngine *owner) :
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
        MemoryEncryptionEngine *owner;

      public:
        MetadataRequestPort(const std::string &name,
                                  MemoryEncryptionEngine *owner) :
          MemSidePort(name, owner), owner(owner) {  };

        bool recvTimingResp(PacketPtr pkt) override;
        void recvTimingSnoopReq(PacketPtr pkt) override { return; }
        void recvReqRetry() override;
        void sendPacket(PacketPtr pkt);
    };

    class MetadataResponsePort : public CpuSidePort
    {
      private:
        MemoryEncryptionEngine *owner;

      public:
        MetadataResponsePort(const std::string &name,
                                  MemoryEncryptionEngine *owner) :
          CpuSidePort(name, owner), owner(owner) {  };

        bool recvTimingReq(PacketPtr pkt) override;
    };

    CpuSidePort cpu_side_port;
    MemSidePort mem_side_port;

    // Connects to metadata cache from above to send requests to the metadata
    // cache and receive its responses
    MetadataRequestPort metadata_request_port;
    // Connects to the metadata cache from below to receive requests from
    // metadata cache and misses send the responses from memory back to the
    // cache
    MetadataResponsePort metadata_response_port;

    bool secure;
    bool metadata_caches;
    bool strict_persistence;
    bool leaf_persistence;
    bool strict_outside_flex;

    double moveRatio;
    int active_requests;
    int max_active_requests;

    // HW/SW co-design
    bool enable_sched;
    bool enable_physalloc;

    int num_gb;
    uint64_t start_addr;

    bool needsRetry;

  public:
    inline static int flexibilitree_level = -1;

  private:
    uint64_t flexibilitree;
    uint64_t next_subtree;
    uint64_t flexibilitree_moving;
    std::vector<uint64_t> flexibilitree_candidates;
    std::set<uint64_t> dirty_counters;
    int flexibilitree_index = 0;
    int max_flex_index;

    std::vector<PacketPtr> request_queue;

    std::unordered_map<uint64_t, PacketPtr> pending_metadata_reads;
    std::unordered_map<uint64_t, PacketPtr> pending_metadata_writes;

    std::deque<PacketPtr> decryptQueue;
    EventFunctionWrapper verificationEvent;
    std::deque<PacketPtr> hashQueue;

    std::vector<uint64_t> integrity_levels;
    int data_level;
    int hash_level = 0;

    int mem_read_latency = 60000;
    int mem_write_latency = 150000;

    // On receiving a request...
    void handleRequest(PacketPtr pkt);
    void centralLoop();
    void createMetadata(uint64_t addr, int tree_level,
                bool is_read, bool is_wt);

    // On receiving a response...
    void handleHashResp(PacketPtr pkt);
    void handleTreeReadResp(PacketPtr pkt);
    void handleTreeWriteResp(PacketPtr pkt);

    void doneWithFront();

    // For flexibilitree
    bool in_flex_tree(uint64_t addr, int tree_level, bool track = true);
    bool _in_flex_tree(uint64_t addr, int tree_level);

  public:
    // So that this function can be called from pseudo-instruction
    void moveFlexTree(uint64_t physical_start_addr = 0xdeadbeef,
                bool context_switch = false);

    void count_contextswitches();

    void scheduleVerification() {
      if (!verificationEvent.scheduled()) {
        schedule(verificationEvent, curTick() + 1);
      }
    }

  //   // Description later
    std::unique_ptr<Packet> pendingDelete;

    uint64_t calculateAddress(uint64_t addr, int tree_level, bool counter);
    uint64_t calcHashAddr(PacketPtr pkt);
    void processVerificationEvent();

  public:
    MemoryEncryptionEngine(const MemoryEncryptionEngineParams *p);
    ~MemoryEncryptionEngine() { std::cout << "Hello world!" << std::endl; }

    Port &getPort(const std::string &if_name, PortID idx);

  // For statistics
  struct MEEStats : public statistics::Group
  {
      MEEStats(MemoryEncryptionEngine &m);
      void regStats() override;

      const MemoryEncryptionEngine &m;

      /** Number of times the flexibilitree root is hit. */
      statistics::Scalar flexibilitreeHits;

      /** Number of times the flexibilitree root is
        * missed at the flex-level. */
      statistics::Scalar flexibilitreeMisses;

      /** Number of times the flexibilitree changes. */
      statistics::Scalar flexibilitreeChanges;

      /** Number of times the flexibilitree stays the same. */
      statistics::Scalar flexibilitreeMaintains;

      /** Number of context switches from the OS. */
      statistics::Scalar contextSwitches;

      /** Number of subtree movements due to context switch. */
      statistics::Scalar movesFromCS;

      /** Number of subtree movements due to physical page allocator. */
      statistics::Scalar movesFromPA;

      /** Number of subtree movements due to hardware. */
      statistics::Scalar movesFromHW;




      /** HACK: trying to communicate ending
       * subtree addr from fast forward via stats file */
      statistics::Scalar subtreeAddr;
  };

  MEEStats stats;

};

} // namespace memory
} // namespace gem5

#endif // __MEM_MEMORY_ENCRYPTION_ENGINE_HPP__
