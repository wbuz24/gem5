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
 * Declares a the leaf crash-recovery Memory Encryption Engine.
 */

#ifndef __MEM_MEE_LEAF_HH__
#define __MEM_MEE_LEAF_HH__

#include <set>

#include "base/statistics.hh"
#include "mem/mee/base.hh"
#include "params/AMNT.hh"

namespace gem5 {


class AMNT : public BaseMemoryEncryptionEngine
{
  private:
    bool needsWritethrough(uint64_t addr, int tree_level) {
        if (subtree_moving > 0) {
            return true;
        } else if (!in_subtree(addr, tree_level,
                tree_level == data_level - 1)) {
            return true;
        } else if (tree_level == data_level - 1) {
            return true;
        } else {
            return false;
        }
    };

    bool doneWriting(PacketPtr pkt) {
        if (std::find(subtree_roots.begin(), subtree_roots.end(),
                          pkt->req->metadata_addr) != subtree_roots.end()) {
            return subtree_moving == 0;
        }

        return BaseMemoryEncryptionEngine::doneWriting(pkt);
    };

    bool trusted(PacketPtr pkt) {
        if (std::find(subtree_roots.begin(), subtree_roots.end(),
                        pkt->req->metadata_addr)  != subtree_roots.end()) {
            return true;
       }

        return BaseMemoryEncryptionEngine::trusted(pkt);
    };

    bool handleResponse(PacketPtr pkt) {
        if (subtree_moving > 0 && pkt->isWrite()) {
            if (pkt->req->tree_level == subtree_level
                    && std::find(subtree_roots.begin(), subtree_roots.end(),
                    pkt->getAddr()) != subtree_roots.end()) {
                subtree_moving--;
            }

            if (subtree_moving == 0) {
                assert(!next_subtrees.empty());

                subtree_roots = next_subtrees;
                next_subtrees.clear();
                dirty_counters.clear();
            }
        }

        return BaseMemoryEncryptionEngine::handleResponse(pkt);
    };


    //////////////////////////////////
    ////// AMNT SPECIFIC FIELDS //////
    //////////////////////////////////

    // Fixed constant, determined at production time based on QoS
    // requirements -- closer to root means higher ST rates but
    // longer wait times on system restoration
    int subtree_level;
    int num_subtrees;

    // Root of the subtree, refers to the address (64b NV register)
    std::vector<uint64_t> subtree_roots;

    // When a different subtree is determined to be hot, its
    // address is tracked in a temporary register (can be volatile)
    std::vector<uint64_t> next_subtrees;

    // Observation interval length to track next hot subtree
    int max_st_index;
    // Current index in tracking array (pointer to which register
    // to use next)
    int subtree_tracking_index;

    // Field used to track hot subtree across current interval
    std::vector<uint64_t> subtree_candidates;

    // Field used to determine whether or not a counter in the
    // current subtree has been dirtied (so we know if it needs
    // to be written through on ST movement)
    std::set<uint64_t> dirty_counters;

    // Used to determine how many more counters need to be written
    // through before we can start doing relaxed persistence in the
    // next subtree
    int subtree_moving;

    // Threshold of nodes observed to determine that a subtree is ``hot''
    double moveRatio;

    /////////////////////////////////////
    ////// AMNT SPECIFIC FUNCTIONS //////
    ////////////////////////////////////

    bool isSubtreeRoot(uint64_t addr) {
        for (int i = 0; i < num_subtrees; i++) {
            if (addr == subtree_roots[i]) {
                return true;
            }
        }

        return false;
    };

  public:
    AMNT(const AMNTParams *p);

    // Function and helper function to determine whether or not
    // a BMT node falls in the current subtree
    bool in_subtree(uint64_t addr, int tree_level, bool track = true);
    bool _in_subtree(uint64_t addr, int tree_level);

    // Function to begin non-blocking subtree movement procedure
    void moveSubtree();


  struct AMNTStats : public statistics::Group
  {
      AMNTStats(AMNT &m);
      void regStats() override;

      const AMNT &m;

      /** Number of times the flexibilitree root is hit. */
      statistics::Scalar subtreeHits;

      /** Number of times the flexibilitree root is
        * missed at the flex-level. */
      statistics::Scalar subtreeMisses;

      /** Number of times the flexibilitree changes. */
      statistics::Scalar subtreeChanges;

      /** Number of times the flexibilitree stays the same. */
      statistics::Scalar subtreeMaintains;
  };

  AMNTStats stats;

};

}

#endif //__MEM_MEE_LEAF_HH__
