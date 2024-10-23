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

#include "mem/mee/amnt.hh"

#include <cmath>

namespace gem5 {

AMNT::AMNT(const AMNTParams *p) :
    BaseMemoryEncryptionEngine(p),
    subtree_level(p->subtree_level),
    num_subtrees(p->num_subtrees),
    max_st_index(p->record_length),
    subtree_tracking_index(0),
    subtree_moving(0),
    moveRatio(p->movement_ratio),
    stats(*this)
{
    for (int i = 0; i < (num_subtrees * 64); i += 64) {
        subtree_roots.push_back(integrity_levels[subtree_level] + i);
    }

    for (int i = 0; i < max_st_index; i++) {
        subtree_candidates.push_back(0);
    }
}

bool
AMNT::in_subtree(uint64_t addr, int tree_level, bool track)
{
    if (tree_level == subtree_level) {
        bool to_return = false;

        if (std::find(subtree_roots.begin(), subtree_roots.end(), addr)
                       != subtree_roots.end()) {
            if (track) {
                stats.subtreeHits++;
           }
        }

        if (!to_return) {
            if (track) {
                stats.subtreeMisses++;
            }
        }

        // HW implementation: Add this as a possible flex tree
        if (track &&
                subtree_tracking_index < subtree_candidates.size()) {
            subtree_candidates[subtree_tracking_index] = addr;
            subtree_tracking_index++;

            if (subtree_tracking_index == max_st_index) {
                moveSubtree();
            }
        }

        return to_return;
    } else if (tree_level < subtree_level) {
        return false;
    }

    bool r = in_subtree(
            calculateAddress(addr, tree_level, false), tree_level - 1, track);

    if (tree_level == data_level - 1 && r) {
        dirty_counters.emplace(addr);
    }

    return r;
}

bool
AMNT::_in_subtree(uint64_t addr, int tree_level)
{
    if (tree_level == subtree_level) {
        if (std::find(subtree_roots.begin(), subtree_roots.end(), addr)
                       != subtree_roots.end()) {
            return true;
        } else {
            return false;
       }

        return false;
    }

    return _in_subtree(
            calculateAddress(addr, tree_level, false), tree_level - 1);
}

void
AMNT::moveSubtree()
{
    assert(subtree_level != -1);

    std::vector<std::pair<uint64_t, int>> candidate_map;
    std::vector<uint64_t> most_frequented_addrs = subtree_roots;
    // std::vector<int> max_accesses;
    int max_index = num_subtrees;

    // Determine most common candidates
    for (int i = 0; i < max_st_index; i++) {
        bool found = false;
        for (int j = 0; j < candidate_map.size(); j++) {
            if (candidate_map[j].first == subtree_candidates[i]) {
                candidate_map[j].second++;

                found = true;
                break;
            }
        }

        if (!found) {
            candidate_map.push_back(std::pair<uint64_t, int>
                                       (subtree_candidates[i], 1));
       }
    }

    if (candidate_map.size() < num_subtrees) {
        max_index = candidate_map.size();
    }

    struct
    {
        bool operator()(std::pair<uint64_t, int> a,std::pair<uint64_t, int> b)
            const { return a.second > b.second; }
    } candidateSort;

    // sort subtree_candidates
    std::sort(candidate_map.begin(), candidate_map.end(), candidateSort);

    subtree_tracking_index = 0;

    std::vector<uint64_t> changing_roots;
    std::vector<uint64_t> maintaining_roots;
    std::vector<uint64_t> old_roots;
    int num_accesses = 0;

    for (int i = 0; i < max_index; i++) {
        if (std::find(subtree_roots.begin(), subtree_roots.end(),
                        candidate_map[i].first) == subtree_roots.end()) {
            changing_roots.push_back(candidate_map[i].first);
        } else {
            maintaining_roots.push_back(candidate_map[i].first);
        }

        num_accesses += candidate_map[i].second;
    }

    // set next_subtrees
    assert(next_subtrees.empty());
    next_subtrees = subtree_roots;
    for (int i = 0; i < max_index; i++) {
        next_subtrees[i] = candidate_map[i].first;
    }

    for (int i = max_index; i < num_subtrees; i++) {
        maintaining_roots.push_back(next_subtrees[i]);
    }

    for (int i = 0; i < num_subtrees; i++) {
        if (std::find(next_subtrees.begin(), next_subtrees.end(),
                            subtree_roots[i]) == next_subtrees.end()) {
            old_roots.push_back(subtree_roots[i]);
        }
    }

    // Stat counting
    if (changing_roots.empty()) {
        stats.subtreeMaintains += num_subtrees;
        next_subtrees.clear();
        return;
    } else if (moveRatio > 0
                && ((1.0 * num_accesses) / max_st_index) < moveRatio) {
        stats.subtreeMaintains += num_subtrees;
        next_subtrees.clear();
        return;
    }

    // Prepare all necessary fields to compute the move
    uint64_t num_counters_per_subtree = (integrity_levels[data_level - 2] -
            integrity_levels[data_level - 1]) /
            BLOCK_SIZE / pow(8, subtree_level - 1);

    std::vector<uint64_t> root_block_ids;
    std::vector<uint64_t> starting_counter_indices;
    std::vector<uint64_t> ending_counter_indices;

    for (int i = 0; i < old_roots.size(); i++) {
        uint64_t block_num = (old_roots[i] - integrity_levels[subtree_level])
               / BLOCK_SIZE;
        starting_counter_indices.push_back(block_num *
                        num_counters_per_subtree);
        ending_counter_indices.push_back((block_num + 1) *
                        num_counters_per_subtree);
    }

    for (int root_id = 0; root_id < old_roots.size(); root_id++) {
        for (int i = starting_counter_indices[root_id];
                    i < ending_counter_indices[root_id]; i++) {
            uint64_t addr = (i * BLOCK_SIZE) +integrity_levels[data_level - 1];
            if (_in_subtree(addr, data_level - 1)
                       && dirty_counters.find(addr) != dirty_counters.end()) {
                subtree_moving++;
                createMetadata(addr, data_level - 1, false, nullptr);
             }
        }
    }

    if (subtree_moving == 0) {
        subtree_roots = next_subtrees;
        next_subtrees.clear();
    }

    stats.subtreeChanges += changing_roots.size();
    stats.subtreeMaintains += maintaining_roots.size();
}

AMNT::AMNTStats::AMNTStats(AMNT &amnt) :
    statistics::Group(&amnt), m(amnt),

    ADD_STAT(subtreeHits, statistics::units::Count::get(),
             "times where we stopped early because we hit the fast subtree"),
    ADD_STAT(subtreeMisses, statistics::units::Count::get(),
             "times where we missed the fast subtree"),
    ADD_STAT(subtreeChanges, statistics::units::Count::get(),
             "times the fast subtree moved (expensive op)"),
    ADD_STAT(subtreeMaintains, statistics::units::Count::get(),
             "times the fast subtree stays the same")
{
}

void
AMNT::AMNTStats::regStats()
{
    using namespace statistics;

    statistics::Group::regStats();
}

} // gem5

gem5::AMNT *
gem5::AMNTParams::create() const
{
    return new gem5::AMNT(this);
}
