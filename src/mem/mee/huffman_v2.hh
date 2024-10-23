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
 * Declares a Memory Encryption Engine where the Merkle tree is Huffmanized.
 */

#ifndef __MEM_MEE_HUFFMAN_V2_HH__
#define __MEM_MEE_HUFFMAN_V2_HH__

#include "mem/mee/timing_pointer.hh"
#include <array>
#include <algorithm>
#include <iostream>
#include <vector>
#include <queue>
#include <bits/stdc++.h>
#include "params/TimingPointerEncryptionEngine.hh"
#include "params/HuffmanV2EncryptionEngine.hh"


#define PAGE_SIZE (unsigned long long) 4096

namespace gem5 {

struct HuffmanV2EncryptionEngineParams;

struct node {
    uint64_t addr, parent;
    int freq;
    node *children[8];
    bool inserted;

    node(uint64_t x, int y) {
        this->freq = y;
        this->addr = x;
        this->inserted = false;
        
        for (int i = 0; i < 8; i++) {
          children[i] = nullptr;
        }
    }
};

struct compare {
    bool operator() (struct node* left, struct node* right) {
        return (left->freq > right->freq);
    }
};

struct heap {
    std::priority_queue<struct node*, std::vector<struct node*>, compare> minheap;
    int heap_size = 0;

    heap(std::vector<std::pair<uint64_t, uint64_t>> frequencies) {
        this->heap_size = frequencies.size();
        for (int i=0; i < (this->heap_size); i++) {
            (this->minheap).push(new node(frequencies[i].first, frequencies[i].second));
        }
    }
};

struct huffman_tree {
    struct node* root;
    struct node* all_nodes;

    huffman_tree(std::vector<std::pair<uint64_t, uint64_t>> frequencies, uint64_t size, uint64_t next_addr) {
        all_nodes = (node *) malloc(sizeof(node) * size);
        struct heap *heap_holder = new heap(frequencies);
        struct node *top;
        struct node *children[8];
        auto huffman_heap = heap_holder->minheap;

        uint64_t idx = 0;

        while (huffman_heap.size() > 1) {
            int total_freq = 0;

            for (int i = 0; i < 8; i++) {
              children[i] = huffman_heap.top();
              if (huffman_heap.top()->inserted) {
                all_nodes[idx] = *huffman_heap.top();
                idx++;
              }
              huffman_heap.pop();

              total_freq = children[i]->freq;
            }

            top = new node(next_addr, total_freq);
            next_addr += BLOCK_SIZE;
            for (int i = 0; i < 8; i++) {
              top->children[i] = children[i];
            }
            top->inserted = true;
            huffman_heap.push(top);
        }
        this->root = top;
    }

    void ht_free(struct node *root) {
        if (root == NULL) {
            return;
        }

        for (int i = 0; i < 8; i++) {
          ht_free(root->children[i]);
        }
        free(root);
    }
};

class HuffmanV2EncryptionEngine : public TimingPointerEncryptionEngine
{
  private:
    // for tracking how much to increment by
    std::unordered_map<uint64_t, int> increment_map;

    std::vector<std::pair<uint64_t, uint64_t>> frequencies;

    // huffman specific fields
    enum { NORMAL, PQ_SORT, HUFFMAN };
    int state = NORMAL;
    
    uint64_t cells_to_clear;
    uint64_t cells_to_sort;
    uint64_t cells_to_huffmanize;

    uint64_t max_ht_size;
    struct huffman_tree *ht;

    // override functions
    bool handleRequest(PacketPtr pkt);
    bool handleResponse(PacketPtr pkt);
  public:
    HuffmanV2EncryptionEngine(const HuffmanV2EncryptionEngineParams *p);
};

}

#endif //__MEM_MEE_HUFFMAN_V2_HH__
