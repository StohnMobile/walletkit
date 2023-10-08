//
//  BRChainParams.c
//  BRCore
//
//  Created by Aaron Voisine on 3/11/19.
//  Copyright (c) 2019 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include "BRChainParams.h"

#define LTC_TARGET_TIMESPAN     (14*24*60*60/4)
#define LTC_MAX_PROOF_OF_WORK   0x1e0ffff0 // highest value for difficulty target (higher values are less difficult)

static const char *BRMainNetDNSSeeds[] = {
    "node2.walletbuilders.com.", NULL
};

static const char *BRTestNetDNSSeeds[] = {
    NULL
};

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they must be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const BRCheckPoint BRMainNetCheckpoints[] = {
    {      0, uint256("c321976e6eab027d1cf712823d37c0995b046f49b53f8dcaf228e7c69c340251"), 1623334958, 0x1e0ffff0 }
};

static const BRCheckPoint BRTestNetCheckpoints[] = {
    {      0, uint256("991db00f7a203b32935844b414d98e38437359e6220fdad6e95d8cdbe197b9b5"), 1623337198, 0x1e0ffff0 }
};

static int ltcVerifyProofOfWork(const BRMerkleBlock *block)
{
    assert(block != NULL);
    
    // target is in "compact" format, where the most significant byte is the size of the value in bytes, next
    // bit is the sign, and the last 23 bits is the value after having been right shifted by (size - 3)*8 bits
    uint32_t size = block->target >> 24, target = block->target & 0x007fffff;
    uint8_t buf[80];
    size_t off = 0;
    int i;
    UInt256 w, t = UINT256_ZERO;
    
    UInt32SetLE(&buf[off], block->version);
    off += sizeof(uint32_t);
    UInt256Set(&buf[off], block->prevBlock);
    off += sizeof(UInt256);
    UInt256Set(&buf[off], block->merkleRoot);
    off += sizeof(UInt256);
    UInt32SetLE(&buf[off], block->timestamp);
    off += sizeof(uint32_t);
    UInt32SetLE(&buf[off], block->target);
    off += sizeof(uint32_t);
    UInt32SetLE(&buf[off], block->nonce);
    off += sizeof(uint32_t);
    BRScrypt(w.u8, 32, buf, off, buf, off, 1024, 1, 1);

    if (size - 3 >= sizeof(t) - sizeof(uint32_t)) return 0;
    
    if (size > 3) UInt32SetLE(&t.u8[size - 3], target);
    else UInt32SetLE(t.u8, target >> (3 - size)*8);
        
    for (i = sizeof(t) - 1; i >= 0; i--) { // check proof-of-work
        if (w.u8[i] < t.u8[i]) break;
        if (w.u8[i] > t.u8[i]) return 0;
    }
    
    return 1;
}

static int BRMainNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet)
{
    const BRMerkleBlock *previous, *b = NULL;
    int i, size = 0, r = 1;
    uint64_t target = 0;
    int64_t timespan;

    assert(block != NULL);
    assert(blockSet != NULL);
    previous = BRSetGet(blockSet, &block->prevBlock);

    if (! previous || !UInt256Eq(block->prevBlock, previous->blockHash) || block->height != previous->height + 1) r = 0;
        
    if (r && (block->height % BLOCK_DIFFICULTY_INTERVAL) == 0) { // check if we hit a difficulty transition
        // target is in "compact" format, where the most significant byte is the size of the value in bytes, next
        // bit is the sign, and the last 23 bits is the value after having been right shifted by (size - 3)*8 bits
        size = previous->target >> 24;
        target = previous->target & 0x007fffff;

        for (i = 0, b = block; b && b->height > 0 && i < BLOCK_DIFFICULTY_INTERVAL + 1; i++) { // litecoin timewarp fix
            b = BRSetGet(blockSet, &b->prevBlock);
        }
        
        timespan = (b) ? (int64_t)previous->timestamp - b->timestamp : 0;
        
        // limit difficulty transition to -75% or +400%
        if (timespan < LTC_TARGET_TIMESPAN/4) timespan = LTC_TARGET_TIMESPAN/4;
        if (timespan > LTC_TARGET_TIMESPAN*4) timespan = LTC_TARGET_TIMESPAN*4;
    
        // LTC_TARGET_TIMESPAN happens to be a multiple of 64, and since timespan is at least LTC_TARGET_TIMESPAN/4, we
        // don't lose precision when target is multiplied by timespan*4 and then divided by LTC_TARGET_TIMESPAN/64
        target *= (uint64_t)timespan*4;
        target /= LTC_TARGET_TIMESPAN >> 6;
        size--; // decrement size since we multiplied timespan by 4 and only divided by LTC_TARGET_TIMESPAN/64
    
        while (size < 1 || target > 0x007fffff) { target >>= 8; size++; } // normalize target for "compact" format
        target |= (uint64_t)size << 24;
    
        if (target > LTC_MAX_PROOF_OF_WORK) target = LTC_MAX_PROOF_OF_WORK; // limit to LTC_MAX_PROOF_OF_WORK
        if (b && block->target != target) r = 0;
    }
    else if (r && block->target != previous->target) r = 0;
    
    return r && ltcVerifyProofOfWork(block);
}

static int BRTestNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet)
{
    return 1; // XXX skip testnet difficulty check for now
}

extern const BRCheckPoint *BRChainParamsGetCheckpointBefore (const BRChainParams *params, uint32_t timestamp) {
    for (ssize_t index = params->checkpointsCount - 1; index >= 0; index--)
        if (params->checkpoints[index].timestamp < timestamp)
            return &params->checkpoints[index];
   return NULL;
}

extern const BRCheckPoint *BRChainParamsGetCheckpointBeforeBlockNumber (const BRChainParams *params, uint32_t blockNumber) {
    for (ssize_t index = params->checkpointsCount - 1; index >= 0; index--)
        if (params->checkpoints[index].height < blockNumber)
            return &params->checkpoints[index];
   return NULL;
}

static const BRChainParams BRMainNetParamsRecord = {
    BRMainNetDNSSeeds,
    37218,                 // standardPort
    0xc44941f7,            // magicNumber
    SERVICES_NODE_WITNESS, // services
    BRMainNetVerifyDifficulty,
    BRMainNetCheckpoints,
    sizeof(BRMainNetCheckpoints)/sizeof(*BRMainNetCheckpoints),
    { BITCOIN_PUBKEY_PREFIX, BITCOIN_SCRIPT_PREFIX, BITCOIN_PRIVKEY_PREFIX, BITCOIN_BECH32_PREFIX },
    BITCOIN_FORKID
};
const BRChainParams *BRMainNetParams = &BRMainNetParamsRecord;

static const BRChainParams BRTestNetParamsRecord = {
    BRTestNetDNSSeeds,
    47218,                 // standardPort
    0xa135ea92,            // magicNumber
    SERVICES_NODE_WITNESS, // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints)/sizeof(*BRTestNetCheckpoints),
    { BITCOIN_PUBKEY_PREFIX_TEST, BITCOIN_SCRIPT_PREFIX_TEST, BITCOIN_PRIVKEY_PREFIX_TEST, BITCOIN_BECH32_PREFIX_TEST },
    BITCOIN_FORKID
};

const BRChainParams *BRTestNetParams = &BRTestNetParamsRecord;
