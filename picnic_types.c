/*! @file picnic_types.c
 *  @brief Functions to allocate/free data types used in the Picnic signature
 *  scheme implementation.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic_types.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

shares_t* allocateShares(size_t count)
{
    shares_t* shares = malloc(sizeof(shares_t));

    shares->shares = calloc(count, sizeof(uint16_t));
    shares->numWords = count;
    return shares;
}
void freeShares(shares_t* shares)
{
    free(shares->shares);
    free(shares);
}

/* Allocate/free functions for dynamically sized types */
void allocateView(view_t* view, paramset_t* params)
{
    view->inputShare = calloc(params->stateSizeBytes, 1);
    view->communicatedBits = calloc(params->andSizeBytes, 1);
    view->outputShare = calloc(params->stateSizeBytes, 1);
}

void freeView(view_t* view)
{
    free(view->inputShare);
    free(view->communicatedBits);
    free(view->outputShare);
}

/* Allocate/free functions for dynamically sized types */
void allocateViewBlind(view_blind_t * view, paramset_t* params)
{
    view->inputShare = calloc(params->stateSizeBytes, 1);
    view->inputBlindShare = calloc(params->stateSizeBytes, 1);
    view->communicatedBits = calloc(params->andSizeBytes*2, 1);
    view->outputShare = calloc(params->stateSizeBytes, 1);
}

void freeViewBlind(view_blind_t* view)
{
    free(view->inputShare);
    free(view->inputBlindShare);
    free(view->communicatedBits);
    free(view->outputShare);
}


size_t getTapeSizeBytes(const paramset_t* params)
{
    return 2*params->andSizeBytes;
}

void allocateRandomTape(randomTape_t* tape, paramset_t* params)
{
    tape->nTapes = params->numMPCParties;
    tape->tape = malloc(tape->nTapes * sizeof(uint8_t*));
    size_t tapeSizeBytes = getTapeSizeBytes(params);
    uint8_t* slab = calloc(1, tape->nTapes * tapeSizeBytes);
    for (uint8_t i = 0; i < tape->nTapes; i++) {
        tape->tape[i] = slab;
        slab += tapeSizeBytes;
    }
    tape->pos = 0;

}


void freeRandomTape(randomTape_t* tape)
{
    if (tape != NULL) {
        free(tape->tape[0]);
        free(tape->tape);
    }
}

void allocateRandomTapeBlind(randomTape_t* tape, paramset_t* params)
{

    tape->nTapes = params->numMPCParties;
    tape->tape = malloc(tape->nTapes* sizeof(uint8_t*));
    size_t tapeSizeBytes = getTapeSizeBytes(params);
    uint8_t* slab = calloc(1, tape->nTapes*2 * tapeSizeBytes);
    for (uint8_t i = 0; i < tape->nTapes; i++) {
        tape->tape[i] = slab;
        slab += tapeSizeBytes*2;
    }
    tape->pos = 0;
}


void freeRandomTapeBlind(randomTape_t* tape)
{
    if (tape != NULL) {
        free(tape->tape[0]);
        free(tape->tape);
    }
}
void allocateProof2(proof2_t* proof, paramset_t* params)
{
    memset(proof, 0, sizeof(proof2_t));

    proof->seedInfo = NULL;     // Sign/verify code sets it
    proof->seedInfoLen = 0;
    proof->C = malloc(params->digestSizeBytes);
    proof->input = calloc(1, params->stateSizeBytes);
    proof->aux = calloc(1, params->andSizeBytes);
    proof->msgs = calloc(1, params->andSizeBytes);

}

void allocateProof2Blind(proof2_t_blind * proof, paramset_t* params)
{
    memset(proof, 0, sizeof(proof2_t_blind));

    proof->seedInfo = NULL;     // Sign/verify code sets it
    proof->seedInfoLen = 0;
    proof->C = malloc(params->digestSizeBytes);

    proof->input = calloc(1, params->stateSizeBytes);
    proof->aux = calloc(1, params->andSizeBytes*2);
    proof->msgs = calloc(1, params->andSizeBytes*2);

    proof->inputSecond = calloc(1, params->stateSizeBytes);


}
void freeProof2(proof2_t* proof)
{
    free(proof->seedInfo);
    free(proof->C);
    free(proof->input);
    free(proof->aux);
    free(proof->msgs);
}
void freeProof2Blind(proof2_t_blind * proof)
{
    free(proof->seedInfo);
    free(proof->C);
    free(proof->input);
    free(proof->aux);
    free(proof->msgs);

    free(proof->inputSecond);

}

void allocateProof(proof_t* proof, paramset_t* params)
{
    proof->seed1 = malloc(params->seedSizeBytes);
    proof->seed2 = malloc(params->seedSizeBytes);
    proof->inputShare = malloc(params->stateSizeBytes);
    proof->communicatedBits = malloc(params->andSizeBytes);
    proof->view3Commitment = malloc(params->digestSizeBytes);
    if (params->UnruhGWithInputBytes > 0) {
        proof->view3UnruhG = malloc(params->UnruhGWithInputBytes);
    }
    else {
        proof->view3UnruhG = NULL;
    }
}

void freeProof(proof_t* proof)
{
    free(proof->seed1);
    free(proof->seed2);
    free(proof->inputShare);
    free(proof->communicatedBits);
    free(proof->view3Commitment);
    free(proof->view3UnruhG);
}

void allocateSignature(signature_t* sig, paramset_t* params)
{
    sig->proofs = (proof_t*)malloc(params->numMPCRounds * sizeof(proof_t));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        allocateProof(&(sig->proofs[i]), params);
    }

    sig->challengeBits = (uint8_t*)malloc(numBytes(2 * params->numMPCRounds));
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
}

void freeSignature(signature_t* sig, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeProof(&(sig->proofs[i]));
    }

    free(sig->proofs);
    free(sig->challengeBits);
    free(sig->salt);
}

void allocateBlindProof(proof_blind_t* proof, paramset_t* params)
{
    proof->seed1 = malloc(params->seedSizeBytes*2);
    proof->seed2 = malloc(params->seedSizeBytes*2);
    proof->inputShare = malloc(params->stateSizeBytes);
    proof->inputBlindShare = malloc(params->stateSizeBytes);
    proof->communicatedBits = malloc(params->andSizeBytes*2);
    proof->view3Commitment = malloc(params->digestSizeBytes);
    if (params->UnruhGWithInputBytes > 0) {
        proof->view3UnruhG = malloc(params->UnruhGWithInputBytes);
    }
    else {
        proof->view3UnruhG = NULL;
    }
}

void freeBlindProof(proof_blind_t* proof)
{
    free(proof->seed1);
    free(proof->seed2);
    free(proof->inputShare);
    free(proof->communicatedBits);
    free(proof->view3Commitment);
    free(proof->view3UnruhG);

    free(proof->inputBlindShare);
}

void allocateBlindSignature(signature_blind_t* sig, paramset_t* params)
{
    sig->proofs = (proof_blind_t*)malloc(params->numMPCRounds * sizeof(proof_blind_t));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        allocateBlindProof(&(sig->proofs[i]), params);
    }

    sig->challengeBits = (uint8_t*)malloc(numBytes(2 * params->numMPCRounds));
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
}

void freeBlindSignature(signature_blind_t* sig, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeBlindProof(&(sig->proofs[i]));
    }

    free(sig->proofs);
    free(sig->challengeBits);
    free(sig->salt);
}

void allocateSignature2(signature2_t* sig, paramset_t* params)
{
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
    sig->iSeedInfo = NULL;
    sig->iSeedInfoLen = 0;
    sig->cvInfo = NULL;       // Sign/verify code sets it
    sig->cvInfoLen = 0;
    sig->challengeC = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeP = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeHash = (uint8_t*)malloc(params->digestSizeBytes);
    sig->proofs = calloc(params->numMPCRounds, sizeof(proof2_t));
    // Individual proofs are allocated during signature generation, only for rounds when neeeded
}

void freeSignature2(signature2_t* sig, paramset_t* params)
{
    free(sig->salt);
    free(sig->iSeedInfo);
    free(sig->cvInfo);
    free(sig->challengeC);
    free(sig->challengeP);
    free(sig->challengeHash);
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeProof2(&sig->proofs[i]);
    }
    free(sig->proofs);
}

void allocateSignature2Blind(signature2_t_blind* sig, paramset_t* params)
{
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
    sig->iSeedInfo = NULL;
    sig->iSeedInfoLen = 0;
    sig->cvInfo = NULL;       // Sign/verify code sets it
    sig->cvInfoLen = 0;
    sig->challengeC = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeP = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeHash = (uint8_t*)malloc(params->digestSizeBytes);

    // Individual proofs are allocated during signature generation, only for rounds when neeeded
    sig->proofs = calloc(params->numMPCRounds, sizeof(proof2_t_blind));

}

void freeSignature2Blind(signature2_t_blind * sig, paramset_t* params)
{
    free(sig->salt);
    free(sig->iSeedInfo);
    free(sig->cvInfo);
    free(sig->challengeC);
    free(sig->challengeP);
    free(sig->challengeHash);
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeProof2Blind(&sig->proofs[i]);
    }
    free(sig->proofs);

}

seeds_t* allocateSeeds(paramset_t* params)
{
    seeds_t* seeds = malloc((params->numMPCRounds + 1) * sizeof(seeds_t));
    size_t nSeeds = params->numMPCParties;
    uint8_t* slab1 = malloc((params->numMPCRounds * nSeeds) * params->seedSizeBytes + params->saltSizeBytes);                                   // Seeds
    uint8_t* slab2 = malloc(params->numMPCRounds * nSeeds * sizeof(uint8_t*) + sizeof(uint8_t*) + params->numMPCRounds * sizeof(uint8_t*) );    // pointers to seeds
    uint8_t* slab3 = malloc((params->numMPCRounds) * params->seedSizeBytes + params->saltSizeBytes);                                            // iSeeds, used to derive seeds

    // We need multiple slabs here, because the seeds are generated with one call to the KDF;
    // they must be stored contiguously

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        seeds[i].seed = (uint8_t**)slab2;
        slab2 += nSeeds * sizeof(uint8_t*);
        seeds[i].iSeed = slab3;
        slab3 += params->seedSizeBytes;

        for (uint32_t j = 0; j < nSeeds; j++) {
            seeds[i].seed[j] = slab1;
            slab1 += params->seedSizeBytes;
        }
    }

    // The salt is the last seed value
    // Accessed by seeds[params->numMPCRounds].iSeed
    seeds[params->numMPCRounds].seed = NULL;
    if (params->numMPCParties == 3) {
        seeds[params->numMPCRounds].iSeed = slab1;      // For ZKB parameter sets, the salt must be derived with the seeds
    }
    else {
        seeds[params->numMPCRounds].iSeed = slab3;      // For Pincic2 paramter sets, the salt is dervied with the initial seeds
    }

    return seeds;
}

void freeSeeds(seeds_t* seeds)
{
    free(seeds[0].seed[0]); // Frees slab1
    free(seeds[0].iSeed);   // Frees slab3
    free(seeds[0].seed);    // frees slab2
    free(seeds);
}
seeds_t* allocateSeedsBlind(paramset_t* params)
{
    seeds_t* seeds = malloc((params->numMPCRounds*2 + 1) * sizeof(seeds_t));
    size_t nSeeds = params->numMPCParties;
    uint8_t* slab1 = malloc(2*(params->numMPCRounds * nSeeds) * params->seedSizeBytes + params->saltSizeBytes);                                   // Seeds
    uint8_t* slab2 = malloc(2*params->numMPCRounds * nSeeds * sizeof(uint8_t*) + sizeof(uint8_t*) +2* params->numMPCRounds * sizeof(uint8_t*) );    // pointers to seeds
    uint8_t* slab3 = malloc(2*(params->numMPCRounds) * params->seedSizeBytes + params->saltSizeBytes);                                            // iSeeds, used to derive seeds

    // We need multiple slabs here, because the seeds are generated with one call to the KDF;
    // they must be stored contiguously

    for (uint32_t i = 0; i < params->numMPCRounds*2; i++) {
        seeds[i].seed = (uint8_t**)slab2;
        slab2 += nSeeds * sizeof(uint8_t*);
        seeds[i].iSeed = slab3;
        slab3 += params->seedSizeBytes;

        for (uint32_t j = 0; j < nSeeds; j++) {
            seeds[i].seed[j] = slab1;
            slab1 += params->seedSizeBytes;
        }
       // printf("I:%d, slab1:%lu\n", i,(uintptr_t)slab1);
    }

    // The salt is the last seed value
    // Accessed by seeds[params->numMPCRounds].iSeed
    //seeds[params->numMPCRounds].seed = NULL;
    seeds[params->numMPCRounds*2].seed = NULL;
    if (params->numMPCParties == 3) {
        seeds[params->numMPCRounds*2].iSeed = slab1;      // For ZKB parameter sets, the salt must be derived with the seeds

    }
    else {
        seeds[params->numMPCRounds*2].iSeed = slab3;      // For Pincic2 paramter sets, the salt is dervied with the initial seeds
    }

    return seeds;
}



commitments_t* allocateCommitments(paramset_t* params, size_t numCommitments)
{
    commitments_t* commitments = malloc(params->numMPCRounds * sizeof(commitments_t));

    commitments->nCommitments = (numCommitments) ? numCommitments : params->numMPCParties;

    uint8_t* slab = malloc(params->numMPCRounds * (commitments->nCommitments * params->digestSizeBytes +
                                                   commitments->nCommitments * sizeof(uint8_t*)) );

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        commitments[i].hashes = (uint8_t**)slab;
        slab += commitments->nCommitments * sizeof(uint8_t*);

        for (uint32_t j = 0; j < commitments->nCommitments; j++) {
            commitments[i].hashes[j] = slab;
            slab += params->digestSizeBytes;
        }
    }

    return commitments;
}

void freeCommitments(commitments_t* commitments)
{
    free(commitments[0].hashes);
    free(commitments);
}


commitments_t* allocateBlindCommitments(paramset_t* params, size_t numCommitments)
{
    commitments_t* commitments = malloc(params->numMPCRounds * sizeof(commitments_t)*2); //Double size

    commitments->nCommitments = (numCommitments) ? numCommitments : params->numMPCParties;

    uint8_t* slab = malloc(params->numMPCRounds *2* (commitments->nCommitments * params->digestSizeBytes +
                                                   commitments->nCommitments * sizeof(uint8_t*)) ); //Double size

    for (uint32_t i = 0; i < params->numMPCRounds*2; i++) {
        commitments[i].hashes = (uint8_t**)slab;
        slab += commitments->nCommitments * sizeof(uint8_t*);

        for (uint32_t j = 0; j < commitments->nCommitments; j++) {
            commitments[i].hashes[j] = slab;
            slab += params->digestSizeBytes;
        }
    }

    return commitments;
}

void freeBlindCommitments(commitments_t* commitments)
{
    free(commitments[0].hashes);
    free(commitments);
}


/* Allocate one commitments_t object with capacity for numCommitments values */
void allocateCommitments2(commitments_t* commitments, paramset_t* params, size_t numCommitments)
{
    commitments->nCommitments = numCommitments;

    uint8_t* slab = malloc(numCommitments * params->digestSizeBytes + numCommitments * sizeof(uint8_t*));

    commitments->hashes = (uint8_t**)slab;
    slab += numCommitments * sizeof(uint8_t*);

    for (size_t i = 0; i < numCommitments; i++) {
        commitments->hashes[i] = slab;
        slab += params->digestSizeBytes;
    }
}

void freeCommitments2(commitments_t* commitments)
{
    if (commitments != NULL) {
        if(commitments->hashes != NULL) {
            free(commitments->hashes);
        }
    }
}

inputs_t allocateInputs(paramset_t* params)
{
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->stateSizeWords*sizeof(uint32_t) + sizeof(uint8_t*)));

    inputs_t inputs = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        inputs[i] = (uint8_t*)slab;
        slab += params->stateSizeWords * sizeof(uint32_t);
    }

    return inputs;
}
inputs_t allocateBlindInputs(paramset_t* params) //TODO
{
    uint8_t* slab = calloc(1, params->numMPCRounds * 2*(params->stateSizeWords*sizeof(uint32_t) + sizeof(uint8_t*)));//double size

    inputs_t inputs = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*)*2; //double rounds

    for (uint32_t i = 0; i < params->numMPCRounds*2; i=i+2) { //double rounds
        inputs[i] = (uint8_t*)slab;
        slab += params->stateSizeWords * sizeof(uint32_t);
        inputs[i+1] = (uint8_t*)slab;
        slab += params->stateSizeWords * sizeof(uint32_t);
    }


    return inputs;
}

void freeInputs(inputs_t inputs)
{
    free(inputs);
}

void freeBlindInputs(inputs_t inputs)
{
    free(inputs);
}

msgs_t* allocateMsgs(paramset_t* params)
{
    msgs_t* msgs = malloc(params->numMPCRounds * sizeof(msgs_t));
    size_t msgsSize = params->andSizeBytes;
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->numMPCParties * msgsSize +
                                                      params->numMPCParties * sizeof(uint8_t*)));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        msgs[i].pos = 0;
        msgs[i].unopened = -1;
        msgs[i].msgs = (uint8_t**)slab;
        slab += params->numMPCParties * sizeof(uint8_t*);

        for (uint32_t j = 0; j < params->numMPCParties; j++) {
            msgs[i].msgs[j] = slab;
            slab += msgsSize;
        }
    }

    return msgs;
}
msgs_t* allocateMsgsBlind(paramset_t* params)
{
    msgs_t* msgs = malloc(params->numMPCRounds * sizeof(msgs_t)*2); //Double size
    size_t msgsSize = params->andSizeBytes;
    uint8_t* slab = calloc(1, params->numMPCRounds *2* (params->numMPCParties * msgsSize + //Double size
                                                      params->numMPCParties * sizeof(uint8_t*)));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {//Double size
        msgs[i].pos = 0;
        msgs[i].unopened = -1;
        msgs[i].msgs = (uint8_t**)slab;
        slab += params->numMPCParties * sizeof(uint8_t*);

        for (uint32_t j = 0; j < params->numMPCParties; j++) {
            msgs[i].msgs[j] = slab;
            slab += msgsSize*2;
        }
    }

    return msgs;
}
void freeMsgs(msgs_t* msgs)
{
    free(msgs[0].msgs);
    free(msgs);
}

view_t** allocateViews(paramset_t* params)
{
    // 3 views per round
    view_t** views = malloc(params->numMPCRounds * sizeof(view_t *));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        views[i] = calloc(3, sizeof(view_t));
        for (size_t j = 0; j < 3; j++) {
            allocateView(&views[i][j], params);
        }
    }

    return views;
}

void freeViews(view_t** views, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            freeView(&views[i][j]);
        }
        free(views[i]);
    }

    free(views);
}

view_blind_t** allocateViewsBlind(paramset_t* params)
{
    // 3 views per round
    view_blind_t** views = malloc(params->numMPCRounds * sizeof(view_blind_t *));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        views[i] = calloc(3, sizeof(view_blind_t));
        for (size_t j = 0; j < 3; j++) {
            allocateViewBlind(&views[i][j], params);
        }
    }

    return views;
}

void freeViewsBlind(view_blind_t** views, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            freeViewBlind(&views[i][j]);
        }
        free(views[i]);
    }

    free(views);
}

g_commitments_t* allocateGCommitments(paramset_t* params)
{
    g_commitments_t* gs = NULL;

    if (params->transform == TRANSFORM_UR) {
        gs = malloc(params->numMPCRounds * sizeof(g_commitments_t));
        uint8_t* slab = malloc(params->UnruhGWithInputBytes * params->numMPCRounds * 3);
        for (uint32_t i = 0; i < params->numMPCRounds; i++) {
            for (uint8_t j = 0; j < 3; j++) {
                gs[i].G[j] = slab;
                slab += params->UnruhGWithInputBytes;
            }
        }
    }

    return gs;
}

void freeGCommitments(g_commitments_t* gs)
{
    if (gs != NULL) {
        free(gs[0].G[0]);
        free(gs);
    }
}

