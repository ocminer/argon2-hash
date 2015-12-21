/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2013 Neisklar,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "argon2m.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/ar2/src/argon2.h"
#include "sha3/sj/scrypt-jane.h"


void argon2_hash(const char* input, char* output)
{

//    uint32_t _ALIGN(32) hashA[8], hashB[8],hashC[8];

   uint32_t  hashA[8], hashB[8], hashC[8];

    unsigned int t_costs = 2;            
    unsigned int m_costs = 16;

    uint32_t mask = 8;
    uint32_t zero = 0;



/*
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);	 //0



    if ((hashB[0] & mask) != zero) //7
    {
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hashB, 64); //
        sph_keccak512_close(&ctx_keccak, hashA); //8
    }
    else
    {
        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, hashB, 64); //7
        sph_jh512_close(&ctx_jh, hashA); //8
    }
*/

scrypt((const unsigned char *)input, 80, 
(const unsigned char *)input, 80,
m_costs/2, 0, 0, (unsigned char *)hashA, 32);	
	
	if ((hashA[0] & mask) != zero)	
 hash_argon2d(hashB, 32, hashA, 32,
                 hashA, 32,  t_costs, m_costs);	
	else	
	hash_argon2i(hashB, 32,hashA, 32,
                 hashA, 32,  t_costs, m_costs);	

scrypt((const unsigned char *)hashB, 32, 
(const unsigned char *)hashB, 32,
m_costs/2, 0, 0, (unsigned char *)hashC, 32);	
	
	memcpy(output, hashC, 32);



}


