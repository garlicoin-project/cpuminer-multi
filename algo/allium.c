/**
 * Blake2-S Implementation
 * tpruvot@github 2015-2016
 */

#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "crypto/blake2s.h"

#define BLAKE2S_BLOCK_SIZE    64U
#define BLAKE2S_OUTBYTES 32

// #include "blake2.c"
// #include "lyra2re.c"

#define printpfx(n,h) \
	printf("%s%11s%s: %s\n", CL_CYN, n, CL_N, format_hash(s, (uint8_t*) h))

static char* format_hash(char* buf, uint8_t *hash)
{
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void allium_hash(void *output, const void *input)
{
    int inputLen = 80;
    uint32_t hashA[8], hashB[8];
    char s[80];

    blake2s_hash((unsigned char *) hashA, input);

    // printpfx("lyra", hashA);

    LYRA2(&hashB, 32, hashA, 32, hashA, 32, 1, 8, 8);

    // printpfx("lyra", hashB);

    // blake2s_simple((unsigned char *) hashA, hashB, 32);

    // printpfx("output", hashA);

    memcpy(output, hashB, 32);
}

int scanhash_allium(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;

    if(opt_benchmark){
        ptarget[7] = 0x000fff;
    }

    for (int i=0; i < 19; i++) {
        be32enc(&endiandata[i], pdata[i]);
    }

    do {
        be32enc(&endiandata[19], n);
        allium_hash(hash, endiandata);

        if (hash[7] < Htarg && fulltest(hash, ptarget)) {
            work_set_target_ratio(work, hash);
            *hashes_done = n - first_nonce + 1;
            pdata[19] = n;
            return 1;
        }
        n++;

    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;

    return 0;
}
