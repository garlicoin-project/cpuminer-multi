/**
 * Blake2-S Implementation
 * tpruvot@github 2015-2016
 */

#include "miner.h"

#include <string.h>
#include <stdint.h>

// #include "blake2.c"
// #include "lyra2re.c"

void allium_hash(void *state, const void *input)
{
    uint32_t _ALIGN(128) a_hash[8];
    lyra2_hash(a_hash, input);
    blake2s_hash(state, a_hash);
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
