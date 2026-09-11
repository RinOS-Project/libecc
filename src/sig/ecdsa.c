/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include <libecc/lib_ecc_config.h>
#ifdef WITH_SIG_ECDSA

#include <libecc/nn/nn_rand.h>
#include <libecc/nn/nn_mul_public.h>
#include <libecc/nn/nn_logical.h>

#include <libecc/sig/sig_algs_internal.h>
#include <libecc/sig/sig_algs.h>
#include <libecc/sig/ec_key.h>
#include <libecc/utils/utils.h>
#ifdef VERBOSE_INNER_VALUES
#define EC_SIG_ALG "ECDSA"
#endif
#include <libecc/utils/dbg_sig.h>

int ecdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv)
{
	return __ecdsa_init_pub_key(out_pub, in_priv, ECDSA);
}

int ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize, u8 *siglen)
{
	return __ecdsa_siglen(p_bit_len, q_bit_len, hsize, blocksize, siglen);
}

int _ecdsa_sign_init(struct ec_sign_context *ctx)
{
	return __ecdsa_sign_init(ctx, ECDSA);
}

int _ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen)
{
	return __ecdsa_sign_update(ctx, chunk, chunklen, ECDSA);
}

int _ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen)
{
	return __ecdsa_sign_finalize(ctx, sig, siglen, ECDSA);
}

int ecdsa_sign_digest(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
			      const u8 *digest, u8 digest_len,
			      hash_alg_type hash_type)
{
	struct ec_sign_context ctx;
	int ret;

	if ((digest == NULL) || (digest_len == 0)) {
		return -1;
	}
	ret = ec_sign_init(&ctx, key_pair, ECDSA, hash_type, NULL, 0); EG(ret, err);
	ret = __ecdsa_sign_finalize_digest(&ctx, sig, siglen, digest, digest_len,
					     ECDSA);

err:
	IGNORE_RET_VAL(local_memset(&ctx, 0, sizeof(ctx)));
	return ret;
}

int _ecdsa_verify_init(struct ec_verify_context *ctx, const u8 *sig, u8 siglen)
{
	return __ecdsa_verify_init(ctx, sig, siglen, ECDSA);
}

int _ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen)
{
	return __ecdsa_verify_update(ctx, chunk, chunklen, ECDSA);
}

int _ecdsa_verify_finalize(struct ec_verify_context *ctx)
{
	return __ecdsa_verify_finalize(ctx, ECDSA);
}

int ecdsa_verify_digest(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
				const u8 *digest, u8 digest_len,
				hash_alg_type hash_type)
{
	struct ec_verify_context ctx;
	int ret;

	if ((digest == NULL) || (digest_len == 0)) {
		return -1;
	}
	ret = ec_verify_init(&ctx, pub_key, sig, siglen, ECDSA, hash_type, NULL, 0); EG(ret, err);
	ret = __ecdsa_verify_finalize_digest(&ctx, digest, digest_len, ECDSA);

err:
	IGNORE_RET_VAL(local_memset(&ctx, 0, sizeof(ctx)));
	return ret;
}

int ecdsa_public_key_from_sig(ec_pub_key *out_pub1, ec_pub_key *out_pub2, const ec_params *params,
                              const u8 *sig, u8 siglen, const u8 *hash, u8 hsize)
{
	return __ecdsa_public_key_from_sig(out_pub1, out_pub2, params, sig, siglen, hash, hsize, ECDSA);
}

#else /* WITH_SIG_ECDSA */

/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif /* WITH_SIG_ECDSA */
