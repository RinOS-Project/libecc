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
#include <libecc/lib_ecc_types.h>
#ifdef WITH_SIG_ECDSA

#ifndef __ECDSA_H__
#define __ECDSA_H__

#include <libecc/sig/ecdsa_common.h>

ATTRIBUTE_WARN_UNUSED_RET int ecdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

ATTRIBUTE_WARN_UNUSED_RET int ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize, u8 *siglen);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_sign_init(struct ec_sign_context *ctx);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

/* ECDSA over a digest that has already been computed by the caller. The
 * supplied digest length must match hash_type exactly. */
ATTRIBUTE_WARN_UNUSED_RET int ecdsa_sign_digest(u8 *sig, u8 siglen,
                                                const ec_key_pair *key_pair,
                                                const u8 *digest, u8 digest_len,
                                                hash_alg_type hash_type);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_verify_init(struct ec_verify_context *ctx,
		       const u8 *sig, u8 siglen);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen);

ATTRIBUTE_WARN_UNUSED_RET int _ecdsa_verify_finalize(struct ec_verify_context *ctx);

ATTRIBUTE_WARN_UNUSED_RET int ecdsa_verify_digest(const u8 *sig, u8 siglen,
                                                  const ec_pub_key *pub_key,
                                                  const u8 *digest,
                                                  u8 digest_len,
                                                  hash_alg_type hash_type);

ATTRIBUTE_WARN_UNUSED_RET int ecdsa_public_key_from_sig(ec_pub_key *out_pub1, ec_pub_key *out_pub2, const ec_params *params,
                                const u8 *sig, u8 siglen, const u8 *hash, u8 hsize);

#endif /* __ECDSA_H__ */
#endif /* WITH_SIG_ECDSA */
