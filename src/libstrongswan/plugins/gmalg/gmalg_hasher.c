/*
 * Copyright (C) 2008-2017 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <gmalg.h>
#include <sm2.h>
#include <ecc.h>

#include <gmssl/sm3.h>

#include "gmalg_hasher.h"

extern struct ecc_curve ecc_curve;

typedef struct private_gmalg_hasher_t private_gmalg_hasher_t;

/**
 * Private data of gmalg_hasher_t
 */
struct private_gmalg_hasher_t {

	/**
	 * Public part of this class.
	 */
	gmalg_hasher_t public;

	/**
	 * the hasher to use
	 */
	hash_algorithm_t algo;

	SM3_CTX *ctx;
};

METHOD(hasher_t, get_hash_size, size_t,
	private_gmalg_hasher_t *this)
{
	return HASH_SIZE_SM3;
}

METHOD(hasher_t, reset, bool,
	private_gmalg_hasher_t *this)
{
	GMSSL_HashInit(this->ctx, NULL, NULL, 0);

	return TRUE;
}

METHOD(hasher_t, get_hash, bool,
	private_gmalg_hasher_t *this, chunk_t chunk, uint8_t *hash)
{
	GMSSL_HashUpdate(this->ctx, chunk.ptr, chunk.len);

	if (hash)
	{
		u_int len;
		GMSSL_HashFinal(this->ctx, hash, &len);
		GMSSL_HashInit(this->ctx, NULL, NULL, 0);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_gmalg_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(get_hash_size(this));
		return get_hash(this, chunk, hash->ptr);
	}
	return get_hash(this, chunk, NULL);
}

METHOD(hasher_t, destroy, void,
	private_gmalg_hasher_t *this)
{
	free(this->ctx);
	free(this);
}

/*
 * Described in header
 */
gmalg_hasher_t *gmalg_hasher_create(hash_algorithm_t algo)
{
	private_gmalg_hasher_t *this;

	INIT(this,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	this->algo = algo;
	this->ctx = (SM3_CTX*)malloc(sizeof(SM3_CTX));
	GMSSL_HashInit(this->ctx, NULL, NULL, 0);

	return &this->public;
}

gmalg_hasher_t *gmalg_hasher_create_ecc(hash_algorithm_t algo, ECCrefPublicKey *pub_key, chunk_t id)
{
	private_gmalg_hasher_t *this;

	INIT(this,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
	);

	this->algo = algo;
	this->ctx = (SM3_CTX*)malloc(sizeof(SM3_CTX));
	GMSSL_HashInit(this->ctx, pub_key, id.ptr, id.len);

	return &this->public;
}

void GMSSL_sm3_z(uint8_t *id, uint32_t idlen, ecc_point *pub, u8 *hash)
{
	uint8_t a[ECC_NUMWORD];
	uint8_t b[ECC_NUMWORD];
	uint8_t x[ECC_NUMWORD];
	uint8_t y[ECC_NUMWORD];
	uint8_t idlen_char[2];
	SM3_CTX md;

	digit2str16(idlen<<3, idlen_char);

	ecc_bytes2native(a, ecc_curve.a);
	ecc_bytes2native(b, ecc_curve.b);
	ecc_bytes2native(x, ecc_curve.g.x);
	ecc_bytes2native(y, ecc_curve.g.y);

	sm3_init(&md);
	sm3_update(&md, idlen_char, 2);
	sm3_update(&md, id, idlen);
	sm3_update(&md, a, ECC_NUMWORD);
	sm3_update(&md, b, ECC_NUMWORD);
	sm3_update(&md, x, ECC_NUMWORD);
	sm3_update(&md, y, ECC_NUMWORD);
	sm3_update(&md, pub->x, ECC_NUMWORD);
	sm3_update(&md, pub->y, ECC_NUMWORD);
	sm3_finish(&md, hash);
}


void GMSSL_HashInit(
	SM3_CTX *ctx,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	sm3_init(ctx);
	uint8_t Z[ECC_NUMWORD];

	if (uiIDLength) {
		GMSSL_sm3_z(pucID, uiIDLength, pucPublicKey->x, Z);
		sm3_update(ctx, Z, ECC_NUMWORD);
	}
}

void GMSSL_HashUpdate (
	SM3_CTX *ctx,
	unsigned char *pucData,
	unsigned int uiDataLength)

{
	sm3_update(ctx, pucData, uiDataLength);
}

int GMSSL_HashFinal (
	SM3_CTX *ctx,
	unsigned char *pucHash,
	unsigned int *puiHashLength)

{
	sm3_finish(ctx, pucHash);
	if (puiHashLength)
		*puiHashLength =  32;
}
