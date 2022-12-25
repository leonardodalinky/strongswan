/*
 * Copyright (C) 2008 Tobias Brunner
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

#include "gmalg_crypter.h"

#include <gmalg.h>

#include <gmssl/sm4.h>

typedef struct private_gmalg_crypter_t private_gmalg_crypter_t;

/**
 * Private data of gmalg_crypter_t
 */
struct private_gmalg_crypter_t {

	/**
	 * Public part of this class.
	 */
	gmalg_crypter_t public;

	/*
	 * the key
	 */
	chunk_t	key;

	/*
	 * the cipher to use
	 */
	encryption_algorithm_t algo;

	SM4_KEY *key_enc;
	SM4_KEY *key_dec;
};

/**
 * Do the actual en/decryption in an EVP context
 */
static bool crypt(private_gmalg_crypter_t *this, chunk_t data, chunk_t iv,
				  chunk_t *dst, int enc)
{
	bool success = TRUE;
	u_int alg_mode;
	u_char *out;
	u_int len;
	int rc;

	switch (this->algo)
	{
		case ENCR_SM1_ECB:
			alg_mode = GMALG_SM1_ECB;
			break;
		case ENCR_SM1_CBC:
			alg_mode = GMALG_SM1_CBC;
			break;
		case ENCR_SM4_ECB:
			alg_mode = GMALG_SM4_CBC;
			break;
		case ENCR_SM4_CBC:
			alg_mode = GMALG_SM4_CBC;
			break;
		default:
		{
			/* algo unavailable invalid */
			return FALSE;
		}
	}

	out = data.ptr;
	if (dst)
	{
		*dst = chunk_alloc(data.len);
		out = dst->ptr;
	}

	if (enc)
		rc = GMSSL_Encrypt(this->key_enc, alg_mode, iv.ptr, data.ptr, data.len, out, &len);
	else
		rc = GMSSL_Decrypt(this->key_dec, alg_mode, iv.ptr, data.ptr, data.len, out, &len);
	if(rc)
		success = FALSE;

	return success;
}

METHOD(crypter_t, decrypt, bool,
	private_gmalg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 0);
}

METHOD(crypter_t, encrypt, bool,
	private_gmalg_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	return crypt(this, data, iv, dst, 1);
}

METHOD(crypter_t, get_block_size, size_t,
	private_gmalg_crypter_t *this)
{
	return SM4_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_gmalg_crypter_t *this)
{
	return SM4_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
	private_gmalg_crypter_t *this)
{
	return this->key.len;
}

METHOD(crypter_t, set_key, bool,
	private_gmalg_crypter_t *this, chunk_t key)
{
	memcpy(this->key.ptr, key.ptr, min(key.len, this->key.len));
	sm4_set_encrypt_key(this->key_enc, this->key.ptr);
	sm4_set_decrypt_key(this->key_dec, this->key.ptr);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_gmalg_crypter_t *this)
{
	free(this->key_enc);
	free(this->key_dec);
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
gmalg_crypter_t *gmalg_crypter_create(encryption_algorithm_t algo,
												  size_t key_size)
{
	private_gmalg_crypter_t *this;

	INIT(this,
		.public = {
			.crypter = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
	);

	this->algo = algo;
	if (key_size != SM4_KEY_SIZE) {
		DBG1(DBG_LIB, "invalid sm4 key size: %d", key_size);
		return NULL;
	}
	this->key = chunk_alloc(key_size);
	this->key_enc = (SM4_KEY *)malloc(sizeof(SM4_KEY));
	this->key_dec = (SM4_KEY *)malloc(sizeof(SM4_KEY));
	set_key(this, this->key);

	return &this->public;
}

void GMSSL_sm4_ecb_encrypt(SM4_KEY *key, uint8_t *in, uint32_t len, uint8_t *out)
{
	while(len > 0) {
		sm4_encrypt(key, in, out);
		in  += SM4_BLOCK_SIZE;
		out += SM4_BLOCK_SIZE;
		len -= SM4_BLOCK_SIZE;
	}
}

#define GMSSL_sm4_ecb_decrypt GMSSL_sm4_ecb_encrypt

int GMSSL_Encrypt(
	SM4_KEY* key,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)

{
	int rc = 0;

	switch( uiAlgID){
	case GMALG_SM1_ECB:{
		GMSSL_sm4_ecb_encrypt(key, pucData, uiDataLength, pucEncData);
		if(puiEncDataLength)
			*puiEncDataLength = uiDataLength;
	}break;
	case GMALG_SM1_CBC:{
		sm4_cbc_encrypt(key, pucIV, pucData, uiDataLength / SM4_BLOCK_SIZE, pucEncData);
		if(puiEncDataLength)
			*puiEncDataLength = uiDataLength;
	}break;
	case GMALG_SM4_ECB:{
		GMSSL_sm4_ecb_encrypt(key, pucData, uiDataLength, pucEncData);
		if(puiEncDataLength)
			*puiEncDataLength = uiDataLength;
	}break;
	case GMALG_SM4_CBC:{
		sm4_cbc_encrypt(key, pucIV, pucData, uiDataLength / SM4_BLOCK_SIZE, pucEncData);
		if(puiEncDataLength)
			*puiEncDataLength = uiDataLength;
	}break;
	default:{ rc = -1;}
	}

	return rc;
}

int GMSSL_Decrypt (
	SM4_KEY* key,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)

{
	int rc = 0;

	switch( uiAlgID){
	case GMALG_SM1_ECB:{
		GMSSL_sm4_ecb_decrypt(key, pucEncData, uiEncDataLength, pucData);
		if(puiDataLength)
			*puiDataLength = uiEncDataLength;
	}break;
	case GMALG_SM1_CBC:{
		sm4_cbc_decrypt(key, pucIV, pucEncData, uiEncDataLength / SM4_BLOCK_SIZE, pucData);
		if(puiDataLength)
			*puiDataLength = uiEncDataLength;
	}break;
	case GMALG_SM4_ECB:{
		GMSSL_sm4_ecb_decrypt(key, pucEncData, uiEncDataLength, pucData);
		if(puiDataLength)
			*puiDataLength = uiEncDataLength;
	}break;
	case GMALG_SM4_CBC:{
		sm4_cbc_decrypt(key, pucIV, pucEncData, uiEncDataLength / SM4_BLOCK_SIZE, pucData);
		if(puiDataLength)
			*puiDataLength = uiEncDataLength;
	}break;
	default:{ rc = -1;}
	}

	return rc;
}
