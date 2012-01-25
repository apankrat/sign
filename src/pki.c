/*
 *	This file is a part of "sign", a file signing utility project.
 *	Copyright (c) 2004-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/sign
 */

/*
 *	The program is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

#include "alloc.h"
#include "pki.h"
#include "uue.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/pem.h>

/*
 *	openssl/evp.h had some of its constants renamed along 
 *	the way - fix it
 */
#ifndef EVP_F_EVP_DECRYPTFINAL_EX
#define EVP_F_EVP_DECRYPTFINAL_EX  EVP_F_EVP_DECRYPTFINAL
#endif

/*
 *
 */
static void   pki_init(void);
static bool_t buf_parse_bignum(buf_t * b, BIGNUM * bn);
static bool_t buf_store_bignum(buf_t * b, const BIGNUM * bn);

/*
 *
 */
bool_t pki_sign(const buf_t * data, const prikey_t * pk, buf_t * sig)
{
	RSA * k = (void*)pk;
	int len;

	pki_init();

	buf_reset(sig);

	if ((len = RSA_size(k)) < 0)
		goto failed;

	if (! buf_alloc(sig, len))
		goto failed;
	
	if (RSA_private_encrypt(buf_size(data), data->p, sig->p, k, 
		RSA_PKCS1_PADDING) != len)
		goto failed;

	return btrue;

failed:
	buf_free(sig);
	return bfalse;
}

bool_t pki_verify(const buf_t * data, const pubkey_t * pk, const buf_t * sig)
{
	RSA * k = (void*)pk;
	uchar * tmp;
	int len, raw;
	bool_t r = bfalse;

	pki_init();
	
	len = RSA_size(k);
	if (len <= 0 || len != buf_size(sig))
		return bfalse;

	tmp = xalloc(len);
	if (! tmp)
		return bfalse;
		
	raw = RSA_public_decrypt(len, sig->p, tmp, k, RSA_PKCS1_PADDING);
	if (raw < 0)
		goto cleanup;
		
	r = (buf_memcmp(data, tmp, raw) == 0);
cleanup:
	xfree(tmp);
	return r;
}

/*
 *	pub key
 */
pubkey_t * pubkey_parse_openssh_blob(const buf_t * _kb)
{
	buf_t  kb = *_kb;
	RSA *  rsa = 0;
	buf_t  kt;        /* key type */

	pki_init();
	
	/* prepare RSA key */
	if (! (rsa = RSA_new()))
		return 0;
	if (! (rsa->n = BN_new()))
		goto failed;
	if (! (rsa->e = BN_new()))
		goto failed;

	/* deserialize 'n' and 'e' from the blob */	
	if (! buf_parse_str(&kb, &kt) ||
	    ! buf_parse_bignum(&kb, rsa->e) ||
	    ! buf_parse_bignum(&kb, rsa->n) ||
	      buf_size(&kb) > 0)
	    	goto failed;

	/* check the type */
	if (buf_strcmp(&kt, "rsa") && buf_strcmp(&kt, "ssh-rsa"))
		goto failed;
#if 0
	RSA_print_fp(stderr, rsa, 8);
	fprintf(stderr, "%d\n", RSA_size(rsa));
#endif
	return (void*)rsa;

failed:
	RSA_free(rsa);
	return 0;
}
 
pubkey_t * pubkey_parse_openssh_text(const buf_t * buf)
{
	buf_t b = *buf;
	buf_t kt; /* key type */
	buf_t kb; /* key blob */
	int   len;
	void * p;
	pubkey_t * pk = 0;

	pki_init();
	
	/* skip leading whitespace */
	while (buf_size(&b) && isspace(*(char*)b.p))
		b.p++;

	/* find first lexem */
	kt.p = b.p;
	if (! (kt.e = buf_find(&b, isspace)))
		return 0;
	
	/* support rsa keys only for now */
	if (buf_strcmp(&kt, "rsa") && buf_strcmp(&kt, "ssh-rsa"))
		return 0;
	b.p = kt.e + 1;

	/* skip whitespace */
	while (buf_size(&b) && isspace(*b.p))
		b.p++;
		
	/* trim upto the whitespace if there's any */
	p = buf_find(&b, isspace);
	b.e = p ? p : buf->e;

	/* determine key length in binary format */
	len = uudecode_len(b.p, buf_size(&b));
	if (len < 0)
		return 0;

	if (! buf_alloc(&kb, len))
		return 0;

	/* convert b64 into binary */
	if (! uudecode(b.p, buf_size(&b), kb.p))
		goto cleanup;

	/* parse the blob */
	pk = pubkey_parse_openssh_blob(&kb);
	
cleanup:
	buf_free(&kb);
	return pk;
}
/*
 *
 */
bool_t pubkey_store_openssh_blob(const pubkey_t * pk, buf_t * b)
{
	RSA * k = (void*)pk;
	
	buf_reset(b);
	return buf_store_str(b, "rsa", 3) &&
	       buf_store_bignum(b, k->e) &&
	       buf_store_bignum(b, k->n);
}

bool_t pubkey_store_openssh_text(const pubkey_t * pk, buf_t * b)
{
	buf_t  kb;
	size_t len;

	if (! pubkey_store_openssh_blob(pk, &kb))
		return bfalse;

	/* store encoded */
	len = buf_size(&kb);
	
	if (! buf_alloc(b, 4 + uuencode_len(len)))
		return bfalse;

	memcpy(b->p, "rsa ", 4);
	uuencode(kb.p, len, b->p + 4);

	buf_free(&kb);	
	return btrue;
}

bool_t pubkey_equal(const pubkey_t * pk1, const pubkey_t * pk2)
{
	RSA * k1 = (void*)pk1;
	RSA * k2 = (void*)pk2;
	
	return ! BN_cmp(k1->e, k2->e) &&
	       ! BN_cmp(k1->n, k2->n);
}

bool_t pubkey_hash(const pubkey_t * pk, hash_alg_t * alg, void * hash)
{
	buf_t kb;         /* key blob */
	hash_val_t * h;
	bool_t r = bfalse;

	if (! pubkey_store_openssh_blob(pk, &kb))
		return bfalse;

	h = alg->instance();
	if (! h)
		goto cleanup;
	
	h->update(h, kb.p, buf_size(&kb));
	h->complete(h, hash);
	r = btrue;

cleanup:
	buf_free(&kb);
	return r;
}

/*
 *	private
 */
struct pass_ctx
{
	password_cb cb;
	void * cb_arg;
	bool_t no_pass;
};

typedef struct pass_ctx pass_ctx_t;

int pass_cb(char * buf, int len, int w /* writing */, void * arg)
{
	pass_ctx_t * ctx = arg;
	buf_t pass; 
	
	ctx->no_pass = btrue;
	if (! ctx->cb(&pass, ctx->cb_arg))
		return -1;

	if (len < buf_size(&pass)) /* should not happen */
		return -1;

	len = buf_size(&pass);
	memcpy(buf, pass.p, len);
	ctx->no_pass = bfalse;

	buf_free(&pass);
	return len;
}

prikey_t * prikey_parse_pem(const buf_t * buf, password_cb cb, void * cb_arg)
{
	BIO * bio;
	EVP_PKEY * k = 0;
	RSA * rsa = 0;
	BUF_MEM * mem;
	pass_ctx_t pass_ctx;

	pki_init();

	/* attach BIO to the memory buffer */
	if (! (bio = BIO_new_mem_buf(buf->p, buf_size(buf))))
		return 0;

	pass_ctx.cb = cb;
	pass_ctx.cb_arg = cb_arg;

	for (;;)
	{
		/* parse and decrypt */
		k = PEM_read_bio_PrivateKey(bio, 0, pass_cb, &pass_ctx);
		if (k)
			break;

		/* if it's not a decryption problem - bail out */
		if (ERR_get_error() != ERR_PACK(ERR_LIB_EVP,
		                                EVP_F_EVP_DECRYPTFINAL_EX,
		                                EVP_R_BAD_DECRYPT))
			goto cleanup;

		/* rewind bio stuff */
		mem = (BUF_MEM*)bio->ptr;
		mem->data = (char*)buf->p;
		mem->length =  buf_size(buf);
	}

	if (EVP_PKEY_type(k->type) != EVP_PKEY_RSA)
		goto cleanup;

	rsa = EVP_PKEY_get1_RSA(k);

cleanup:
	EVP_PKEY_free(k);
	BIO_free(bio);
	return (void*)rsa;

}

/*
 *	statics
 */
static void pki_init(void)
{
	static bool_t init = bfalse;
	if (! init)
	{
		OpenSSL_add_all_ciphers();
		init = btrue;
	}
}
 
static bool_t buf_parse_bignum(buf_t * b, BIGNUM * bn)
{
	size_t len;

	if (! buf_parse_len(b, &len) || len > 8*1024)
		return bfalse;

	if (buf_size(b) < len)
		return bfalse;

	if (! BN_bin2bn(b->p, len, bn))
		return bfalse;

	b->p += len;
	return btrue;
}

static bool_t buf_store_bignum(buf_t * b, const BIGNUM * bn)
{
	size_t len = BN_num_bytes(bn);

	if (! buf_store_len(b, len) || ! buf_grow(b, len))
		return bfalse;
		
	if (! BN_bn2bin(bn, b->e - len))
		return bfalse;

	return btrue;
}

