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

#include "digest.h"
#include "alloc.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <assert.h>

/*
 *	md5
 */
static void _md5_update(hash_val_t * h, const void * data, size_t dlen)
{
	assert(h && h->update == _md5_update);
	MD5_Update((MD5_CTX*)(h+1), data, dlen);
}

static void _md5_complete(hash_val_t * h, void * hval)
{
	assert(h && h->complete == _md5_complete);
	if (hval)
		MD5_Final(hval, (MD5_CTX*)(h+1));
	xfree(h);
}

static void _md5_process(const void * data, size_t dlen, void * hval)
{
	MD5_CTX  temp;

	MD5_Init(&temp);
	MD5_Update(&temp, data, dlen);
	MD5_Final(hval, &temp);
}

static hash_val_t * _md5_instance()
{
	hash_val_t * h;
	MD5_CTX  * ctx;

	h = xalloc(sizeof(hash_val_t) + sizeof(MD5_CTX));
	if (! h)
		return 0;

	ctx = (MD5_CTX*)(h+1);

	h->alg = md5_alg;
	h->update = _md5_update;
	h->complete = _md5_complete;

	MD5_Init(ctx);
	return h;
}

/*
 *	sha1
 */
static void _sha1_update(hash_val_t * h, const void * data, size_t dlen)
{
	assert(h && h->update == _sha1_update);
	SHA1_Update((SHA_CTX*)(h+1), data, dlen);
}

/*  */
static void _sha1_complete(hash_val_t * h, void * hval)
{
	assert(h && h->complete == _sha1_complete);

	if (hval)
		SHA1_Final(hval, (SHA_CTX*)(h+1));
	xfree(h);
}

/*  */
static void _sha1_process(const void * data, size_t dlen, void * hval)
{
	SHA_CTX  temp;

	SHA1_Init(&temp);
	SHA1_Update(&temp, data, dlen);
	SHA1_Final(hval, &temp);
}

/*  */
static hash_val_t * _sha1_instance()
{
	hash_val_t  * h;
	SHA_CTX * ctx;

	h = xalloc(sizeof(hash_val_t) + sizeof(SHA_CTX));
	if (! h)
		return 0;

	ctx = (SHA_CTX*)(h+1);

	h->alg = sha1_alg;
	h->update = _sha1_update;
	h->complete = _sha1_complete;

	SHA1_Init(ctx);

	return h;
}

/*
 *
 */
static hash_alg_t _md5 = { 16, 64, _md5_process, _md5_instance };
static hash_alg_t _sha1 = { 20, 64, _sha1_process, _sha1_instance };

hash_alg_t * md5_alg = &_md5;
hash_alg_t * sha1_alg = &_sha1;

