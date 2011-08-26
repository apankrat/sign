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

#ifndef _SIGN_PKI_H_
#define _SIGN_PKI_H_

#include "types.h"
#include "buf.h"
#include "digest.h"

typedef struct pki_pubkey pubkey_t;
typedef struct pki_prikey prikey_t;

/*
 *	core ops
 */
bool_t pki_sign(const buf_t * data, const prikey_t * pk, buf_t * sig);
bool_t pki_verify(const buf_t * data, const pubkey_t * pk, const buf_t * sig);

/*
 *	public key
 */
pubkey_t * pubkey_parse_openssh_blob(const buf_t * buf);
pubkey_t * pubkey_parse_openssh_text(const buf_t * buf);

bool_t     pubkey_store_openssh_blob(const pubkey_t * pk, buf_t * buf);
bool_t     pubkey_store_openssh_text(const pubkey_t * pk, buf_t * buf);

bool_t     pubkey_equal(const pubkey_t * pk1, const pubkey_t * pk2);
bool_t     pubkey_hash (const pubkey_t * pk, hash_alg_t * alg, void * hash);

/*
 *	private key
 */
typedef bool_t (*password_cb)(buf_t * pass, void * arg);
 
prikey_t * prikey_parse_pem(const buf_t * buf, password_cb cb, void * cb_arg);

#endif

