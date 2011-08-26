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

#ifndef _DIGEST_ALG_H_
#define _DIGEST_ALG_H_

#include "types.h"  /* size_t */

/*
 *  The longest hash currently defined
 */
#define HASH_max_len  20

typedef struct hash_val        hash_val_t;
typedef const struct hash_alg  hash_alg_t;

/*
 *
 */
struct hash_val
{
	hash_alg_t * alg;

	void (*update)(hash_val_t * h, const void * data, size_t len);
	void (*complete)(hash_val_t * h, void * hval);
};

struct hash_alg
{
	size_t hlen;
	size_t blen;

	void (*process)(const void * data, size_t len, void * hval);
	hash_val_t * (*instance)();
};

/*
 *    The list of currently defined hashing algotihms
 */
extern hash_alg_t * md5_alg;
extern hash_alg_t * sha1_alg;

#endif
