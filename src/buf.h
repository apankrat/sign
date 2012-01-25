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

#ifndef _SIGN_BUF_H_
#define _SIGN_BUF_H_

#include "types.h" /* size_t */

/*
 *
 */
struct buffer
{
	uchar * p;
	uchar * e;
};

typedef struct buffer buf_t;

/*  basic  */
#define buf_size(b)            ((b)->e - (b)->p)
#define buf_reset(b)           ((b)->p = (b)->e = 0)

buf_t * buf_assign(buf_t * b, uchar * p, size_t len);
buf_t * buf_string(buf_t * b, char * s);

/*  alloc  */
void *  buf_alloc (buf_t * b, size_t len);
void *  buf_grow (buf_t * b, size_t inc);
void    buf_free (buf_t * b);
 
/*  search  */
void *  buf_find(const buf_t * b, int (*is)(int));

/*  comparison  */
int     buf_strcmp(const buf_t * b, const char * str);
int     buf_memcmp(const buf_t * b, const void * ptr, size_t len);
int     buf_bufcmp(const buf_t * b, const buf_t * b2);
bool_t  buf_prefix(const buf_t * b, const buf_t * pfx); /* b starts with pfx */

/*  serialization  */
bool_t  buf_parse_len(buf_t * b, size_t * v);  /* 32 bit, msb */
bool_t  buf_parse_str(buf_t * b, buf_t * str); /* len, data   */

bool_t  buf_store_len(buf_t * b, size_t v);
bool_t  buf_store_str(buf_t * b, const void * p, size_t n);

/*  conversion  */
const char * buf_to_hex(const buf_t * b, void * txt, size_t len);

/*
 *	printf() helpers
 */
#define __buf_str(b)           (int)buf_size(b), (int)buf_size(b), (b)->p
#define __buf_hex(b, arr)      buf_to_hex((b), arr, sizeof(arr))


#endif

