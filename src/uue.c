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

#include "uue.h"

#include <assert.h>
#include <string.h>

/*
 *
 */
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz"
                          "0123456789+/";

static const char b64_rev[] = 
{
	62,                                                 /* +     */
	-1, -1, -1,                                         
	63,                                                 /* /     */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,             /* 0 - 9 */
	-1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, /* A - Z */
	13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	-1, -1, -1, -1, -1, -1,
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, /* a - z */
	39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
};

/*
 *	decode
 */
size_t uudecode_len(const char * enc, size_t len)
{
	size_t r = 3 * len / 4;
	
	if (! len || (len % 4))
		return -1;

	if (enc[len-1] != '=')
		return r;
	if (enc[len-2] != '=')
		return r-1;
	return r-2;
}

bool_t uudecode(const char * enc, size_t len, char * dec)
{
	const char * e;
	char v;

	assert(len && ! (len % 4));

#define get_next() \
	v = (*enc++); \
	if (v < '+' || 'z' < v) return bfalse; \
	v = b64_rev[v - '+']; \
	if (v == -1) return bfalse; \

	e = enc + len;
	while (enc < e)
	{
		get_next();
		*dec = v << 2;
		if (*enc == '=') break;
			
		get_next();
		*dec |= (v >> 4) & 0x03;
		if (*enc == '=') break;
		*++dec = (v << 4) & 0xF0;

		get_next();
		*dec |= (v >> 2) & 0x0F;
		if (*enc == '=') break;
		*++dec = (v << 6) & 0xC0;

		get_next();
		*dec++ |= v;
	}
#undef get_next

	if (e - enc > 3)
		return bfalse;

	while (++enc < e)
		if (*enc != '=')
			return bfalse;

	return btrue;
}

/*
 *	encode
 */
size_t uuencode_len(size_t len)
{
	return (len + 2) / 3 * 4;
}

void uuencode(const char * raw, size_t len, char * enc)
{
	const char * end = raw + len;
	char v0, v1, v2;
	
	while (raw < end)
	{
		v0 = *raw++;
		v1 = raw < end ? *raw++ : 0;
		v2 = raw < end ? *raw++ : 0;
		*enc++ = b64[ (v0 >> 2) & 0x3F];
		*enc++ = b64[((v0 << 4) & 0x30) | ((v1 >> 4) & 0x0F)];
		*enc++ = b64[((v1 << 2) & 0x3C) | ((v2 >> 6) & 0x03)];
		*enc++ = b64[ (v2 >> 0) & 0x3F];
	}

	switch (len % 3)
	{
	case 1: enc[-2] = '=';
	case 2: enc[-1] = '=';
	}
}


