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

#include "buf.h"
#include "alloc.h"

#include <stdio.h>
#include <assert.h>

/*
 *	alloc
 */
void * buf_alloc(buf_t * b, size_t len)
{
	void * p = xalloc(len);
	
	if (! p)
		return 0;
	
	return buf_assign(b, p, len);
}

void * buf_grow(buf_t * b, size_t inc)
{
	size_t n = buf_size(b);
	void * p = xrealloc(b->p, n + inc);
	
	if (! p)
		return p;
	
	return buf_assign(b, p, n+inc) + n;
}

void buf_free(buf_t * b)
{
	xfree(b->p);
	b->p = b->e = 0;
}

/*
 *	search
 */
void * buf_find(const buf_t * b, int (*is)(int))
{
	uchar * p;
	for (p = b->p; p < b->e; p++)
		if (is(*p))
			return p;
	return 0;
}

/*
 *	comparison
 */
int buf_strcmp(const buf_t * b, const char * str)
{
	size_t ns = strlen(str);
	size_t nb = b->e - b->p;
	if (nb != ns)
		return nb - ns;
	return memcmp(b->p, str, ns);
}

int buf_memcmp(const buf_t * b, const void * ptr, size_t np)
{
	size_t nb = buf_size(b);
	if (nb != np)
		return nb - np;
	return memcmp(b->p, ptr, np);
}

int buf_bufcmp(const buf_t * b1, const buf_t * b2)
{
	return buf_memcmp(b1, b2->p, b2->e - b2->p);
}
  
bool_t buf_prefix(const buf_t * b, const buf_t * pfx)
{
	size_t np = buf_size(pfx);
	return np <= buf_size(b) &&
	       memcmp(b->p, pfx->p, np) == 0;
}

/*
 *	serialization
 */
bool_t buf_parse_len(buf_t * b, size_t * v)
{
	int i;
	if (buf_size(b) < 4)
		return bfalse;
		
	*v = 0;
	for (i=0; i<4; i++)
		*v = (*v << 8) | *(uchar*)b->p++;

	return *v <= buf_size(b);
}

bool_t buf_parse_str(buf_t * b, buf_t * str)
{
	size_t len;
	if (! buf_parse_len(b, &len))
		return bfalse;

	buf_assign(str, b->p, len);
	b->p += len;
	return btrue;
}

bool_t buf_store_len(buf_t * b, size_t v)
{
	int i;

	if (! buf_grow(b, 4))
		return bfalse;
		
	for (i=-1; -5<i; i--, v >>= 8)
		b->e[i] = v & 0xff;

	return btrue;
}

bool_t buf_store_str(buf_t * b, const void * p, size_t n)
{
	if (! buf_store_len(b, n) || ! buf_grow(b, n))
		return bfalse;
		
	memcpy(b->e - n, p, n); 
	return btrue;
}

const char * buf_to_hex(const buf_t * data, void * str, size_t len)
{
	int i, n = buf_size(data);
	char * p = str,
	     * e = str + len;
	
	assert(3*n <= len);
	if (! n || len < 3*n)
		return 0;
	
	for (i=0; i<n; i++)
	{
		if (i) *p++ = ':';
		p += snprintf(p, e-p, "%02x", 0xff & (unsigned)data->p[i]);
	}
	*p = 0;

	return str;
}

