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

#include "util.h"

#include "alloc.h"
#include "die.h"
#include "sys.h"

#include <assert.h>
#include <string.h>
#include <stdarg.h>

/*
 *	utility functions
 */
bool_t read_file(const char * filename, size_t maxsz, buf_t * buf)
{
	char * fn;
	sys_fstat_t st;
	FILE * fh;
	bool_t r = bfalse;

	/*  */
	fn = sys_expand(filename);
	if (! fn)
		return bfalse;

	if (! sys_fstat(fn, &st) || st.type != SYS_FTYPE_file)
		goto free;
		
	if (st.type != SYS_FTYPE_file || 
	    st.size <= 0 || maxsz < st.size)
		goto free;

	fh = fopen(fn, "r");
	if (! fh)
		goto free;
	
	if (! buf_alloc(buf, st.size))
		goto close;
		
	if (fread(buf->p, 1,  st.size, fh) != st.size)
		goto close;
		
	r = btrue;

close:
	fclose(fh);
free:
	xfree(fn);
	return r;
}


static int is_crlf(int ch)
{
	return (ch == '\r') || (ch == '\n');
}

buf_t * parse_file(const buf_t * buf, size_t * lines)
{
	buf_t b = *buf;
	buf_t * tmp, * r = 0;
	int n = 0;
	uchar * p;

	while (buf_size(&b))
	{
		p = buf_find(&b, is_crlf);
		p = p ? p : b.e;
		
		if (p - b.p < 1)
			goto next;

		tmp = xrealloc(r, sizeof(*r) * (n+1));
		if (! tmp)
		{
			xfree(r);
			return 0;
		}
		r = tmp;
		r[n].p = b.p;
		r[n].e = p;
		n++;
next:
		/* skip line separator(s) */
		for (b.p = p; buf_size(&b) && is_crlf(*b.p); b.p++);
	}

	*lines = n;
	return r;
}

/*
 */
#define get16(p) \
	( (((unsigned char *)(p))[0] << 8) | \
	   ((unsigned char *)(p))[1] )

bool_t buf_get_tlv(buf_t * buf, int type, size_t len, void * data)
{
	size_t blen;
	if (buf_size(buf) < 3 + len ||
	    buf->p[0] != type)
	    	return bfalse;

	blen = get16(buf->p+1);
	if (blen != len)
	    	return bfalse;

	memmove(data, buf->p+3, len);
	buf->p += 3 + len;
	return btrue;
}

bool_t buf_get_tlb(buf_t * buf, int type, buf_t * data)
{
	size_t len;
	
	if (buf_size(buf) < 3 || buf->p[0] != type)
	    	return bfalse;

	len = get16(buf->p+1);
	if (buf_size(buf) < 3 + len)
		return bfalse;
		
	data->p = buf->p + 3;
	data->e = data->p + len;
	buf->p += 3 + len;
	return btrue;
}

/*
 *	functions that don't fail (they choose to die())
 */
size_t xwrite(const void * buf, size_t len, FILE * fh, hash_val_t * h)
{
	if (h)
		h->update(h, buf, len);

	if (! fh)
		return len;  /* dev_null */
		
	if (fwrite(buf, 1, len, fh) != len)
		die(-1, "write error");
	return len;
}

size_t xwrite_buf(const buf_t * buf, FILE * fh, hash_val_t * h)
{
	return xwrite(buf->p, buf_size(buf), fh, h);
}

size_t xwrite_tlv(int t, size_t l, const void * v, FILE * fh, hash_val_t *h)
{
	unsigned char buf[3];

	if (t > 0xff || l > 0xffff)
		die(-1, "printer is on fire"); /* should not happen */
	
	buf[0] = t;
	buf[1] = (l >> 8) & 0xff;
	buf[2] = (l     ) & 0xff;

	return xwrite(buf, 3, fh, h) + xwrite(v, l, fh, h);
}

size_t xwrite_tlb(int t, const buf_t * data, FILE * fh, hash_val_t * h)
{
	return xwrite_tlv(t, buf_size(data), data->p, fh, h);
}

char * xpath(const char * path)
{
	char * fn = sys_expand(path);
	if (! fn)
		die(-1, "guru meditation error");
	return fn;
}

void xmkdir(const char * path)
{
	sys_fstat_t st;
	char * fn;

	/*   */
	fn = xpath(path);

	if (sys_fstat(fn, &st))
	{
		if (st.type != SYS_FTYPE_directory)
			die(-1, "%s exists and it's not a directory", fn);
	}
	else
	{
		if (! sys_mkdir(fn))
			die(-1, "failed to create directory %s", fn);
	}
	xfree(fn);
}

/*
 *
 */
bool_t confirm(const char * prompt, ...)
{
	va_list m;
	char buf[32] = { 0 };

	va_start(m, prompt);
	vfprintf(stderr, prompt, m);
	va_end(m);
	
	for (;;)
	{
		fflush(stderr);
		if (! sys_input(buf, sizeof buf - 1, btrue))
			die(-1, 0);
		if (! strcasecmp(buf, "no"))
			return bfalse;
		if (! strcasecmp(buf, "yes"))
			return btrue;
		fprintf(stderr, "Please type 'yes' or 'no': ");
	}
}

