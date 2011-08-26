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

#ifndef _SIGN_UTILS_H_
#define _SIGN_UTILS_H_

#include "buf.h"
#include "digest.h"
#include <stdio.h>

/*
 *
 */
bool_t  read_file (const char * filename, size_t maxsz, buf_t * buf);
buf_t * parse_file(const buf_t * b, size_t * lines);

bool_t buf_get_tlv(buf_t * buf, int type, size_t len, void * data);
bool_t buf_get_tlb(buf_t * buf, int type, buf_t * data);

/*
 *
 */
size_t xwrite(const void * buf, size_t len, FILE * fh, hash_val_t * h);
size_t xwrite_tlv(int t, size_t l, const void * v, FILE * fh, hash_val_t *h);
size_t xwrite_tlb(int t, const buf_t * data, FILE * fh, hash_val_t *h);

char * xpath(const char * path); /* sys_expand() */
void   xmkdir(const char * path);

bool_t confirm(const char * prompt, ...);

#endif

