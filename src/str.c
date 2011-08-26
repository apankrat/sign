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

#include "str.h"
#include "alloc.h"

char * xstrdup(const char * s)
{
	size_t n = strlen(s);
	char * r = xalloc(n+1);

	if (!r)
		return 0;
	memcpy(r, s, n);
	r[n] = 0;
	return r;
}

char * xstrmrg(const char * s1, const char * s2)
{
	return xstrnmrg(s1, strlen(s1), s2);
}

char * xstrnmrg(const char * s1, size_t n1, const char * s2)
{
	size_t n2 = strlen(s2);
	char * r = xalloc(n1 + n2 + 1);
	
	if (! r)
		return 0;
	memcpy(r, s1, n1);
	memcpy(r+n1, s2, n2);
	r[n1+n2] = 0;
	return r;
}

