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

#ifndef _SIGN_STRING_H_
#define _SIGN_STRING_H_

/*
 *	String operations 
 *
 *	These exist primarily to quiet over-paranoid BSD gcc, which boldly, 
 *	yet very annoyingly declares that strcpy/strcat/sprintf are 'almost 
 *	always misused'. Yeah. Right.
 */
#include "types.h"

char * xstrdup(const char * s);
char * xstrmrg(const char * s1, const char * s2);                /* merge */
char * xstrnmrg(const char * s1, size_t len1, const char * s2);

#endif

