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

#ifndef _SIGN_TYPES_H_
#define _SIGN_TYPES_H_

/*
 *	u_char, size_t, bool_t, realloc_t
 */
#include <stddef.h> 

typedef unsigned char uchar;

typedef enum { bfalse, btrue } bool_t;

typedef void * (*realloc_t)(void *, size_t);

#endif

