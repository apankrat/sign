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

#ifndef _SIGN_ALLOC_H_
#define _SIGN_ALLOC_H_

#include "types.h"
#include <string.h>

/*
 *	malloc/free api proxy
 */
realloc_t xrealloc; /* tentative declaration */

#define xalloc(n)    xrealloc(0,(n))
#define xfree(p)     xrealloc((p),0)

#endif

