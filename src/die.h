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

#ifndef _SIGN_DIE_H_
#define _SIGN_DIE_H_

#include "types.h"

/*
 *	terminates an application with exit(rc);
 *	if 'format' is not 0, also issues error() message
 */
void die(int rc, const char * format, ...);

/*
 *	hook called from die() immediately before exit()
 */
void on_die(int ret);

#endif

