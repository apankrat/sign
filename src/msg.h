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

#ifndef _SIGN_MESSAGE_H_
#define _SIGN_MESSAGE_H_

#include "types.h"
#include <stdarg.h>

/*
 *	logging
 */
void error(const char * format, ...); /* verbosity - any */
void warn (const char * format, ...); /* verbosity > 0   */
void info (const char * format, ...); /* verbosity > 1   */
void trace(const char * format, ...); /* verbosity > 2   */

void vmsg (int level, const char * format, va_list va);

/*
 *
 */
extern const char * __name; /* invokation name */
extern int          __verb; /* verbosity level */

#endif

