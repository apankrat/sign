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

#include "msg.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void error(const char * f, ...)
{
	va_list m;
	va_start(m, f);
	vmsg(0, f, m);
	va_end(m);
}

void warn(const char * f, ...)
{
	va_list m;
	va_start(m, f);
	vmsg(1, f, m);
	va_end(m);
}

void info(const char * f, ...)
{
	va_list m;
	va_start(m, f);
	vmsg(2, f, m);
	va_end(m);
}

void trace(const char * f, ...)
{
	va_list m;
	va_start(m, f);
	vmsg(3, f, m);
	va_end(m);
}

void vmsg(int level, const char * f, va_list m)
{
	if (level > __verb)
		return;
	
	fprintf(stderr, "%s: ", __name);
	vfprintf(stderr, f, m);
	fprintf(stderr, "\n");
}

/*
 *
 */
const char * __name = "sign";
int          __verb = 0;

