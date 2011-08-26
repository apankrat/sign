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

#include "die.h"
#include "msg.h"
#include <stdlib.h>

/*
 *
 */
void die(int rc, const char * f, ...)
{
	if (f)
	{
		va_list m;
		va_start(m, f);
		vmsg(0, f, m);
		va_end(m);
	}
	on_die(rc);
	exit(rc < 0  ? EXIT_FAILURE : 
	     rc == 0 ? EXIT_SUCCESS : rc);
}

