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

#ifndef _SIGN_UUENCODE_H_
#define _SIGN_UUENCODE_H_

#include "types.h" /* size_t */

size_t uudecode_len(const void * enc, size_t enc_len);
bool_t uudecode    (const void * enc, size_t enc_len, void * raw);

size_t uuencode_len(size_t raw_len);
void   uuencode    (const void * raw, size_t raw_len, void * enc);

#endif

