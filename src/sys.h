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

#ifndef _SIGN_SYS_H_
#define _SIGN_SYS_H_

/*
 *	platform-specific file ops
 */
#include "types.h"

/*
 *	
 */
typedef enum
{
	SYS_FTYPE_unknown,
	SYS_FTYPE_file,
	SYS_FTYPE_directory,
	SYS_FTYPE_other

} sys_ftype_e;
 
struct sys_fstat
{
	sys_ftype_e type;
	size_t      size;
};

typedef struct sys_fstat sys_fstat_t;

/*
 *	constants
 */
extern const char   SYS_path_sep;
extern const char * SYS_dev_null;

/*
 *
 */
bool_t sys_check_filename(const char * name);

char * sys_expand(const char * name);

bool_t sys_fstat(const char * name, sys_fstat_t * st);

bool_t sys_copy_fileattr(const char * src, const char * dst);

bool_t sys_rename(const char * from, const char * to);

bool_t sys_unlink(const char * name);

bool_t sys_mkdir(const char * name);

bool_t sys_input(char * buf, size_t buf_len, bool_t echo);

#endif

