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

/*
 *	system-specific API
 */
#include "sys.h"
#include "str.h"

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <pwd.h>
#include <utime.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 *	constant
 */
const char   SYS_path_sep = '/';
const char * SYS_dev_null = "/dev/null";

/*
 *
 */
bool_t sys_check_filename(const char * name)
{
	return name && name[0] && name[0] != '.' && name[1] != '.';
}

char * sys_expand(const char * name)
{
	struct passwd * pw;
	
	if (name[0] != '~')
		return xstrdup(name);
	assert(name[1] == SYS_path_sep); /* no support for '~uname/..' */

	pw = getpwuid(getuid());
	if (! pw)
		return 0;
	
	return xstrmrg(pw->pw_dir, name+1);
}

bool_t sys_fstat(const char * name, sys_fstat_t * fs)
{
	struct stat st;
	if (stat(name, &st) < 0)
	{
		fs->type = SYS_FTYPE_unknown;
		fs->size = -1;
		return errno != ENOENT;
	}

	if (S_ISREG(st.st_mode))
		fs->type = SYS_FTYPE_file;
	else
	if (S_ISDIR(st.st_mode))
		fs->type = SYS_FTYPE_directory;
	else
		fs->type = SYS_FTYPE_other;

	fs->size = st.st_size;
	return btrue;
}

bool_t sys_copy_fileattr(const char * src, const char * dst)
{
	struct stat    st;
	struct utimbuf ut;

	if (stat(src, &st) < 0)
		return bfalse;

	if (chmod(dst, st.st_mode) < 0)
		return bfalse;

	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime;
	if (utime(dst, &ut) < 0)
		return bfalse;

	chown(dst, st.st_uid, st.st_gid);
	return btrue;
}

bool_t sys_rename(const char * from, const char * to)
{
	return rename(from, to) == 0;
}

bool_t sys_unlink(const char * name)
{
	return unlink(name) == 0;
}

bool_t sys_mkdir(const char * name)
{
	return mkdir(name, 0700) == 0;
}
