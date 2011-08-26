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

#ifndef _SIGN_RESOURCES_H_
#define _SIGN_RESOURCES_H_

/*
 *	control data magic
 */
#define VERSION_MAGIC       "sig1"

/*
 *	file names
 */
#define DIR_ROOT            "~/.sign"
 
#define FILE_PUBLIC_KEY     DIR_ROOT "/pubkey"
#define FILE_PRIVATE_KEY    DIR_ROOT "/prikey"

#define FILE_OWNED_SOURCES  DIR_ROOT "/owned_titles"
#define FILE_KNOWN_SOURCES  DIR_ROOT "/known_titles"

/*
 *	usage, version and license messages
 */
#define MESG_VERSION  \
	"sign, a file signing utility. Version 1.0.7, 07-Aug-2004.\n" \
	"\n"

#define MESG_USAGE   \
"  usage: sign [flags and input files in any order]\n" \
"\n" \
"  -h --help               print this message\n" \
"  -s --sign               create and append the signature\n" \
"  -t --test               verify the signature\n" \
"  -u --unsign             verify and strip the signature\n" \
"\n" \
"  -g --keygen             generate a keypair for signing\n" \
"\n" \
"  -c --stdout             output to standard output\n" \
"  -k --keep               keep (don't delete) input files\n" \
"  -f --force              overwrite existing output files\n" \
"  -v --verbose            increate verbosity level\n" \
"  -L --license            show software license\n" \
"  -V --version            show software version\n" \
"\n" \
"  --title <name>          use this title\n" \
"  --password <pass>       use this private key password\n" \
"  --strict                reject unknown titles\n" \
"  --weak                  accept unknown titles\n" \
"\n"  \
"  If invoked as 'sign',   default action is to sign (create and append sig)" \
"\n" \
"             as 'unsign', default action is to unsign (verify and strip sig)"\
"\n" \
"\n" \
"  If no file names are given, standard input is processed to standard output"\
"\n" \
"  Short flags can be combined, ie '-s -k -f' means the same as '-skf'\n" \
"\n"
	
#define MESG_LICENSE \
"  Copyright (c) 2004 Alex Pankratov. All rights reserved.\n" \
"\n" \
"  This program is free software; you can redistribute it and/or modify\n" \
"  it under the terms set out in the LICENSE file, which is includedi in\n" \
"  the sign-1.0 source distribution.\n" \
"\n" \
"  This program is distributed in the hope that it will be useful,\n" \
"  but WITHOUT ANY WARRANTY; without even the implied warranty of\n" \
"  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n" \
"  LICENSE file for more details.\n" \
"\n"

#endif

