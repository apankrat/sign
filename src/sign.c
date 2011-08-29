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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "sign.h"

/*
 *
 */
typedef enum 
{
	OUTPUT_unknown,
	OUTPUT_file,
	OUTPUT_null,
	OUTPUT_stdout
} output_e;

typedef enum
{
	MODE_unknown,
	MODE_sign,
	MODE_test,
	MODE_unsign,
	MODE_keygen
} mode_e;

typedef enum
{
	HASH_unknown,
	HASH_sha1
/*	HASH_md5,   */
/*	HASH_tiger, */
/*	HASH_ripemd */
} hash_e;

typedef enum
{
	CHECK_unknown,
	CHECK_weak,
	CHECK_ask,
	CHECK_strict
} check_e;

typedef enum
{
	TLV_unknown,
	TLV_version,
	TLV_hashalg,
	TLV_title,
	TLV_pubkey,
	TLV_sig_sha1
} tlv_e;

typedef enum
{
	RC_success = 0,  /* die() notation */
	RC_failure = 1,  /* die() notation */

	RC_no_ctl        = 10, /* no control block               */
	RC_bad_ctl       = 11, /* malformed control block        */
        RC_bad_title     = 12, /* mismatching title              */
	RC_bad_sig       = 13, /* mismatching signature          */
	RC_bad_pubkey    = 14, /* pubkey is different from remembered */
	RC_unk_pubkey    = 15  /* pubkey is not on the trusted list   */

} retcode_e;

/*
 *
 */
struct title
{
	buf_t     name;
	pubkey_t * pub;
};

typedef struct title title_t;

/*
 *
 */
struct state
{
	const char * name; /* invokation name  */

	/* command-line parameters */	
	int keep;          /* keep input */
	int force;         /* overwrite output */
	
	output_e  output;  /* file, null, stdout */
	mode_e    mode;    /* sign, test, unsign */

	const char ** in;  /* input file names */
	int in_n;

	/* unsign config */
	struct
	{
		buf_t     known_buf;
		title_t * known;     /* known titles */
		int       known_n;
		check_e   check;
		size_t    tail;      /* max control block size */
	} u;

	/* sign config */
	struct 
	{
		buf_t        title;  /* --title    */
		const char * pass;   /* --password */
		hash_e       hash;   /* --hash     */

		int          pass_tries;
		pubkey_t   * pub;
		prikey_t   * pri;
		buf_t        owned_buf;
		buf_t      * owned;  /* owned titles */
		size_t       owned_n;
	} s;

	/* run-time data */
	const char * out;
	int    idx;
	FILE * ifh;
	FILE * ofh;
};

typedef struct state state_t;

state_t * ctx;
static unsigned char buffer[32*1024];

/*
 *
 */
#define sizeof_array(a) sizeof(a)/sizeof(a[0])

/*
 *
 */
void usage(void);
void license(void);
void version(void);

void init_defaults(void);
int  map_long_arg(const char * str);
void parse_args(int argc, char ** argv);
void load_s_config(void); /* sign   */
void load_u_config(void); /* unsign */
void process(void);
void finalize(void);
void on_die(int rc);

char * make_sname(const char * org);
char * make_uname(const char * org);
bool_t get_passwd(buf_t * pass, void * arg);

void do_sign(void);
void do_unsign(void);
void do_keygen(void);

/*
 *
 */
void * realloc_or_die(void * p, size_t n)
{
	p = realloc(p, n);
	if (n && !p)
		die(-1, "out of memory");
	return p;
}

void on_signal(int sig)
{
	fprintf(stderr, "\n");
	die(-1, 0);
}
 
int main(int argc, char ** argv)
{
	state_t the_state;
	char * p;

	/* it's a cruel world */
	xrealloc = realloc_or_die;
	
	signal(SIGINT,  on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGHUP,  on_signal);

	/* reset */
	ctx = &the_state;
	memset(ctx, 0, sizeof(*ctx));

	/* set invokation name */
	p = strrchr(argv[0], SYS_path_sep);
	ctx->name = p ? p+1 : argv[0];

	/* set defaults based on it */
	init_defaults();

	/* parse arguments */
	parse_args(argc, argv);

	/* keygen is here on a temporary basis, it'll be moved */
	if (ctx->mode == MODE_keygen)
	{
		do_keygen();
		return 0;
	}
	
	/* finalize configuration */
	if (ctx->mode == MODE_sign)
		load_s_config();
	else
		load_u_config();

	/* process files */
	process();

	/*  */
	finalize();

	/* cleanup */
	on_die(0);

	return 0;
}

/*
 *
 */
void version(void)
{
	fprintf(stderr, MESG_VERSION);
}

void usage(void)
{
	version();
	fprintf(stderr, MESG_USAGE);
}

void license(void)
{
	version();
	fprintf(stderr, MESG_LICENSE);
}

/*
 *
 */
void init_defaults(void)
{
	if (! strcmp(ctx->name, "unsign"))
		ctx->mode = MODE_unsign;
	else
	if (! strcmp(ctx->name, "sign-keygen"))
		ctx->mode = MODE_keygen;
	else
		ctx->mode = MODE_sign;

	ctx->output = OUTPUT_file;
}

int map_long_arg(const char * str)
{
	static struct 
	{
		int    val;
		char * str;
	} map[] =
	{
		{ 'h', "help" },
		{ 'k', "keep" },
		{ 'f', "force" },
		{ 'c', "stdout" },
		{ 'v', "verbose" },
		{ 'L', "license" },
		{ 'V', "version" },
		{ 's', "sign" },
		{ 't', "test" },
		{ 'u', "unsign" },
		{ 'g', "keygen" },
		
		{ '\1', "title" },
		{ '\2', "password" },
		{ '\5', "strict" },
		{ '\6', "weak" },
/*		{ '\7', "tail" }, */
		{ 0 }
	};
	int i;

	for (i=0; map[i].str; i++)
		if (! strcmp(map[i].str, str))
			return map[i].val;
	return -1;
}

void parse_args(int argc, char ** argv)
{
	int i, decode = 1;
	char * p, * q, arg[] = "x";

	for (i=1; i<argc; i++)
	{
		/* file name */
		if (argv[i][0] != '-' || !decode)
		{
			ctx->in = xrealloc(ctx->in, ++ctx->in_n*sizeof(char*));
			ctx->in[ctx->in_n-1] = argv[i];
			continue;
		}
			
		/* an option */
		if (argv[i][1] == '-') /* long option */
		{
			if (! argv[i][2]) /* -- option list terminator */
			{
				decode = 0;
				continue;
			}
			
			p = arg;
			*p = map_long_arg(argv[i]+2);
		}
		else
			p = argv[i]+1;

		for (; *p; p++)
			switch (*p)
			{
			case 'k': ctx->keep = 1; break;
			case 'f': ctx->force = 1; break;
			case 'c': ctx->output = OUTPUT_stdout; break;
			case 'v': __verb++; break;

			case 's': ctx->mode = MODE_sign; break;
			case 't': ctx->mode = MODE_test; break;
			case 'u': ctx->mode = MODE_unsign; break;
			case 'g': ctx->mode = MODE_keygen; break;
		
			case '?':
			case 'h': usage();   die(0, 0);
			case 'L': license(); die(0, 0);
			case 'V': version(); die(0, 0);

			case '\1': /* --title */
				if (p[1] || i+1 == argc)
					goto no_parm;
				
				q = argv[++i];
				buf_string(&ctx->s.title, q);
				break;
			
			case '\2': /* --password */
			
				if (p[1] || i+1 == argc)
					goto no_parm;

				ctx->s.pass = argv[++i];
				break;

			case '\5': ctx->u.check = CHECK_strict; break;
			case '\6': ctx->u.check = CHECK_weak; break;
			
			default:
				error("bad flag %s", argv[i]);
				usage();
				die(-1, 0);
			}
		
		continue;
no_parm:
		die(-1, "%s is not followed by an argument", argv[i]);
	}
}

/*
 *
 */
void load_s_config(void)
{
	buf_t  buf;
	bool_t need_titles;

	/* must have --title if reading from stdin */
	if (! ctx->in && ! buf_size(&ctx->s.title))
		die(-1, "--title is required when using stdin");

	/* --check is useless */
	if (ctx->u.check)
		warn("--strict and/or --weak have no effect");

	/* set defaults */
	if (! ctx->s.hash)
		ctx->s.hash = HASH_sha1;

	ctx->s.pass_tries = 0;

	/* load owned_titles */
	need_titles = ! buf_size(&ctx->s.title);
		
	if (! read_file(FILE_OWNED_SOURCES, 16*1024, &ctx->s.owned_buf))
	{
		if (! need_titles)
			goto load_keys;
			
		error("failed to load title list '%s'", FILE_OWNED_SOURCES);
		die(-1, "cannot figure out what title to use (did you forget "
		        "--title ?)");
	}

	ctx->s.owned = parse_file(&ctx->s.owned_buf, &ctx->s.owned_n);
	if (! ctx->s.owned && need_titles)
	{
		error("title list '%s' is empty", FILE_OWNED_SOURCES);
		die(-1, "cannot figure out what title to use (did you forget "
		        "--title ?)");
	}

load_keys:
	/* load public key */
	if (! read_file(FILE_PUBLIC_KEY, 16*1024, &buf))
	{
		error("failed to read public key from %s", FILE_PUBLIC_KEY);
		die(-1,"did you run 'sign --keygen' ?");
	}

	ctx->s.pub = pubkey_parse_openssh_text(&buf);
	if (! ctx->s.pub)
		die(-1, "failed to load pubkey from %s", FILE_PUBLIC_KEY);
		
	buf_free(&buf);

	/* load private key */
	if (! read_file(FILE_PRIVATE_KEY, 16*1024, &buf))
	{
		error("failed to read private key from %s", FILE_PRIVATE_KEY);
		die(-1,"did you run 'sign --keygen' ?");
	}

	ctx->s.pri = prikey_parse_pem(&buf, get_passwd, ctx);
	if (! ctx->s.pri)
		die(-1, "failed to load prikey from %s", FILE_PRIVATE_KEY);
	
	buf_free(&buf);
}

void load_u_config(void)
{
	buf_t * tmp;
	size_t  n, i;
	char *  p;

	/* check few things */
	if (buf_size(&ctx->s.title))
		warn("--title has no effect");
		
	if (ctx->s.pass)
		warn("--password has no effect");
		
	/* set defaults */
	if (! ctx->u.check)
		ctx->u.check = ctx->in ? CHECK_ask : CHECK_strict;

	if (! ctx->u.tail)
		ctx->u.tail = 4*1024; /* estimated max control data size */

	if (ctx->mode == MODE_test)
		ctx->keep = 1;

	/* load known_titles */ 
	if (! read_file(FILE_KNOWN_SOURCES, 16*1024, &ctx->u.known_buf))
		goto done;

	tmp = parse_file(&ctx->u.known_buf, &n);
	if (! tmp)
		goto done;

	ctx->u.known = xrealloc(ctx->u.known, sizeof(title_t)*n);

	for (i=0; i<n; i++)
	{
		buf_t * b = tmp+i;
		title_t t;

		/* skip leading whitespace */
		while (buf_size(b) && isspace(*b->p))
			b->p++;
		
		/* find first separator */
		p = buf_find(b, isspace);
		if (! p)
			die(-1, "%s, line %d is malformed", 
				FILE_KNOWN_SOURCES, i+1);

		t.name.p = b->p;
		t.name.e = p;
		
		b->p = p+1;

		/* skip whitespace */
		while (buf_size(b) && isspace(*b->p))
			b->p++;

		t.pub = pubkey_parse_openssh_text(b);
		if (! t.pub)
			die(-1, "cannot load key %d from %s", i+1, 
				FILE_KNOWN_SOURCES);

		ctx->u.known[i] = t;	

	}
	ctx->u.known_n = i;

done:
	;
}

/*
 *
 */
void process(void)
{
	sys_fstat_t st;
	const char * in;
	char * out;
	int i;
	
	char * (*make_name) (const char *) = 0;
	void   (*do_process)(void) = 0;

	switch (ctx->mode)
	{
	case MODE_sign:
		make_name = make_sname;   
		do_process = do_sign;
		break;
	case MODE_test:
		make_name = 0;
		do_process = do_unsign;
		break;
	case MODE_unsign:
		make_name = make_uname;
		do_process = do_unsign;
		break;
	default:
		assert(0);
	}

	i = 0;
	do
	{
		in = out = 0;
		ctx->idx = i;
		
		/* do some checks when data comes from the file */
		if (ctx->in)
		{
			in = ctx->in[i];
			
			/* input file */
			if (! sys_check_filename(in))
				die(-1, "illegal filename '%s'", in);

			if (! sys_fstat(in, &st))
				die(-1, "'%s' doesn't exist", in);

			if (st.type == SYS_FTYPE_unknown)
				die(-1, "'%s' exists but not accesible", in);

			if (st.type != SYS_FTYPE_file)
				die(-1, "'%s' is not a file", in);
		}

		/* more check when output goes into the file */
		if (in && make_name && ctx->output != OUTPUT_stdout)
		{
			/* output file */
			ctx->out = out = (*make_name)(in);
			assert(out);
			
			if (! sys_fstat(out, &st))
				goto do_open;
				
			if (! ctx->force)
				die(-1, "output '%s' already exists", out);
			else
			if (st.type == SYS_FTYPE_unknown)
				die(-1, "output '%s' is not accessible", out);
			else
			if (st.type == SYS_FTYPE_directory)
				die(-1, "output '%s' is a directory", out);
			else
			if (st.type != SYS_FTYPE_file)
				die(-1, "output '%s' is not a regular file", 
					out);
		}
		
do_open:
		/* ok, let's open the source .. */
		ctx->ifh = in ? fopen(in, "r") : stdin;
		if (! ctx->ifh)
			die(-1, "failed to open input file '%s'", in);

		/* .. and dest */
		if (make_name) /* not a MODE_test */
		{
			ctx->ofh = out ? fopen(out, "w") : stdout;
			if (! ctx->ofh)
				die(-1, "failed to open output file '%s'", out);
		}

		/* process */
		if (in)
			info("%s", in);

		(*do_process)();

		/* close and clean up */
		if (in)
			fclose(ctx->ifh);
		ctx->ifh = 0;

		if (out)
		{
			fclose(ctx->ofh);
			sys_copy_fileattr(in, out); /* copy attr and owner */
			xfree(out);
			ctx->out = 0;
		}
		ctx->ofh = 0;

		if (in && ! ctx->keep &&
		    ! sys_unlink(in))
			die(-1, "failed to remove source file '%s'", in);
	}
	while (++i < ctx->in_n);
}

void finalize(void)
{
	buf_t * new_t = &ctx->s.title;
	buf_t * old_t;
	int i, pos = -1;
	char * fn;
	FILE * fh;

	/*
	 *	if signing and title is not in owned_titles, ask if 
	 *	to add it there
	 */	
	if (ctx->mode != MODE_sign)
		return;
		
	if (! buf_size(new_t) || ! ctx->in)
		return;

	/* figure out where to place it */
	for (i=0; i<ctx->s.owned_n; i++)
	{
		old_t = ctx->s.owned + i;

		if (! buf_bufcmp(new_t, old_t)) /* exact match */
			return;

		if (buf_prefix(new_t, old_t) && pos < 0)  
			/* new starts with old */
			pos = i;
	}
	if (pos < 0)
		pos = i;

	if (! confirm(
		"Completed processing the input.\n"
		"Would you like to add title '%*.*s' to the list of owned "
		"titles (yes/no)? ", __buf_str(new_t)))
		return;

	/* ok, add it */
	xmkdir(DIR_ROOT);
	
	fn = xpath(FILE_OWNED_SOURCES);
	fh = fopen(fn, "w");
	if (! fh)
		die(-1, "failed to open %s for updating", fn);

	for (i=0; i<pos; i++)
		fprintf(fh, "%*.*s\n", __buf_str(ctx->s.owned + i));

	fprintf(fh, "%*.*s\n", __buf_str(new_t));

	for ( ; i<ctx->s.owned_n; i++)
		fprintf(fh, "%*.*s\n", __buf_str(ctx->s.owned + i));
	
	fclose(fh);
}

void on_die(int rc)
{
	if (ctx->ofh) /* we're dying in the middle of process() */
	{
		fclose(ctx->ofh);
		sys_unlink(ctx->out);
	}
}

/*
 *
 */
char * make_sname(const char * org)
{
	return xstrmrg(org, ".signed");
}

char * make_uname(const char * org)
{
	static struct {
		char * org;
		char * sig;
		int    len; /* sig len */
	} exts[] = {
		{ ".gz",   ".sgz",    4 },
		{ ".bz",   ".sbz" ,   4 },
		{ ".bz2",  ".sbz2",   5 },
		{ ".tgz",  ".stgz",   5 },
		{ ".tbz",  ".stbz",   5 },
		{ ".tbz2", ".stbz2",  6 },
		{ "",      ".signed", 7 }
	};

	int i, tmp, len = strlen(org);
	char * out;

	for (i=0; i<sizeof_array(exts); i++)
	{
		tmp = exts[i].len;
		if (tmp < len && !memcmp(org + len - tmp, exts[i].sig, tmp))
			break;
	}

	if (i == sizeof_array(exts))
	{
		out = xstrmrg(org, ".out");
		error("cannot guess original name for '%s' -- using '%s'", 
			org, out);
	}
	else
	{
		out = xstrnmrg(org, len - tmp, exts[i].org);
	}
	
	return out;
}

bool_t get_passwd(buf_t * pass, void * arg)
{
	const char * p;
	char buf[128];
	int len;
	
	assert(arg == ctx);


	/* --password */
	if (ctx->s.pass)
	{
		if (ctx->s.pass_tries)
			die(-1, "Private key password is incorrect");

		p = ctx->s.pass;
		goto ok;
	}

	/* cannot do interactive password prompt with piped input */
	if (! ctx->in)
	{
		die(-1, "Private key is encrypted; please provide the "
		        "password using --password option or use interactive "
			"mode");
	}

	if (ctx->s.pass_tries)
		fprintf(stderr, "Password is incorrect\n");
		
	/* limit number of password prompts */
	if (ctx->s.pass_tries > 3)
		return bfalse;

	fprintf(stderr, "Password for %s: ", FILE_PRIVATE_KEY);
	if (! sys_input(buf, sizeof buf, bfalse))
		return bfalse;
	
	p = buf;
ok:	
	len = strlen(p);
	if (! buf_alloc(pass, len))
		return bfalse;

	memcpy(pass->p, p, len);
	ctx->s.pass_tries++;
	return btrue;
}

/*
 *
 */
void do_sign(void)
{
	int i, n, ext, hlen;

	const buf_t * title = 0;
	const char * p, * in = 0;
	buf_t in_buf;
	
	hash_val_t * h;
	buf_t  hash, tmp;

	/*  */
	assert(ctx->ifh);
	assert(ctx->ofh);

	/* get source filename */
	if (ctx->in)
	{
		in = ctx->in[ctx->idx];
		p = strrchr(in, SYS_path_sep);
		p = p ? p+1 : in;
		buf_string(&in_buf, (void*)p);
	}

	/* find appropriate title */
	if (! buf_size(&ctx->s.title))
	{
		assert(ctx->in); /* --title is required with stdin */

		for (i=0; i<ctx->s.owned_n; i++)
			if (buf_prefix(&in_buf, ctx->s.owned + i))
			{
				title = ctx->s.owned + i;
				break;
			}
		if (! title)
			die(-1, "cannot find matching title for '%s'", in);
	}
	else
	{
		title = &ctx->s.title;

		/* check that filename starts with the title */
		if (ctx->in && ! buf_prefix(&in_buf, title))
			die(-1, "input file name '%s' does not start with "
			        "title '%s'", in, title->p);
	}

	if (0xFFFF < buf_size(title))
		die(-1, "title '%s' is too long", title);
		
	info("using '%*.*s' title", __buf_str(title));

	/* prep hash instance */
	assert(ctx->s.hash == HASH_sha1);

	h = sha1_alg->instance();
	hlen = h->alg->hlen;

	/* copy the file */
	while (! feof(ctx->ifh))
	{
		n = fread(buffer, 1, sizeof buffer, ctx->ifh);
		if (n < 0)
			die(-1, "read error");
		xwrite(buffer, n, ctx->ofh, h);
	}

	/* append version */
	ext = xwrite_tlv(TLV_version, 4, VERSION_MAGIC, ctx->ofh, h);
	
	/* append title */
	ext += xwrite_tlb(TLV_title, title, ctx->ofh, h);

	/* append pub key */
	if (! pubkey_store_openssh_blob(ctx->s.pub, &tmp))
		die(-1, "store_openssh() failed");
	
	ext += xwrite_tlb(TLV_pubkey, &tmp, ctx->ofh, h);

	buf_free(&tmp);

	/* compute the hash */
	h->complete(h, buffer);

	buf_assign(&hash, buffer, hlen);

	/* sign it */
	if (! pki_sign(&hash, ctx->s.pri, &tmp))
		die(-1, "pki_sign() failed");

	/* write hash and sig out */
	ext += xwrite_tlb(TLV_sig_sha1, &tmp, ctx->ofh, 0);

	buf_free(&tmp);

	/* write the size of control data */
	for (i=0; i<4; i++)
		buffer[i] = ext >> (24 - 8*i);
	xwrite(buffer, 4, ctx->ofh, 0);
	
	/* dump hash for curious ones */
	info("hash is %s", buf_to_hex(&hash, buffer+20, 128));
}

void do_unsign(void)
{
	const size_t buf_max = sizeof buffer;

	int i, n, len, total, hlen;
	char ver[4], hval[HASH_max_len];
	char hex[3*HASH_max_len];
	const void * in;
	hash_val_t * h;
	pubkey_t * pubkey;
	buf_t ctl, title, key, sig;
	buf_t hash, kfp, tmp;
	
	/*  */
	assert(ctx->ifh);
	assert(ctx->ofh || ctx->mode == MODE_test);

	/*
	 * an assumption here is that the size of the control data is
	 * less than 'tail' bytes so we are going to pump all data, but 
	 * the tail from in to out, and deal with the last bytes separately
	 */
	h = sha1_alg->instance();
	hlen = h->alg->hlen;
	
	/* copy the file */
	total = len = 0;
	while (! feof(ctx->ifh))
	{
		n = fread(buffer + len, 1, buf_max - len, ctx->ifh);
		if (n < 0)
			die(-1, "read error");

		len += n;
		if (len > ctx->u.tail)
		{
			n = len - ctx->u.tail;
			total += xwrite(buffer, n, ctx->ofh, h);
			memmove(buffer, buffer + n, len - n);
			len = ctx->u.tail;
		}
	}

	/* got a leftover of 'tail' bytes or less */
	if (len < 4)
		die(RC_no_ctl, "input file contains no signature");

	n =  buffer[len-1] | 
	    (buffer[len-2] << 8) |
	    (buffer[len-3] << 16) |
	    (buffer[len-4] << 24);
	len -= 4;

	if (n <=0 || total + len < n)
		die(RC_no_ctl, "input file contains no signature");

	if (len < n)
		die(RC_no_ctl, "signature is either corrupted or too long "
		               "(%ld bytes)", n);

	/* write residual data */
	if (n < len)
		xwrite(buffer, len-n, ctx->ofh, 0);

	/* initialize control data block */
	ctl.p = buffer + len - n;
	ctl.e = ctl.p + n;

	/* parse ctl data */

	/* version */
	if (! buf_get_tlv(&ctl, TLV_version, 4, ver))
		die(RC_no_ctl, "input file contains no valid signature");

	if (memcmp(ver, VERSION_MAGIC, 4))
		die(RC_bad_ctl, "unknown signature format");

	if (! buf_get_tlb(&ctl, TLV_title, &title))
		die(RC_bad_ctl, "signature is corrupted (title)");

	if (! buf_get_tlb(&ctl, TLV_pubkey, &key))
		die(RC_bad_ctl, "signature is corrupted (pubkey)");

	h->update(h, buffer, ctl.p - buffer); /* hash the rest of data and   */
	h->complete(h, hval);                 /* .. parts of the control blk */
	
	if (! buf_get_tlb(&ctl, TLV_sig_sha1, &sig))
		die(RC_bad_ctl, "signature is corrupted (sig)");

	/* do checks */
	if (ctx->in)
	{
		in = ctx->in[ctx->idx];
		buf_string(&tmp, (void*)in);
		if (! buf_prefix(&tmp, &title))
			die(RC_bad_title, 
			    "the title '%*.*s' in the signature does not "
			    "match file name '%s'", __buf_str(&title), in);
	}

	pubkey = pubkey_parse_openssh_blob(&key);
	if (! pubkey)
		die(RC_bad_ctl, "signature is corrupted (blob)"); 

	/* digest */
	buf_assign(&hash, hval, hlen);

	if (! pki_verify(&hash, pubkey, &sig))
		die(RC_bad_sig, "the digest is incorrect !");

	/* no residue */
	if (buf_size(&ctl))
		die(RC_bad_ctl, "signature is corrupted (tail)");

	/* prep key fingerprint */
	pubkey_hash(pubkey, md5_alg, hval);

	buf_assign(&kfp, hval, md5_alg->hlen);

	/* signature is ok, now's let's check if we know the title */
	for (i=0; i<ctx->u.known_n; i++)
		if (! buf_bufcmp(&title, &ctx->u.known[i].name))
			break;

	/* known title */
	if (i < ctx->u.known_n)
	{
		/* let's see if pubkey matches */
		if (pubkey_equal(ctx->u.known[i].pub, pubkey))
			goto accept;
			
		/* ALARMA ! */
		if (ctx->u.check == CHECK_strict ||
		    ctx->u.check == CHECK_ask)
				
			fprintf(stderr,
	"##########################################\n"
	"# WARNING: SIGNER'S PUBLIC KEY CHANGED ! #\n"
	"##########################################\n"
	"\n"
	"Eventhough the signature of the file is correct, it was "
	"created using\n"
	"the key that is different from the one you have previously "
	"choosen to\n"
	"associate with '%*.*s' title.\n"
	"\n"
	"Key fingerprint is %s\n"
	"Offending key in %s is %d\n", 
				__buf_str(&ctx->u.known[i].name),
				__buf_hex(&kfp, hex),
				FILE_KNOWN_SOURCES,
				i+1);

		if (ctx->u.check == CHECK_strict)
			die(RC_bad_pubkey, 0);

		if (ctx->u.check == CHECK_ask &&
		    ! confirm("\nAccept the file as authentic (yes/no)? "))
		    	die(RC_bad_pubkey, 0);

		goto accept;
	}

	/* unknown publisher */
	fprintf(stderr, 
		"The signature of the file is correct.\n"
		"However its title '%*.*s' is unknown. "
		"File authenticity cannot be established.\n",
		__buf_str(&title));

	if (ctx->u.check == CHECK_strict)
		die(RC_unk_pubkey, 0);

	fprintf(stderr, "Signer's key fingerprint is %s\n",
		__buf_hex(&kfp, hex));

	if (ctx->u.check == CHECK_weak)
		goto accept;

	if (ctx->u.check == CHECK_ask)
	{
		fprintf(stderr,
		"\n"
		"If you are confident that the signature is authentic, "
		"you may choose\n"
		"to permanently associate its signer's public key with "
		"the above title.\n");

		if (! confirm("Would you like to do this (yes/no)? "))
			goto accept;
	}

	/* ok, add it */
	{
		char * fn;
		FILE * fh;

		/*   */
		xmkdir(DIR_ROOT);
		
		/*   */		
		fn = xpath(FILE_KNOWN_SOURCES);
		fh = fopen(fn, "a");
		if (! fh)
			die(-1, "failed to open %s for updating", fn);
			
		if (! pubkey_store_openssh_text(pubkey, &tmp))
			die(-1, "internal error -131");
				
		fprintf(fh, "%*.*s %*.*s\n",
			__buf_str(&title),
			__buf_str(&tmp));

		buf_free(&tmp);
		fclose(fh);
		xfree(fn);
	}

accept:
	xfree(pubkey);	
}

void do_keygen(void)
{
	char buf[256];
	char * pri, * pub, * tmp;
	
	xmkdir(DIR_ROOT);

	pri = xpath(FILE_PRIVATE_KEY);
	pub = xpath(FILE_PUBLIC_KEY);

	tmp = xstrmrg(pri, ".pub");

	snprintf(buf, sizeof buf, 
		"ssh-keygen -t rsa -f %s -b 2048 -C \"\"", pri);

	if (! confirm(
	"sign does not currently have its own key generation facility. "
	"The following\n"
	"external command will be launched to generate 2048 bit RSA key - \n"
	"\n"
	"\t%s\n"
	"\n"
	"Would you like to continue (yes/no)? ", buf))
		die(0,0);
	
	warn("executing '%s' ..", buf);
	if (system(buf) != 0)
		die(-1, "'%s' failed", buf);

	fprintf(stderr, "Renaming %s to %s\n", tmp, pub);
	if (! sys_rename(tmp, pub))
	{
		sys_unlink(pri);
		sys_unlink(tmp);
		die(-1, "rename() failed\n");
	}

	xfree(tmp);
	xfree(pub);
	xfree(pri);
}

