/*	$OpenBSD: getopt_long.c,v 1.25 2011/03/05 22:10:11 guenther Exp $	*/
/*	$NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $	*/

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */
/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/getopt_long.c */
#include "includes.h"

#もし !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#もし 0
#include <err.h>
#include <getopt.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"

struct option {
	/* name of long option */
	const char *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	整数 has_arg;
	/* if not NULL, set *flag to val when option found */
	整数 *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	整数 val;
};

整数	opterr = 1;		/* if error message should be printed */
整数	optind = 1;		/* index into parent argv vector */
整数	optopt = '?';		/* character checked for validity */
整数	optreset;		/* reset getopt */
char    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(整数)'?'
#define	BADARG		((*options == ':') ? (整数)':' : (整数)'?')
#define	INORDER		(整数)1

#define	EMSG		""

static 整数 getopt_internal(整数, char * const *, const char *,
			   const struct option *, 整数 *, 整数);
static 整数 parse_long_options(char * const *, const char *,
			      const struct option *, 整数 *, 整数);
static 整数 gcd(整数, 整数);
static void permute_args(整数, 整数, 整数, char * const *);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static 整数 nonopt_start = -1; /* first non option argument (for permute) */
static 整数 nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
static const char recargchar[] = "option requires an argument -- %c";
static const char recargstring[] = "option requires an argument -- %s";
static const char ambig[] = "ambiguous option -- %.*s";
static const char noarg[] = "option doesn't take an argument -- %.*s";
static const char illoptchar[] = "unknown option -- %c";
static const char illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
static 整数
gcd(整数 a, 整数 b)
{
	整数 c;

	c = a % b;
	ながら (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	戻る (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(整数 panonopt_start, 整数 panonopt_end, 整数 opt_end,
	char * const *nargv)
{
	整数 cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	ために (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		ために (j = 0; j < cyclelen; j++) {
			もし (pos >= panonopt_end)
				pos -= nnonopts;
			否则
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((char **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((char **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
static 整数
parse_long_options(char * const *nargv, const char *options,
	const struct option *long_options, 整数 *idx, 整数 short_too)
{
	char *current_argv, *has_equal;
	size_t current_argv_len;
	整数 i, match;

	current_argv = place;
	match = -1;

	optind++;

	もし ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} 否则
		current_argv_len = strlen(current_argv);

	ために (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		もし (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		もし (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			break;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		もし (short_too && current_argv_len == 1)
			continue;

		もし (match == -1)	/* partial match */
			match = i;
		否则 {
			/* ambiguous abbreviation */
			もし (PRINT_ERROR)
				warnx(ambig, (整数)current_argv_len,
				     current_argv);
			optopt = 0;
			戻る (BADCH);
		}
	}
	もし (match != -1) {		/* option found */
		もし (long_options[match].has_arg == no_argument
		    && has_equal) {
			もし (PRINT_ERROR)
				warnx(noarg, (整数)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			もし (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			否则
				optopt = 0;
			戻る (BADARG);
		}
		もし (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			もし (has_equal)
				optarg = has_equal;
			否则 もし (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		もし ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			もし (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			もし (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			否则
				optopt = 0;
			--optind;
			戻る (BADARG);
		}
	} 否则 {			/* unknown option */
		もし (short_too) {
			--optind;
			戻る (-1);
		}
		もし (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		戻る (BADCH);
	}
	もし (idx)
		*idx = match;
	もし (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		戻る (0);
	} 否则
		戻る (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static 整数
getopt_internal(整数 nargc, char * const *nargv, const char *options,
	const struct option *long_options, 整数 *idx, 整数 flags)
{
	char *oli;				/* option letter list index */
	整数 optchar, short_too;
	static 整数 posixly_correct = -1;

	もし (options == NULL)
		戻る (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	もし (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	もし (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	もし (*options == '-')
		flags |= FLAG_ALLARGS;
	否则 もし (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	もし (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	もし (optreset)
		nonopt_start = nonopt_end = -1;
start:
	もし (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		もし (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			もし (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			否则 もし (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			戻る (-1);
		}
		もし (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
			place = EMSG;		/* found non-option */
			もし (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				戻る (INORDER);
			}
			もし (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				戻る (-1);
			}
			/* do permutation */
			もし (nonopt_start == -1)
				nonopt_start = optind;
			否则 もし (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			goto start;
		}
		もし (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		もし (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			もし (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			戻る (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	もし (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		もし (*place == '-')
			place++;		/* --foo long option */
		否则 もし (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		もし (optchar != -1) {
			place = EMSG;
			戻る (optchar);
		}
	}

	もし ((optchar = (整数)*place++) == (整数)':' ||
	    (optchar == (整数)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		もし (optchar == (整数)'-' && *place == '\0')
			戻る (-1);
		もし (!*place)
			++optind;
		もし (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		戻る (BADCH);
	}
	もし (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		もし (*place)			/* no space */
			/* NOTHING */;
		否则 もし (++optind >= nargc) {	/* no arg */
			place = EMSG;
			もし (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			戻る (BADARG);
		} 否则				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		戻る (optchar);
	}
	もし (*++oli != ':') {			/* doesn't take argument */
		もし (!*place)
			++optind;
	} 否则 {				/* takes (optional) argument */
		optarg = NULL;
		もし (*place)			/* no white space */
			optarg = place;
		否则 もし (oli[1] != ':') {	/* arg not optional */
			もし (++optind >= nargc) {	/* no arg */
				place = EMSG;
				もし (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				戻る (BADARG);
			} 否则
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	戻る (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
整数
getopt(整数 nargc, char * const *nargv, const char *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	戻る (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}

#もし 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
整数
getopt_long(整数 nargc, char * const *nargv, const char *options,
    const struct option *long_options, 整数 *idx)
{

	戻る (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
整数
getopt_long_only(整数 nargc, char * const *nargv, const char *options,
    const struct option *long_options, 整数 *idx)
{

	戻る (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
