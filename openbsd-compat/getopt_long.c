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

#만약 !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#만약 0
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
	정수 has_arg;
	/* if not NULL, set *flag to val when option found */
	정수 *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	정수 val;
};

정수	opterr = 1;		/* if error message should be printed */
정수	optind = 1;		/* index into parent argv vector */
정수	optopt = '?';		/* character checked for validity */
정수	optreset;		/* reset getopt */
char    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(정수)'?'
#define	BADARG		((*options == ':') ? (정수)':' : (정수)'?')
#define	INORDER		(정수)1

#define	EMSG		""

static 정수 getopt_internal(정수, char * const *, const char *,
			   const struct option *, 정수 *, 정수);
static 정수 parse_long_options(char * const *, const char *,
			      const struct option *, 정수 *, 정수);
static 정수 gcd(정수, 정수);
static void permute_args(정수, 정수, 정수, char * const *);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static 정수 nonopt_start = -1; /* first non option argument (for permute) */
static 정수 nonopt_end = -1;   /* first option after non options (for permute) */

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
static 정수
gcd(정수 a, 정수 b)
{
	정수 c;

	c = a % b;
	동안 (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	반환 (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(정수 panonopt_start, 정수 panonopt_end, 정수 opt_end,
	char * const *nargv)
{
	정수 cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	위해 (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		위해 (j = 0; j < cyclelen; j++) {
			만약 (pos >= panonopt_end)
				pos -= nnonopts;
			아니면
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
static 정수
parse_long_options(char * const *nargv, const char *options,
	const struct option *long_options, 정수 *idx, 정수 short_too)
{
	char *current_argv, *has_equal;
	size_t current_argv_len;
	정수 i, match;

	current_argv = place;
	match = -1;

	optind++;

	만약 ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} 아니면
		current_argv_len = strlen(current_argv);

	위해 (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		만약 (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		만약 (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			break;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		만약 (short_too && current_argv_len == 1)
			continue;

		만약 (match == -1)	/* partial match */
			match = i;
		아니면 {
			/* ambiguous abbreviation */
			만약 (PRINT_ERROR)
				warnx(ambig, (정수)current_argv_len,
				     current_argv);
			optopt = 0;
			반환 (BADCH);
		}
	}
	만약 (match != -1) {		/* option found */
		만약 (long_options[match].has_arg == no_argument
		    && has_equal) {
			만약 (PRINT_ERROR)
				warnx(noarg, (정수)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			만약 (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			아니면
				optopt = 0;
			반환 (BADARG);
		}
		만약 (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			만약 (has_equal)
				optarg = has_equal;
			아니면 만약 (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		만약 ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			만약 (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			만약 (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			아니면
				optopt = 0;
			--optind;
			반환 (BADARG);
		}
	} 아니면 {			/* unknown option */
		만약 (short_too) {
			--optind;
			반환 (-1);
		}
		만약 (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		반환 (BADCH);
	}
	만약 (idx)
		*idx = match;
	만약 (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		반환 (0);
	} 아니면
		반환 (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static 정수
getopt_internal(정수 nargc, char * const *nargv, const char *options,
	const struct option *long_options, 정수 *idx, 정수 flags)
{
	char *oli;				/* option letter list index */
	정수 optchar, short_too;
	static 정수 posixly_correct = -1;

	만약 (options == NULL)
		반환 (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	만약 (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	만약 (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	만약 (*options == '-')
		flags |= FLAG_ALLARGS;
	아니면 만약 (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	만약 (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	만약 (optreset)
		nonopt_start = nonopt_end = -1;
start:
	만약 (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		만약 (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			만약 (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			아니면 만약 (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			반환 (-1);
		}
		만약 (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
			place = EMSG;		/* found non-option */
			만약 (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				반환 (INORDER);
			}
			만약 (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				반환 (-1);
			}
			/* do permutation */
			만약 (nonopt_start == -1)
				nonopt_start = optind;
			아니면 만약 (nonopt_end != -1) {
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
		만약 (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		만약 (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			만약 (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			반환 (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	만약 (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		만약 (*place == '-')
			place++;		/* --foo long option */
		아니면 만약 (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		만약 (optchar != -1) {
			place = EMSG;
			반환 (optchar);
		}
	}

	만약 ((optchar = (정수)*place++) == (정수)':' ||
	    (optchar == (정수)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		만약 (optchar == (정수)'-' && *place == '\0')
			반환 (-1);
		만약 (!*place)
			++optind;
		만약 (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		반환 (BADCH);
	}
	만약 (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		만약 (*place)			/* no space */
			/* NOTHING */;
		아니면 만약 (++optind >= nargc) {	/* no arg */
			place = EMSG;
			만약 (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			반환 (BADARG);
		} 아니면				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		반환 (optchar);
	}
	만약 (*++oli != ':') {			/* doesn't take argument */
		만약 (!*place)
			++optind;
	} 아니면 {				/* takes (optional) argument */
		optarg = NULL;
		만약 (*place)			/* no white space */
			optarg = place;
		아니면 만약 (oli[1] != ':') {	/* arg not optional */
			만약 (++optind >= nargc) {	/* no arg */
				place = EMSG;
				만약 (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				반환 (BADARG);
			} 아니면
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	반환 (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
정수
getopt(정수 nargc, char * const *nargv, const char *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	반환 (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}

#만약 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
정수
getopt_long(정수 nargc, char * const *nargv, const char *options,
    const struct option *long_options, 정수 *idx)
{

	반환 (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
정수
getopt_long_only(정수 nargc, char * const *nargv, const char *options,
    const struct option *long_options, 정수 *idx)
{

	반환 (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
