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

#якщо !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#якщо 0
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
	ціле has_arg;
	/* if not NULL, set *flag to val when option found */
	ціле *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ціле val;
};

ціле	opterr = 1;		/* if error message should be printed */
ціле	optind = 1;		/* index into parent argv vector */
ціле	optopt = '?';		/* character checked for validity */
ціле	optreset;		/* reset getopt */
char    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(ціле)'?'
#define	BADARG		((*options == ':') ? (ціле)':' : (ціле)'?')
#define	INORDER		(ціле)1

#define	EMSG		""

static ціле getopt_internal(ціле, char * const *, const char *,
			   const struct option *, ціле *, ціле);
static ціле parse_long_options(char * const *, const char *,
			      const struct option *, ціле *, ціле);
static ціле gcd(ціле, ціле);
static void permute_args(ціле, ціле, ціле, char * const *);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static ціле nonopt_start = -1; /* first non option argument (for permute) */
static ціле nonopt_end = -1;   /* first option after non options (for permute) */

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
static ціле
gcd(ціле a, ціле b)
{
	ціле c;

	c = a % b;
	поки (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	повернути (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(ціле panonopt_start, ціле panonopt_end, ціле opt_end,
	char * const *nargv)
{
	ціле cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	для (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		для (j = 0; j < cyclelen; j++) {
			якщо (pos >= panonopt_end)
				pos -= nnonopts;
			інакше
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
static ціле
parse_long_options(char * const *nargv, const char *options,
	const struct option *long_options, ціле *idx, ціле short_too)
{
	char *current_argv, *has_equal;
	size_t current_argv_len;
	ціле i, match;

	current_argv = place;
	match = -1;

	optind++;

	якщо ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} інакше
		current_argv_len = strlen(current_argv);

	для (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		якщо (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		якщо (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			break;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		якщо (short_too && current_argv_len == 1)
			continue;

		якщо (match == -1)	/* partial match */
			match = i;
		інакше {
			/* ambiguous abbreviation */
			якщо (PRINT_ERROR)
				warnx(ambig, (ціле)current_argv_len,
				     current_argv);
			optopt = 0;
			повернути (BADCH);
		}
	}
	якщо (match != -1) {		/* option found */
		якщо (long_options[match].has_arg == no_argument
		    && has_equal) {
			якщо (PRINT_ERROR)
				warnx(noarg, (ціле)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			якщо (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			інакше
				optopt = 0;
			повернути (BADARG);
		}
		якщо (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			якщо (has_equal)
				optarg = has_equal;
			інакше якщо (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		якщо ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			якщо (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			якщо (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			інакше
				optopt = 0;
			--optind;
			повернути (BADARG);
		}
	} інакше {			/* unknown option */
		якщо (short_too) {
			--optind;
			повернути (-1);
		}
		якщо (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		повернути (BADCH);
	}
	якщо (idx)
		*idx = match;
	якщо (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		повернути (0);
	} інакше
		повернути (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static ціле
getopt_internal(ціле nargc, char * const *nargv, const char *options,
	const struct option *long_options, ціле *idx, ціле flags)
{
	char *oli;				/* option letter list index */
	ціле optchar, short_too;
	static ціле posixly_correct = -1;

	якщо (options == NULL)
		повернути (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	якщо (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	якщо (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	якщо (*options == '-')
		flags |= FLAG_ALLARGS;
	інакше якщо (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	якщо (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	якщо (optreset)
		nonopt_start = nonopt_end = -1;
start:
	якщо (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		якщо (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			якщо (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			інакше якщо (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			повернути (-1);
		}
		якщо (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
			place = EMSG;		/* found non-option */
			якщо (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				повернути (INORDER);
			}
			якщо (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				повернути (-1);
			}
			/* do permutation */
			якщо (nonopt_start == -1)
				nonopt_start = optind;
			інакше якщо (nonopt_end != -1) {
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
		якщо (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		якщо (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			якщо (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			повернути (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	якщо (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		якщо (*place == '-')
			place++;		/* --foo long option */
		інакше якщо (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		якщо (optchar != -1) {
			place = EMSG;
			повернути (optchar);
		}
	}

	якщо ((optchar = (ціле)*place++) == (ціле)':' ||
	    (optchar == (ціле)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		якщо (optchar == (ціле)'-' && *place == '\0')
			повернути (-1);
		якщо (!*place)
			++optind;
		якщо (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		повернути (BADCH);
	}
	якщо (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		якщо (*place)			/* no space */
			/* NOTHING */;
		інакше якщо (++optind >= nargc) {	/* no arg */
			place = EMSG;
			якщо (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			повернути (BADARG);
		} інакше				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		повернути (optchar);
	}
	якщо (*++oli != ':') {			/* doesn't take argument */
		якщо (!*place)
			++optind;
	} інакше {				/* takes (optional) argument */
		optarg = NULL;
		якщо (*place)			/* no white space */
			optarg = place;
		інакше якщо (oli[1] != ':') {	/* arg not optional */
			якщо (++optind >= nargc) {	/* no arg */
				place = EMSG;
				якщо (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				повернути (BADARG);
			} інакше
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	повернути (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ціле
getopt(ціле nargc, char * const *nargv, const char *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	повернути (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}

#якщо 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ціле
getopt_long(ціле nargc, char * const *nargv, const char *options,
    const struct option *long_options, ціле *idx)
{

	повернути (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ціле
getopt_long_only(ціле nargc, char * const *nargv, const char *options,
    const struct option *long_options, ціле *idx)
{

	повернути (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
