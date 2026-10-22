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

#གལ་ཏེ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#གལ་ཏེ 0
#include <err.h>
#include <getopt.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"

sa_nracanaa option {
	/* name of long option */
	const var_na *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ཧྲིལ has_arg;
	/* if not NULL, set *flag to val when option found */
	ཧྲིལ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ཧྲིལ val;
};

ཧྲིལ	opterr = 1;		/* if error message should be printed */
ཧྲིལ	optind = 1;		/* index into parent argv vector */
ཧྲིལ	optopt = '?';		/* character checked for validity */
ཧྲིལ	optreset;		/* reset getopt */
var_na    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(ཧྲིལ)'?'
#define	BADARG		((*options == ':') ? (ཧྲིལ)':' : (ཧྲིལ)'?')
#define	INORDER		(ཧྲིལ)1

#define	EMSG		""

static ཧྲིལ getopt_internal(ཧྲིལ, var_na * const *, const var_na *,
			   const sa_nracanaa option *, ཧྲིལ *, ཧྲིལ);
static ཧྲིལ parse_long_options(var_na * const *, const var_na *,
			      const sa_nracanaa option *, ཧྲིལ *, ཧྲིལ);
static ཧྲིལ gcd(ཧྲིལ, ཧྲིལ);
static void permute_args(ཧྲིལ, ཧྲིལ, ཧྲིལ, var_na * const *);

static var_na *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static ཧྲིལ nonopt_start = -1; /* first non option argument (for permute) */
static ཧྲིལ nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
static const var_na recargchar[] = "option requires an argument -- %c";
static const var_na recargstring[] = "option requires an argument -- %s";
static const var_na ambig[] = "ambiguous option -- %.*s";
static const var_na noarg[] = "option doesn't take an argument -- %.*s";
static const var_na illoptchar[] = "unknown option -- %c";
static const var_na illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
static ཧྲིལ
gcd(ཧྲིལ a, ཧྲིལ b)
{
	ཧྲིལ c;

	c = a % b;
	སྐབས (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ཕྱིར (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(ཧྲིལ panonopt_start, ཧྲིལ panonopt_end, ཧྲིལ opt_end,
	var_na * const *nargv)
{
	ཧྲིལ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	var_na *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	ཆེད་དུ (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		ཆེད་དུ (j = 0; j < cyclelen; j++) {
			གལ་ཏེ (pos >= panonopt_end)
				pos -= nnonopts;
			དེ་མིན
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((var_na **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((var_na **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
static ཧྲིལ
parse_long_options(var_na * const *nargv, const var_na *options,
	const sa_nracanaa option *long_options, ཧྲིལ *idx, ཧྲིལ short_too)
{
	var_na *current_argv, *has_equal;
	size_t current_argv_len;
	ཧྲིལ i, match;

	current_argv = place;
	match = -1;

	optind++;

	གལ་ཏེ ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} དེ་མིན
		current_argv_len = strlen(current_argv);

	ཆེད་དུ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		གལ་ཏེ (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		གལ་ཏེ (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			bha_nga;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		གལ་ཏེ (short_too && current_argv_len == 1)
			continue;

		གལ་ཏེ (match == -1)	/* partial match */
			match = i;
		དེ་མིན {
			/* ambiguous abbreviation */
			གལ་ཏེ (PRINT_ERROR)
				warnx(ambig, (ཧྲིལ)current_argv_len,
				     current_argv);
			optopt = 0;
			ཕྱིར (BADCH);
		}
	}
	གལ་ཏེ (match != -1) {		/* option found */
		གལ་ཏེ (long_options[match].has_arg == no_argument
		    && has_equal) {
			གལ་ཏེ (PRINT_ERROR)
				warnx(noarg, (ཧྲིལ)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			གལ་ཏེ (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			དེ་མིན
				optopt = 0;
			ཕྱིར (BADARG);
		}
		གལ་ཏེ (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			གལ་ཏེ (has_equal)
				optarg = has_equal;
			དེ་མིན གལ་ཏེ (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		གལ་ཏེ ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			གལ་ཏེ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			གལ་ཏེ (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			དེ་མིན
				optopt = 0;
			--optind;
			ཕྱིར (BADARG);
		}
	} དེ་མིན {			/* unknown option */
		གལ་ཏེ (short_too) {
			--optind;
			ཕྱིར (-1);
		}
		གལ་ཏེ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ཕྱིར (BADCH);
	}
	གལ་ཏེ (idx)
		*idx = match;
	གལ་ཏེ (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		ཕྱིར (0);
	} དེ་མིན
		ཕྱིར (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static ཧྲིལ
getopt_internal(ཧྲིལ nargc, var_na * const *nargv, const var_na *options,
	const sa_nracanaa option *long_options, ཧྲིལ *idx, ཧྲིལ flags)
{
	var_na *oli;				/* option letter list index */
	ཧྲིལ optchar, short_too;
	static ཧྲིལ posixly_correct = -1;

	གལ་ཏེ (options == NULL)
		ཕྱིར (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	གལ་ཏེ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	གལ་ཏེ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	གལ་ཏེ (*options == '-')
		flags |= FLAG_ALLARGS;
	དེ་མིན གལ་ཏེ (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	གལ་ཏེ (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	གལ་ཏེ (optreset)
		nonopt_start = nonopt_end = -1;
start:
	གལ་ཏེ (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		གལ་ཏེ (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			གལ་ཏེ (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			དེ་མིན གལ་ཏེ (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ཕྱིར (-1);
		}
		གལ་ཏེ (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
			place = EMSG;		/* found non-option */
			གལ་ཏེ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ཕྱིར (INORDER);
			}
			གལ་ཏེ (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ཕྱིར (-1);
			}
			/* do permutation */
			གལ་ཏེ (nonopt_start == -1)
				nonopt_start = optind;
			དེ་མིན གལ་ཏེ (nonopt_end != -1) {
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
		གལ་ཏེ (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		གལ་ཏེ (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			གལ་ཏེ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ཕྱིར (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	གལ་ཏེ (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		གལ་ཏེ (*place == '-')
			place++;		/* --foo long option */
		དེ་མིན གལ་ཏེ (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		གལ་ཏེ (optchar != -1) {
			place = EMSG;
			ཕྱིར (optchar);
		}
	}

	གལ་ཏེ ((optchar = (ཧྲིལ)*place++) == (ཧྲིལ)':' ||
	    (optchar == (ཧྲིལ)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		གལ་ཏེ (optchar == (ཧྲིལ)'-' && *place == '\0')
			ཕྱིར (-1);
		གལ་ཏེ (!*place)
			++optind;
		གལ་ཏེ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ཕྱིར (BADCH);
	}
	གལ་ཏེ (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		གལ་ཏེ (*place)			/* no space */
			/* NOTHING */;
		དེ་མིན གལ་ཏེ (++optind >= nargc) {	/* no arg */
			place = EMSG;
			གལ་ཏེ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ཕྱིར (BADARG);
		} དེ་མིན				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		ཕྱིར (optchar);
	}
	གལ་ཏེ (*++oli != ':') {			/* doesn't take argument */
		གལ་ཏེ (!*place)
			++optind;
	} དེ་མིན {				/* takes (optional) argument */
		optarg = NULL;
		གལ་ཏེ (*place)			/* no white space */
			optarg = place;
		དེ་མིན གལ་ཏེ (oli[1] != ':') {	/* arg not optional */
			གལ་ཏེ (++optind >= nargc) {	/* no arg */
				place = EMSG;
				གལ་ཏེ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ཕྱིར (BADARG);
			} དེ་མིན
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	ཕྱིར (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ཧྲིལ
getopt(ཧྲིལ nargc, var_na * const *nargv, const var_na *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ཕྱིར (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}

#གལ་ཏེ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ཧྲིལ
getopt_long(ཧྲིལ nargc, var_na * const *nargv, const var_na *options,
    const sa_nracanaa option *long_options, ཧྲིལ *idx)
{

	ཕྱིར (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ཧྲིལ
getopt_long_only(ཧྲིལ nargc, var_na * const *nargv, const var_na *options,
    const sa_nracanaa option *long_options, ཧྲིལ *idx)
{

	ཕྱིར (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
