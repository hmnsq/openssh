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

#ប្រសិនបើ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#ប្រសិនបើ 0
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
	ចំនួនគត់ has_arg;
	/* if not NULL, set *flag to val when option found */
	ចំនួនគត់ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ចំនួនគត់ val;
};

ចំនួនគត់	opterr = 1;		/* if error message should be printed */
ចំនួនគត់	optind = 1;		/* index into parent argv vector */
ចំនួនគត់	optopt = '?';		/* character checked for validity */
ចំនួនគត់	optreset;		/* reset getopt */
var_na    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(ចំនួនគត់)'?'
#define	BADARG		((*options == ':') ? (ចំនួនគត់)':' : (ចំនួនគត់)'?')
#define	INORDER		(ចំនួនគត់)1

#define	EMSG		""

static ចំនួនគត់ getopt_internal(ចំនួនគត់, var_na * const *, const var_na *,
			   const sa_nracanaa option *, ចំនួនគត់ *, ចំនួនគត់);
static ចំនួនគត់ parse_long_options(var_na * const *, const var_na *,
			      const sa_nracanaa option *, ចំនួនគត់ *, ចំនួនគត់);
static ចំនួនគត់ gcd(ចំនួនគត់, ចំនួនគត់);
static void permute_args(ចំនួនគត់, ចំនួនគត់, ចំនួនគត់, var_na * const *);

static var_na *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static ចំនួនគត់ nonopt_start = -1; /* first non option argument (for permute) */
static ចំនួនគត់ nonopt_end = -1;   /* first option after non options (for permute) */

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
static ចំនួនគត់
gcd(ចំនួនគត់ a, ចំនួនគត់ b)
{
	ចំនួនគត់ c;

	c = a % b;
	ខណៈពេល (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ត្រឡប់ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(ចំនួនគត់ panonopt_start, ចំនួនគត់ panonopt_end, ចំនួនគត់ opt_end,
	var_na * const *nargv)
{
	ចំនួនគត់ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	var_na *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	សម្រាប់ (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		សម្រាប់ (j = 0; j < cyclelen; j++) {
			ប្រសិនបើ (pos >= panonopt_end)
				pos -= nnonopts;
			បើមិនដូច្នេះ
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
static ចំនួនគត់
parse_long_options(var_na * const *nargv, const var_na *options,
	const sa_nracanaa option *long_options, ចំនួនគត់ *idx, ចំនួនគត់ short_too)
{
	var_na *current_argv, *has_equal;
	size_t current_argv_len;
	ចំនួនគត់ i, match;

	current_argv = place;
	match = -1;

	optind++;

	ប្រសិនបើ ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} បើមិនដូច្នេះ
		current_argv_len = strlen(current_argv);

	សម្រាប់ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ប្រសិនបើ (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		ប្រសិនបើ (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			bha_nga;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ប្រសិនបើ (short_too && current_argv_len == 1)
			continue;

		ប្រសិនបើ (match == -1)	/* partial match */
			match = i;
		បើមិនដូច្នេះ {
			/* ambiguous abbreviation */
			ប្រសិនបើ (PRINT_ERROR)
				warnx(ambig, (ចំនួនគត់)current_argv_len,
				     current_argv);
			optopt = 0;
			ត្រឡប់ (BADCH);
		}
	}
	ប្រសិនបើ (match != -1) {		/* option found */
		ប្រសិនបើ (long_options[match].has_arg == no_argument
		    && has_equal) {
			ប្រសិនបើ (PRINT_ERROR)
				warnx(noarg, (ចំនួនគត់)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ប្រសិនបើ (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			បើមិនដូច្នេះ
				optopt = 0;
			ត្រឡប់ (BADARG);
		}
		ប្រសិនបើ (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			ប្រសិនបើ (has_equal)
				optarg = has_equal;
			បើមិនដូច្នេះ ប្រសិនបើ (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ប្រសិនបើ ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ប្រសិនបើ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ប្រសិនបើ (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			បើមិនដូច្នេះ
				optopt = 0;
			--optind;
			ត្រឡប់ (BADARG);
		}
	} បើមិនដូច្នេះ {			/* unknown option */
		ប្រសិនបើ (short_too) {
			--optind;
			ត្រឡប់ (-1);
		}
		ប្រសិនបើ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ត្រឡប់ (BADCH);
	}
	ប្រសិនបើ (idx)
		*idx = match;
	ប្រសិនបើ (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		ត្រឡប់ (0);
	} បើមិនដូច្នេះ
		ត្រឡប់ (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static ចំនួនគត់
getopt_internal(ចំនួនគត់ nargc, var_na * const *nargv, const var_na *options,
	const sa_nracanaa option *long_options, ចំនួនគត់ *idx, ចំនួនគត់ flags)
{
	var_na *oli;				/* option letter list index */
	ចំនួនគត់ optchar, short_too;
	static ចំនួនគត់ posixly_correct = -1;

	ប្រសិនបើ (options == NULL)
		ត្រឡប់ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ប្រសិនបើ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ប្រសិនបើ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	ប្រសិនបើ (*options == '-')
		flags |= FLAG_ALLARGS;
	បើមិនដូច្នេះ ប្រសិនបើ (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	ប្រសិនបើ (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	ប្រសិនបើ (optreset)
		nonopt_start = nonopt_end = -1;
start:
	ប្រសិនបើ (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		ប្រសិនបើ (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			ប្រសិនបើ (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			បើមិនដូច្នេះ ប្រសិនបើ (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ត្រឡប់ (-1);
		}
		ប្រសិនបើ (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
			place = EMSG;		/* found non-option */
			ប្រសិនបើ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ត្រឡប់ (INORDER);
			}
			ប្រសិនបើ (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ត្រឡប់ (-1);
			}
			/* do permutation */
			ប្រសិនបើ (nonopt_start == -1)
				nonopt_start = optind;
			បើមិនដូច្នេះ ប្រសិនបើ (nonopt_end != -1) {
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
		ប្រសិនបើ (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ប្រសិនបើ (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ប្រសិនបើ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ត្រឡប់ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ប្រសិនបើ (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ប្រសិនបើ (*place == '-')
			place++;		/* --foo long option */
		បើមិនដូច្នេះ ប្រសិនបើ (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ប្រសិនបើ (optchar != -1) {
			place = EMSG;
			ត្រឡប់ (optchar);
		}
	}

	ប្រសិនបើ ((optchar = (ចំនួនគត់)*place++) == (ចំនួនគត់)':' ||
	    (optchar == (ចំនួនគត់)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ប្រសិនបើ (optchar == (ចំនួនគត់)'-' && *place == '\0')
			ត្រឡប់ (-1);
		ប្រសិនបើ (!*place)
			++optind;
		ប្រសិនបើ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ត្រឡប់ (BADCH);
	}
	ប្រសិនបើ (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ប្រសិនបើ (*place)			/* no space */
			/* NOTHING */;
		បើមិនដូច្នេះ ប្រសិនបើ (++optind >= nargc) {	/* no arg */
			place = EMSG;
			ប្រសិនបើ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ត្រឡប់ (BADARG);
		} បើមិនដូច្នេះ				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		ត្រឡប់ (optchar);
	}
	ប្រសិនបើ (*++oli != ':') {			/* doesn't take argument */
		ប្រសិនបើ (!*place)
			++optind;
	} បើមិនដូច្នេះ {				/* takes (optional) argument */
		optarg = NULL;
		ប្រសិនបើ (*place)			/* no white space */
			optarg = place;
		បើមិនដូច្នេះ ប្រសិនបើ (oli[1] != ':') {	/* arg not optional */
			ប្រសិនបើ (++optind >= nargc) {	/* no arg */
				place = EMSG;
				ប្រសិនបើ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ត្រឡប់ (BADARG);
			} បើមិនដូច្នេះ
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	ត្រឡប់ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ចំនួនគត់
getopt(ចំនួនគត់ nargc, var_na * const *nargv, const var_na *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ត្រឡប់ (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}

#ប្រសិនបើ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ចំនួនគត់
getopt_long(ចំនួនគត់ nargc, var_na * const *nargv, const var_na *options,
    const sa_nracanaa option *long_options, ចំនួនគត់ *idx)
{

	ត្រឡប់ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ចំនួនគត់
getopt_long_only(ចំនួនគត់ nargc, var_na * const *nargv, const var_na *options,
    const sa_nracanaa option *long_options, ចំនួនគត់ *idx)
{

	ត្រឡប់ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
