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
#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#ಯದಿ 0
#ಅನ್ತರ್ಭಾವ <err.h>
#ಅನ್ತರ್ಭಾವ <getopt.h>
#endif
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ಸಂರಚನಾ option {
	/* name of long option */
	ಧ್ರುವ ವರ್ಣ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ಪೂರ್ಣಾಙ್ಕ has_arg;
	/* if not NULL, set *flag to val when option found */
	ಪೂರ್ಣಾಙ್ಕ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ಪೂರ್ಣಾಙ್ಕ val;
};

ಪೂರ್ಣಾಙ್ಕ	opterr = 1;		/* if error message should be printed */
ಪೂರ್ಣಾಙ್ಕ	optind = 1;		/* index into parent argv vector */
ಪೂರ್ಣಾಙ್ಕ	optopt = '?';		/* character checked for validity */
ಪೂರ್ಣಾಙ್ಕ	optreset;		/* reset getopt */
ವರ್ಣ    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(ಪೂರ್ಣಾಙ್ಕ)'?'
#define	BADARG		((*options == ':') ? (ಪೂರ್ಣಾಙ್ಕ)':' : (ಪೂರ್ಣಾಙ್ಕ)'?')
#define	ಮಧ್ಯಕ್ರಮ		(ಪೂರ್ಣಾಙ್ಕ)1

#define	EMSG		""

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ getopt_internal(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ * ಧ್ರುವ *, ಧ್ರುವ ವರ್ಣ *,
			   ಧ್ರುವ ಸಂರಚನಾ option *, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ parse_long_options(ವರ್ಣ * ಧ್ರುವ *, ಧ್ರುವ ವರ್ಣ *,
			      ಧ್ರುವ ಸಂರಚನಾ option *, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ gcd(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಶೂನ್ಯ permute_args(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ * ಧ್ರುವ *);

ಸ್ಥಿರ ವರ್ಣ *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ nonopt_start = -1; /* first non option argument (for permute) */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ recargchar[] = "option requires an argument -- %c";
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ recargstring[] = "option requires an argument -- %s";
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ ambig[] = "ambiguous option -- %.*s";
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ noarg[] = "option doesn't take an argument -- %.*s";
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ illoptchar[] = "unknown option -- %c";
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
gcd(ಪೂರ್ಣಾಙ್ಕ a, ಪೂರ್ಣಾಙ್ಕ b)
{
	ಪೂರ್ಣಾಙ್ಕ c;

	c = a % b;
	ಯಾವತ್ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ಪ್ರತ್ಯಾಗಮ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
permute_args(ಪೂರ್ಣಾಙ್ಕ panonopt_start, ಪೂರ್ಣಾಙ್ಕ panonopt_end, ಪೂರ್ಣಾಙ್ಕ opt_end,
	ವರ್ಣ * ಧ್ರುವ *nargv)
{
	ಪೂರ್ಣಾಙ್ಕ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	ವರ್ಣ *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	ಪ್ರತಿ (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		ಪ್ರತಿ (j = 0; j < cyclelen; j++) {
			ಯದಿ (pos >= panonopt_end)
				pos -= nnonopts;
			ಅನ್ಯಥಾ
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((ವರ್ಣ **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((ವರ್ಣ **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_long_options(ವರ್ಣ * ಧ್ರುವ *nargv, ಧ್ರುವ ವರ್ಣ *options,
	ಧ್ರುವ ಸಂರಚನಾ option *long_options, ಪೂರ್ಣಾಙ್ಕ *idx, ಪೂರ್ಣಾಙ್ಕ short_too)
{
	ವರ್ಣ *current_argv, *has_equal;
	size_t current_argv_len;
	ಪೂರ್ಣಾಙ್ಕ i, match;

	current_argv = place;
	match = -1;

	optind++;

	ಯದಿ ((has_equal = strchr(current_argv, '=')) != ರಿಕ್ತ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} ಅನ್ಯಥಾ
		current_argv_len = strlen(current_argv);

	ಪ್ರತಿ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ಯದಿ (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			ಅನುವರ್ತ;

		ಯದಿ (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			ಭಙ್ಗ;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ಯದಿ (short_too && current_argv_len == 1)
			ಅನುವರ್ತ;

		ಯದಿ (match == -1)	/* partial match */
			match = i;
		ಅನ್ಯಥಾ {
			/* ambiguous abbreviation */
			ಯದಿ (PRINT_ERROR)
				warnx(ambig, (ಪೂರ್ಣಾಙ್ಕ)current_argv_len,
				     current_argv);
			optopt = 0;
			ಪ್ರತ್ಯಾಗಮ (BADCH);
		}
	}
	ಯದಿ (match != -1) {		/* option found */
		ಯದಿ (long_options[match].has_arg == no_argument
		    && has_equal) {
			ಯದಿ (PRINT_ERROR)
				warnx(noarg, (ಪೂರ್ಣಾಙ್ಕ)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ಯದಿ (long_options[match].flag == ರಿಕ್ತ)
				optopt = long_options[match].val;
			ಅನ್ಯಥಾ
				optopt = 0;
			ಪ್ರತ್ಯಾಗಮ (BADARG);
		}
		ಯದಿ (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			ಯದಿ (has_equal)
				optarg = has_equal;
			ಅನ್ಯಥಾ ಯದಿ (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ಯದಿ ((long_options[match].has_arg == required_argument)
		    && (optarg == ರಿಕ್ತ)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ಯದಿ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ಯದಿ (long_options[match].flag == ರಿಕ್ತ)
				optopt = long_options[match].val;
			ಅನ್ಯಥಾ
				optopt = 0;
			--optind;
			ಪ್ರತ್ಯಾಗಮ (BADARG);
		}
	} ಅನ್ಯಥಾ {			/* unknown option */
		ಯದಿ (short_too) {
			--optind;
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
		ಯದಿ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ಪ್ರತ್ಯಾಗಮ (BADCH);
	}
	ಯದಿ (idx)
		*idx = match;
	ಯದಿ (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		ಪ್ರತ್ಯಾಗಮ (0);
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
getopt_internal(ಪೂರ್ಣಾಙ್ಕ nargc, ವರ್ಣ * ಧ್ರುವ *nargv, ಧ್ರುವ ವರ್ಣ *options,
	ಧ್ರುವ ಸಂರಚನಾ option *long_options, ಪೂರ್ಣಾಙ್ಕ *idx, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ವರ್ಣ *oli;				/* option letter list index */
	ಪೂರ್ಣಾಙ್ಕ optchar, short_too;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ posixly_correct = -1;

	ಯದಿ (options == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ಯದಿ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ಯದಿ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ರಿಕ್ತ);
	ಯದಿ (*options == '-')
		flags |= FLAG_ALLARGS;
	ಅನ್ಯಥಾ ಯದಿ (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	ಯದಿ (*options == '+' || *options == '-')
		options++;

	optarg = ರಿಕ್ತ;
	ಯದಿ (optreset)
		nonopt_start = nonopt_end = -1;
start:
	ಯದಿ (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		ಯದಿ (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			ಯದಿ (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			ಅನ್ಯಥಾ ಯದಿ (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
		ಯದಿ (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == ರಿಕ್ತ)) {
			place = EMSG;		/* found non-option */
			ಯದಿ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ಪ್ರತ್ಯಾಗಮ (ಮಧ್ಯಕ್ರಮ);
			}
			ಯದಿ (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ಪ್ರತ್ಯಾಗಮ (-1);
			}
			/* do permutation */
			ಯದಿ (nonopt_start == -1)
				nonopt_start = optind;
			ಅನ್ಯಥಾ ಯದಿ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			ಗಚ್ಛ start;
		}
		ಯದಿ (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ಯದಿ (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ಯದಿ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ಯದಿ (long_options != ರಿಕ್ತ && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ಯದಿ (*place == '-')
			place++;		/* --foo long option */
		ಅನ್ಯಥಾ ಯದಿ (*place != ':' && strchr(options, *place) != ರಿಕ್ತ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ಯದಿ (optchar != -1) {
			place = EMSG;
			ಪ್ರತ್ಯಾಗಮ (optchar);
		}
	}

	ಯದಿ ((optchar = (ಪೂರ್ಣಾಙ್ಕ)*place++) == (ಪೂರ್ಣಾಙ್ಕ)':' ||
	    (optchar == (ಪೂರ್ಣಾಙ್ಕ)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == ರಿಕ್ತ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ಯದಿ (optchar == (ಪೂರ್ಣಾಙ್ಕ)'-' && *place == '\0')
			ಪ್ರತ್ಯಾಗಮ (-1);
		ಯದಿ (!*place)
			++optind;
		ಯದಿ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ಪ್ರತ್ಯಾಗಮ (BADCH);
	}
	ಯದಿ (long_options != ರಿಕ್ತ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ಯದಿ (*place)			/* no space */
			/* NOTHING */;
		ಅನ್ಯಥಾ ಯದಿ (++optind >= nargc) {	/* no arg */
			place = EMSG;
			ಯದಿ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ಪ್ರತ್ಯಾಗಮ (BADARG);
		} ಅನ್ಯಥಾ				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		ಪ್ರತ್ಯಾಗಮ (optchar);
	}
	ಯದಿ (*++oli != ':') {			/* doesn't take argument */
		ಯದಿ (!*place)
			++optind;
	} ಅನ್ಯಥಾ {				/* takes (optional) argument */
		optarg = ರಿಕ್ತ;
		ಯದಿ (*place)			/* no white space */
			optarg = place;
		ಅನ್ಯಥಾ ಯದಿ (oli[1] != ':') {	/* arg not optional */
			ಯದಿ (++optind >= nargc) {	/* no arg */
				place = EMSG;
				ಯದಿ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ಪ್ರತ್ಯಾಗಮ (BADARG);
			} ಅನ್ಯಥಾ
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	ಪ್ರತ್ಯಾಗಮ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ಪೂರ್ಣಾಙ್ಕ
getopt(ಪೂರ್ಣಾಙ್ಕ nargc, ವರ್ಣ * ಧ್ರುವ *nargv, ಧ್ರುವ ವರ್ಣ *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ಪ್ರತ್ಯಾಗಮ (getopt_internal(nargc, nargv, options, ರಿಕ್ತ, ರಿಕ್ತ, 0));
}

#ಯದಿ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ಪೂರ್ಣಾಙ್ಕ
getopt_long(ಪೂರ್ಣಾಙ್ಕ nargc, ವರ್ಣ * ಧ್ರುವ *nargv, ಧ್ರುವ ವರ್ಣ *options,
    ಧ್ರುವ ಸಂರಚನಾ option *long_options, ಪೂರ್ಣಾಙ್ಕ *idx)
{

	ಪ್ರತ್ಯಾಗಮ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ಪೂರ್ಣಾಙ್ಕ
getopt_long_only(ಪೂರ್ಣಾಙ್ಕ nargc, ವರ್ಣ * ಧ್ರುವ *nargv, ಧ್ರುವ ವರ್ಣ *options,
    ಧ್ರುವ ಸಂರಚನಾ option *long_options, ಪೂರ್ಣಾಙ್ಕ *idx)
{

	ಪ್ರತ್ಯಾಗಮ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
