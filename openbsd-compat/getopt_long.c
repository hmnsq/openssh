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

#ಆದರೆ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು warnx		logit

#ಆದರೆ 0
#ಅನ್ತರ್ಭಾವ <err.h>
#ಅನ್ತರ್ಭಾವ <getopt.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ರಚನೆ option {
	/* name of long option */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ಪೂರ್ಣಾಂಕ has_arg;
	/* if not NULL, set *flag to val when option found */
	ಪೂರ್ಣಾಂಕ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ಪೂರ್ಣಾಂಕ val;
};

ಪೂರ್ಣಾಂಕ	opterr = 1;		/* if error message should be printed */
ಪೂರ್ಣಾಂಕ	optind = 1;		/* index into parent argv vector */
ಪೂರ್ಣಾಂಕ	optopt = '?';		/* character checked for validity */
ಪೂರ್ಣಾಂಕ	optreset;		/* reset getopt */
ಅಕ್ಷರ    *optarg;		/* argument associated with option */

#ವ್ಯಾಖ್ಯಾನಿಸು PRINT_ERROR	((opterr) && (*options != ':'))

#ವ್ಯಾಖ್ಯಾನಿಸು FLAG_ಕ್ರಮಬದಲಾವಣೆ	0x01	/* permute non-options to the end of argv */
#ವ್ಯಾಖ್ಯಾನಿಸು FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#ವ್ಯಾಖ್ಯಾನಿಸು FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#ವ್ಯಾಖ್ಯಾನಿಸು	BADCH		(ಪೂರ್ಣಾಂಕ)'?'
#ವ್ಯಾಖ್ಯಾನಿಸು	BADARG		((*options == ':') ? (ಪೂರ್ಣಾಂಕ)':' : (ಪೂರ್ಣಾಂಕ)'?')
#ವ್ಯಾಖ್ಯಾನಿಸು	ಮಧ್ಯಕ್ರಮ		(ಪೂರ್ಣಾಂಕ)1

#ವ್ಯಾಖ್ಯಾನಿಸು	EMSG		""

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ getopt_ಆಂತರಿಕ(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
			   ಸ್ಥಿರಾಂಕ ರಚನೆ option *, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ parse_long_options(ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
			      ಸ್ಥಿರಾಂಕ ರಚನೆ option *, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಮಹತ್ತಮ_ಸಾಮಾನ್ಯ_ಅಪವರ್ತನ(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಶೂನ್ಯ ಕ್ರಮಬದಲಾವಣೆ_ವಾದಗಳು(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *);

ಸ್ಥಿರ ಅಕ್ಷರ *ಇರಿಸು = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ nonopt_ಆರಂಭ = -1; /* first non option argument (for permute) */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ nonopt_ಕೊನೆ = -1;   /* first option after non options (for permute) */

/* Error messages */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ recargchar[] = "option requires an argument -- %c";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ recargstring[] = "option requires an argument -- %s";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ ambig[] = "ambiguous option -- %.*s";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ noarg[] = "option doesn't take an argument -- %.*s";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ illoptchar[] = "unknown option -- %c";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಮಹತ್ತಮ_ಸಾಮಾನ್ಯ_ಅಪವರ್ತನ(ಪೂರ್ಣಾಂಕ a, ಪೂರ್ಣಾಂಕ b)
{
	ಪೂರ್ಣಾಂಕ c;

	c = a % b;
	ಆಗ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ಹಿಂತಿರುಗಿ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಕ್ರಮಬದಲಾವಣೆ_ವಾದಗಳು(ಪೂರ್ಣಾಂಕ panonopt_ಆರಂಭ, ಪೂರ್ಣಾಂಕ panonopt_ಕೊನೆ, ಪೂರ್ಣಾಂಕ opt_ಕೊನೆ,
	ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv)
{
	ಪೂರ್ಣಾಂಕ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	ಅಕ್ಷರ *ಅದಲುಬದಲು;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_ಕೊನೆ - panonopt_ಆರಂಭ;
	nopts = opt_ಕೊನೆ - panonopt_ಕೊನೆ;
	ncycle = ಮಹತ್ತಮ_ಸಾಮಾನ್ಯ_ಅಪವರ್ತನ(nnonopts, nopts);
	cyclelen = (opt_ಕೊನೆ - panonopt_ಆರಂಭ) / ncycle;

	ಗಾಗಿ (i = 0; i < ncycle; i++) {
		cstart = panonopt_ಕೊನೆ+i;
		pos = cstart;
		ಗಾಗಿ (j = 0; j < cyclelen; j++) {
			ಆದರೆ (pos >= panonopt_ಕೊನೆ)
				pos -= nnonopts;
			ಇಲ್ಲದಿದ್ದರೆ
				pos += nopts;
			ಅದಲುಬದಲು = nargv[pos];
			/* LINTED const cast */
			((ಅಕ್ಷರ **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((ಅಕ್ಷರ **)nargv)[cstart] = ಅದಲುಬದಲು;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_long_options(ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *options,
	ಸ್ಥಿರಾಂಕ ರಚನೆ option *long_options, ಪೂರ್ಣಾಂಕ *idx, ಪೂರ್ಣಾಂಕ short_too)
{
	ಅಕ್ಷರ *current_argv, *has_equal;
	ಗಾತ್ರ_t current_argv_len;
	ಪೂರ್ಣಾಂಕ i, ಹೊಂದಿಕೆ;

	current_argv = ಇರಿಸು;
	ಹೊಂದಿಕೆ = -1;

	optind++;

	ಆದರೆ ((has_equal = strchr(current_argv, '=')) != ಖಾಲಿ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} ಇಲ್ಲದಿದ್ದರೆ
		current_argv_len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(current_argv);

	ಗಾಗಿ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(current_argv, long_options[i].name,
		    current_argv_len))
			ಮುಂದುವರಿ;

		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(long_options[i].name) == current_argv_len) {
			/* exact match */
			ಹೊಂದಿಕೆ = i;
			ನಿಲ್ಲಿಸು;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ಆದರೆ (short_too && current_argv_len == 1)
			ಮುಂದುವರಿ;

		ಆದರೆ (ಹೊಂದಿಕೆ == -1)	/* partial match */
			ಹೊಂದಿಕೆ = i;
		ಇಲ್ಲದಿದ್ದರೆ {
			/* ambiguous abbreviation */
			ಆದರೆ (PRINT_ERROR)
				warnx(ambig, (ಪೂರ್ಣಾಂಕ)current_argv_len,
				     current_argv);
			optopt = 0;
			ಹಿಂತಿರುಗಿ (BADCH);
		}
	}
	ಆದರೆ (ಹೊಂದಿಕೆ != -1) {		/* option found */
		ಆದರೆ (long_options[ಹೊಂದಿಕೆ].has_arg == no_argument
		    && has_equal) {
			ಆದರೆ (PRINT_ERROR)
				warnx(noarg, (ಪೂರ್ಣಾಂಕ)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ಆದರೆ (long_options[ಹೊಂದಿಕೆ].flag == ಖಾಲಿ)
				optopt = long_options[ಹೊಂದಿಕೆ].val;
			ಇಲ್ಲದಿದ್ದರೆ
				optopt = 0;
			ಹಿಂತಿರುಗಿ (BADARG);
		}
		ಆದರೆ (long_options[ಹೊಂದಿಕೆ].has_arg == required_argument ||
		    long_options[ಹೊಂದಿಕೆ].has_arg == optional_argument) {
			ಆದರೆ (has_equal)
				optarg = has_equal;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (long_options[ಹೊಂದಿಕೆ].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ಆದರೆ ((long_options[ಹೊಂದಿಕೆ].has_arg == required_argument)
		    && (optarg == ಖಾಲಿ)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ಆದರೆ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ಆದರೆ (long_options[ಹೊಂದಿಕೆ].flag == ಖಾಲಿ)
				optopt = long_options[ಹೊಂದಿಕೆ].val;
			ಇಲ್ಲದಿದ್ದರೆ
				optopt = 0;
			--optind;
			ಹಿಂತಿರುಗಿ (BADARG);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {			/* unknown option */
		ಆದರೆ (short_too) {
			--optind;
			ಹಿಂತಿರುಗಿ (-1);
		}
		ಆದರೆ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ಹಿಂತಿರುಗಿ (BADCH);
	}
	ಆದರೆ (idx)
		*idx = ಹೊಂದಿಕೆ;
	ಆದರೆ (long_options[ಹೊಂದಿಕೆ].flag) {
		*long_options[ಹೊಂದಿಕೆ].flag = long_options[ಹೊಂದಿಕೆ].val;
		ಹಿಂತಿರುಗಿ (0);
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (long_options[ಹೊಂದಿಕೆ].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
getopt_ಆಂತರಿಕ(ಪೂರ್ಣಾಂಕ nargc, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *options,
	ಸ್ಥಿರಾಂಕ ರಚನೆ option *long_options, ಪೂರ್ಣಾಂಕ *idx, ಪೂರ್ಣಾಂಕ flags)
{
	ಅಕ್ಷರ *oli;				/* option letter list index */
	ಪೂರ್ಣಾಂಕ optchar, short_too;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ posixly_correct = -1;

	ಆದರೆ (options == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ಆದರೆ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ಆದರೆ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ಖಾಲಿ);
	ಆದರೆ (*options == '-')
		flags |= FLAG_ALLARGS;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (posixly_correct || *options == '+')
		flags &= ~FLAG_ಕ್ರಮಬದಲಾವಣೆ;
	ಆದರೆ (*options == '+' || *options == '-')
		options++;

	optarg = ಖಾಲಿ;
	ಆದರೆ (optreset)
		nonopt_ಆರಂಭ = nonopt_ಕೊನೆ = -1;
ಆರಂಭ:
	ಆದರೆ (optreset || !*ಇರಿಸು) {		/* update scanning pointer */
		optreset = 0;
		ಆದರೆ (optind >= nargc) {          /* end of argument vector */
			ಇರಿಸು = EMSG;
			ಆದರೆ (nonopt_ಕೊನೆ != -1) {
				/* do permutation, if we have to */
				ಕ್ರಮಬದಲಾವಣೆ_ವಾದಗಳು(nonopt_ಆರಂಭ, nonopt_ಕೊನೆ,
				    optind, nargv);
				optind -= nonopt_ಕೊನೆ - nonopt_ಆರಂಭ;
			}
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nonopt_ಆರಂಭ != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_ಆರಂಭ;
			}
			nonopt_ಆರಂಭ = nonopt_ಕೊನೆ = -1;
			ಹಿಂತಿರುಗಿ (-1);
		}
		ಆದರೆ (*(ಇರಿಸು = nargv[optind]) != '-' ||
		    (ಇರಿಸು[1] == '\0' && strchr(options, '-') == ಖಾಲಿ)) {
			ಇರಿಸು = EMSG;		/* found non-option */
			ಆದರೆ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ಹಿಂತಿರುಗಿ (ಮಧ್ಯಕ್ರಮ);
			}
			ಆದರೆ (!(flags & FLAG_ಕ್ರಮಬದಲಾವಣೆ)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ಹಿಂತಿರುಗಿ (-1);
			}
			/* do permutation */
			ಆದರೆ (nonopt_ಆರಂಭ == -1)
				nonopt_ಆರಂಭ = optind;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nonopt_ಕೊನೆ != -1) {
				ಕ್ರಮಬದಲಾವಣೆ_ವಾದಗಳು(nonopt_ಆರಂಭ, nonopt_ಕೊನೆ,
				    optind, nargv);
				nonopt_ಆರಂಭ = optind -
				    (nonopt_ಕೊನೆ - nonopt_ಆರಂಭ);
				nonopt_ಕೊನೆ = -1;
			}
			optind++;
			/* process next argument */
			ಹೋಗು ಆರಂಭ;
		}
		ಆದರೆ (nonopt_ಆರಂಭ != -1 && nonopt_ಕೊನೆ == -1)
			nonopt_ಕೊನೆ = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ಆದರೆ (ಇರಿಸು[1] != '\0' && *++ಇರಿಸು == '-' && ಇರಿಸು[1] == '\0') {
			optind++;
			ಇರಿಸು = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ಆದರೆ (nonopt_ಕೊನೆ != -1) {
				ಕ್ರಮಬದಲಾವಣೆ_ವಾದಗಳು(nonopt_ಆರಂಭ, nonopt_ಕೊನೆ,
				    optind, nargv);
				optind -= nonopt_ಕೊನೆ - nonopt_ಆರಂಭ;
			}
			nonopt_ಆರಂಭ = nonopt_ಕೊನೆ = -1;
			ಹಿಂತಿರುಗಿ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ಆದರೆ (long_options != ಖಾಲಿ && ಇರಿಸು != nargv[optind] &&
	    (*ಇರಿಸು == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ಆದರೆ (*ಇರಿಸು == '-')
			ಇರಿಸು++;		/* --foo long option */
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*ಇರಿಸು != ':' && strchr(options, *ಇರಿಸು) != ಖಾಲಿ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ಆದರೆ (optchar != -1) {
			ಇರಿಸು = EMSG;
			ಹಿಂತಿರುಗಿ (optchar);
		}
	}

	ಆದರೆ ((optchar = (ಪೂರ್ಣಾಂಕ)*ಇರಿಸು++) == (ಪೂರ್ಣಾಂಕ)':' ||
	    (optchar == (ಪೂರ್ಣಾಂಕ)'-' && *ಇರಿಸು != '\0') ||
	    (oli = strchr(options, optchar)) == ಖಾಲಿ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ಆದರೆ (optchar == (ಪೂರ್ಣಾಂಕ)'-' && *ಇರಿಸು == '\0')
			ಹಿಂತಿರುಗಿ (-1);
		ಆದರೆ (!*ಇರಿಸು)
			++optind;
		ಆದರೆ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ಹಿಂತಿರುಗಿ (BADCH);
	}
	ಆದರೆ (long_options != ಖಾಲಿ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ಆದರೆ (*ಇರಿಸು)			/* no space */
			/* NOTHING */;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (++optind >= nargc) {	/* no arg */
			ಇರಿಸು = EMSG;
			ಆದರೆ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ಹಿಂತಿರುಗಿ (BADARG);
		} ಇಲ್ಲದಿದ್ದರೆ				/* white space */
			ಇರಿಸು = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		ಇರಿಸು = EMSG;
		ಹಿಂತಿರುಗಿ (optchar);
	}
	ಆದರೆ (*++oli != ':') {			/* doesn't take argument */
		ಆದರೆ (!*ಇರಿಸು)
			++optind;
	} ಇಲ್ಲದಿದ್ದರೆ {				/* takes (optional) argument */
		optarg = ಖಾಲಿ;
		ಆದರೆ (*ಇರಿಸು)			/* no white space */
			optarg = ಇರಿಸು;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (oli[1] != ':') {	/* arg not optional */
			ಆದರೆ (++optind >= nargc) {	/* no arg */
				ಇರಿಸು = EMSG;
				ಆದರೆ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ಹಿಂತಿರುಗಿ (BADARG);
			} ಇಲ್ಲದಿದ್ದರೆ
				optarg = nargv[optind];
		}
		ಇರಿಸು = EMSG;
		++optind;
	}
	/* dump back option letter */
	ಹಿಂತಿರುಗಿ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ಪೂರ್ಣಾಂಕ
getopt(ಪೂರ್ಣಾಂಕ nargc, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ಹಿಂತಿರುಗಿ (getopt_ಆಂತರಿಕ(nargc, nargv, options, ಖಾಲಿ, ಖಾಲಿ, 0));
}

#ಆದರೆ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ಪೂರ್ಣಾಂಕ
getopt_long(ಪೂರ್ಣಾಂಕ nargc, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *options,
    ಸ್ಥಿರಾಂಕ ರಚನೆ option *long_options, ಪೂರ್ಣಾಂಕ *idx)
{

	ಹಿಂತಿರುಗಿ (getopt_ಆಂತರಿಕ(nargc, nargv, options, long_options, idx,
	    FLAG_ಕ್ರಮಬದಲಾವಣೆ));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ಪೂರ್ಣಾಂಕ
getopt_long_only(ಪೂರ್ಣಾಂಕ nargc, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *nargv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *options,
    ಸ್ಥಿರಾಂಕ ರಚನೆ option *long_options, ಪೂರ್ಣಾಂಕ *idx)
{

	ಹಿಂತಿರುಗಿ (getopt_ಆಂತರಿಕ(nargc, nargv, options, long_options, idx,
	    FLAG_ಕ್ರಮಬದಲಾವಣೆ|FLAG_LONGONLY));
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
