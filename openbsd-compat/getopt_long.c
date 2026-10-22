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
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ warnx		logit

#ਜੇ 0
#ਅਨ੍ਤਰ੍ਭਾਵ <err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <getopt.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਬਣਤਰ option {
	/* name of long option */
	ਅਚਲ ਅੱਖਰ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ਪੂਰਨ has_arg;
	/* if not NULL, set *flag to val when option found */
	ਪੂਰਨ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ਪੂਰਨ val;
};

ਪੂਰਨ	opterr = 1;		/* if error message should be printed */
ਪੂਰਨ	optind = 1;		/* index into parent argv vector */
ਪੂਰਨ	optopt = '?';		/* character checked for validity */
ਪੂਰਨ	optreset;		/* reset getopt */
ਅੱਖਰ    *optarg;		/* argument associated with option */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PRINT_ERROR	((opterr) && (*options != ':'))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_ਕ੍ਰਮ_ਬਦਲੋ	0x01	/* permute non-options to the end of argv */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	BADCH		(ਪੂਰਨ)'?'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	BADARG		((*options == ':') ? (ਪੂਰਨ)':' : (ਪੂਰਨ)'?')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ਮੱਧਕ੍ਰਮ		(ਪੂਰਨ)1

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	EMSG		""

ਸਥਿਰ ਪੂਰਨ getopt_ਅੰਦਰੂਨੀ(ਪੂਰਨ, ਅੱਖਰ * ਅਚਲ *, ਅਚਲ ਅੱਖਰ *,
			   ਅਚਲ ਬਣਤਰ option *, ਪੂਰਨ *, ਪੂਰਨ);
ਸਥਿਰ ਪੂਰਨ parse_long_options(ਅੱਖਰ * ਅਚਲ *, ਅਚਲ ਅੱਖਰ *,
			      ਅਚਲ ਬਣਤਰ option *, ਪੂਰਨ *, ਪੂਰਨ);
ਸਥਿਰ ਪੂਰਨ ਮਹੱਤਮ_ਸਾਂਝਾ_ਭਾਜਕ(ਪੂਰਨ, ਪੂਰਨ);
ਸਥਿਰ ਖਾਲੀ ਕ੍ਰਮ_ਬਦਲੋ_ਦਲੀਲਾਂ(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ * ਅਚਲ *);

ਸਥਿਰ ਅੱਖਰ *ਰੱਖੋ = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ਸਥਿਰ ਪੂਰਨ nonopt_ਸ਼ੁਰੂ = -1; /* first non option argument (for permute) */
ਸਥਿਰ ਪੂਰਨ nonopt_ਸਿਰਾ = -1;   /* first option after non options (for permute) */

/* Error messages */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ recargchar[] = "option requires an argument -- %c";
ਸਥਿਰ ਅਚਲ ਅੱਖਰ recargstring[] = "option requires an argument -- %s";
ਸਥਿਰ ਅਚਲ ਅੱਖਰ ambig[] = "ambiguous option -- %.*s";
ਸਥਿਰ ਅਚਲ ਅੱਖਰ noarg[] = "option doesn't take an argument -- %.*s";
ਸਥਿਰ ਅਚਲ ਅੱਖਰ illoptchar[] = "unknown option -- %c";
ਸਥਿਰ ਅਚਲ ਅੱਖਰ illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ਸਥਿਰ ਪੂਰਨ
ਮਹੱਤਮ_ਸਾਂਝਾ_ਭਾਜਕ(ਪੂਰਨ a, ਪੂਰਨ b)
{
	ਪੂਰਨ c;

	c = a % b;
	ਜਦੋਂ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ਵਾਪਸ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ਸਥਿਰ ਖਾਲੀ
ਕ੍ਰਮ_ਬਦਲੋ_ਦਲੀਲਾਂ(ਪੂਰਨ panonopt_ਸ਼ੁਰੂ, ਪੂਰਨ panonopt_ਸਿਰਾ, ਪੂਰਨ opt_ਸਿਰਾ,
	ਅੱਖਰ * ਅਚਲ *nargv)
{
	ਪੂਰਨ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	ਅੱਖਰ *ਅਦਲਾ_ਬਦਲੀ;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_ਸਿਰਾ - panonopt_ਸ਼ੁਰੂ;
	nopts = opt_ਸਿਰਾ - panonopt_ਸਿਰਾ;
	ncycle = ਮਹੱਤਮ_ਸਾਂਝਾ_ਭਾਜਕ(nnonopts, nopts);
	cyclelen = (opt_ਸਿਰਾ - panonopt_ਸ਼ੁਰੂ) / ncycle;

	ਲਈ (i = 0; i < ncycle; i++) {
		cstart = panonopt_ਸਿਰਾ+i;
		pos = cstart;
		ਲਈ (j = 0; j < cyclelen; j++) {
			ਜੇ (pos >= panonopt_ਸਿਰਾ)
				pos -= nnonopts;
			ਨਹੀਂਤਾਂ
				pos += nopts;
			ਅਦਲਾ_ਬਦਲੀ = nargv[pos];
			/* LINTED const cast */
			((ਅੱਖਰ **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((ਅੱਖਰ **)nargv)[cstart] = ਅਦਲਾ_ਬਦਲੀ;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ਸਥਿਰ ਪੂਰਨ
parse_long_options(ਅੱਖਰ * ਅਚਲ *nargv, ਅਚਲ ਅੱਖਰ *options,
	ਅਚਲ ਬਣਤਰ option *long_options, ਪੂਰਨ *idx, ਪੂਰਨ short_too)
{
	ਅੱਖਰ *current_argv, *has_equal;
	ਮਾਪ_t current_argv_len;
	ਪੂਰਨ i, ਮੇਲ;

	current_argv = ਰੱਖੋ;
	ਮੇਲ = -1;

	optind++;

	ਜੇ ((has_equal = strchr(current_argv, '=')) != ਨਿਰਾ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} ਨਹੀਂਤਾਂ
		current_argv_len = ਲੜੀ_ਲੰਬਾਈ(current_argv);

	ਲਈ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(current_argv, long_options[i].name,
		    current_argv_len))
			ਜਾਰੀ;

		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(long_options[i].name) == current_argv_len) {
			/* exact match */
			ਮੇਲ = i;
			ਰੋਕੋ;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ਜੇ (short_too && current_argv_len == 1)
			ਜਾਰੀ;

		ਜੇ (ਮੇਲ == -1)	/* partial match */
			ਮੇਲ = i;
		ਨਹੀਂਤਾਂ {
			/* ambiguous abbreviation */
			ਜੇ (PRINT_ERROR)
				warnx(ambig, (ਪੂਰਨ)current_argv_len,
				     current_argv);
			optopt = 0;
			ਵਾਪਸ (BADCH);
		}
	}
	ਜੇ (ਮੇਲ != -1) {		/* option found */
		ਜੇ (long_options[ਮੇਲ].has_arg == no_argument
		    && has_equal) {
			ਜੇ (PRINT_ERROR)
				warnx(noarg, (ਪੂਰਨ)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ਜੇ (long_options[ਮੇਲ].flag == ਨਿਰਾ)
				optopt = long_options[ਮੇਲ].val;
			ਨਹੀਂਤਾਂ
				optopt = 0;
			ਵਾਪਸ (BADARG);
		}
		ਜੇ (long_options[ਮੇਲ].has_arg == required_argument ||
		    long_options[ਮੇਲ].has_arg == optional_argument) {
			ਜੇ (has_equal)
				optarg = has_equal;
			ਨਹੀਂਤਾਂ ਜੇ (long_options[ਮੇਲ].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ਜੇ ((long_options[ਮੇਲ].has_arg == required_argument)
		    && (optarg == ਨਿਰਾ)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ਜੇ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ਜੇ (long_options[ਮੇਲ].flag == ਨਿਰਾ)
				optopt = long_options[ਮੇਲ].val;
			ਨਹੀਂਤਾਂ
				optopt = 0;
			--optind;
			ਵਾਪਸ (BADARG);
		}
	} ਨਹੀਂਤਾਂ {			/* unknown option */
		ਜੇ (short_too) {
			--optind;
			ਵਾਪਸ (-1);
		}
		ਜੇ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ਵਾਪਸ (BADCH);
	}
	ਜੇ (idx)
		*idx = ਮੇਲ;
	ਜੇ (long_options[ਮੇਲ].flag) {
		*long_options[ਮੇਲ].flag = long_options[ਮੇਲ].val;
		ਵਾਪਸ (0);
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ (long_options[ਮੇਲ].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ਸਥਿਰ ਪੂਰਨ
getopt_ਅੰਦਰੂਨੀ(ਪੂਰਨ nargc, ਅੱਖਰ * ਅਚਲ *nargv, ਅਚਲ ਅੱਖਰ *options,
	ਅਚਲ ਬਣਤਰ option *long_options, ਪੂਰਨ *idx, ਪੂਰਨ flags)
{
	ਅੱਖਰ *oli;				/* option letter list index */
	ਪੂਰਨ optchar, short_too;
	ਸਥਿਰ ਪੂਰਨ posixly_correct = -1;

	ਜੇ (options == ਨਿਰਾ)
		ਵਾਪਸ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ਜੇ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ਜੇ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ਨਿਰਾ);
	ਜੇ (*options == '-')
		flags |= FLAG_ALLARGS;
	ਨਹੀਂਤਾਂ ਜੇ (posixly_correct || *options == '+')
		flags &= ~FLAG_ਕ੍ਰਮ_ਬਦਲੋ;
	ਜੇ (*options == '+' || *options == '-')
		options++;

	optarg = ਨਿਰਾ;
	ਜੇ (optreset)
		nonopt_ਸ਼ੁਰੂ = nonopt_ਸਿਰਾ = -1;
ਸ਼ੁਰੂ:
	ਜੇ (optreset || !*ਰੱਖੋ) {		/* update scanning pointer */
		optreset = 0;
		ਜੇ (optind >= nargc) {          /* end of argument vector */
			ਰੱਖੋ = EMSG;
			ਜੇ (nonopt_ਸਿਰਾ != -1) {
				/* do permutation, if we have to */
				ਕ੍ਰਮ_ਬਦਲੋ_ਦਲੀਲਾਂ(nonopt_ਸ਼ੁਰੂ, nonopt_ਸਿਰਾ,
				    optind, nargv);
				optind -= nonopt_ਸਿਰਾ - nonopt_ਸ਼ੁਰੂ;
			}
			ਨਹੀਂਤਾਂ ਜੇ (nonopt_ਸ਼ੁਰੂ != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_ਸ਼ੁਰੂ;
			}
			nonopt_ਸ਼ੁਰੂ = nonopt_ਸਿਰਾ = -1;
			ਵਾਪਸ (-1);
		}
		ਜੇ (*(ਰੱਖੋ = nargv[optind]) != '-' ||
		    (ਰੱਖੋ[1] == '\0' && strchr(options, '-') == ਨਿਰਾ)) {
			ਰੱਖੋ = EMSG;		/* found non-option */
			ਜੇ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ਵਾਪਸ (ਮੱਧਕ੍ਰਮ);
			}
			ਜੇ (!(flags & FLAG_ਕ੍ਰਮ_ਬਦਲੋ)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ਵਾਪਸ (-1);
			}
			/* do permutation */
			ਜੇ (nonopt_ਸ਼ੁਰੂ == -1)
				nonopt_ਸ਼ੁਰੂ = optind;
			ਨਹੀਂਤਾਂ ਜੇ (nonopt_ਸਿਰਾ != -1) {
				ਕ੍ਰਮ_ਬਦਲੋ_ਦਲੀਲਾਂ(nonopt_ਸ਼ੁਰੂ, nonopt_ਸਿਰਾ,
				    optind, nargv);
				nonopt_ਸ਼ੁਰੂ = optind -
				    (nonopt_ਸਿਰਾ - nonopt_ਸ਼ੁਰੂ);
				nonopt_ਸਿਰਾ = -1;
			}
			optind++;
			/* process next argument */
			ਜਾਓ ਸ਼ੁਰੂ;
		}
		ਜੇ (nonopt_ਸ਼ੁਰੂ != -1 && nonopt_ਸਿਰਾ == -1)
			nonopt_ਸਿਰਾ = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ਜੇ (ਰੱਖੋ[1] != '\0' && *++ਰੱਖੋ == '-' && ਰੱਖੋ[1] == '\0') {
			optind++;
			ਰੱਖੋ = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ਜੇ (nonopt_ਸਿਰਾ != -1) {
				ਕ੍ਰਮ_ਬਦਲੋ_ਦਲੀਲਾਂ(nonopt_ਸ਼ੁਰੂ, nonopt_ਸਿਰਾ,
				    optind, nargv);
				optind -= nonopt_ਸਿਰਾ - nonopt_ਸ਼ੁਰੂ;
			}
			nonopt_ਸ਼ੁਰੂ = nonopt_ਸਿਰਾ = -1;
			ਵਾਪਸ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ਜੇ (long_options != ਨਿਰਾ && ਰੱਖੋ != nargv[optind] &&
	    (*ਰੱਖੋ == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ਜੇ (*ਰੱਖੋ == '-')
			ਰੱਖੋ++;		/* --foo long option */
		ਨਹੀਂਤਾਂ ਜੇ (*ਰੱਖੋ != ':' && strchr(options, *ਰੱਖੋ) != ਨਿਰਾ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ਜੇ (optchar != -1) {
			ਰੱਖੋ = EMSG;
			ਵਾਪਸ (optchar);
		}
	}

	ਜੇ ((optchar = (ਪੂਰਨ)*ਰੱਖੋ++) == (ਪੂਰਨ)':' ||
	    (optchar == (ਪੂਰਨ)'-' && *ਰੱਖੋ != '\0') ||
	    (oli = strchr(options, optchar)) == ਨਿਰਾ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ਜੇ (optchar == (ਪੂਰਨ)'-' && *ਰੱਖੋ == '\0')
			ਵਾਪਸ (-1);
		ਜੇ (!*ਰੱਖੋ)
			++optind;
		ਜੇ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ਵਾਪਸ (BADCH);
	}
	ਜੇ (long_options != ਨਿਰਾ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ਜੇ (*ਰੱਖੋ)			/* no space */
			/* NOTHING */;
		ਨਹੀਂਤਾਂ ਜੇ (++optind >= nargc) {	/* no arg */
			ਰੱਖੋ = EMSG;
			ਜੇ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ਵਾਪਸ (BADARG);
		} ਨਹੀਂਤਾਂ				/* white space */
			ਰੱਖੋ = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		ਰੱਖੋ = EMSG;
		ਵਾਪਸ (optchar);
	}
	ਜੇ (*++oli != ':') {			/* doesn't take argument */
		ਜੇ (!*ਰੱਖੋ)
			++optind;
	} ਨਹੀਂਤਾਂ {				/* takes (optional) argument */
		optarg = ਨਿਰਾ;
		ਜੇ (*ਰੱਖੋ)			/* no white space */
			optarg = ਰੱਖੋ;
		ਨਹੀਂਤਾਂ ਜੇ (oli[1] != ':') {	/* arg not optional */
			ਜੇ (++optind >= nargc) {	/* no arg */
				ਰੱਖੋ = EMSG;
				ਜੇ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ਵਾਪਸ (BADARG);
			} ਨਹੀਂਤਾਂ
				optarg = nargv[optind];
		}
		ਰੱਖੋ = EMSG;
		++optind;
	}
	/* dump back option letter */
	ਵਾਪਸ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ਪੂਰਨ
getopt(ਪੂਰਨ nargc, ਅੱਖਰ * ਅਚਲ *nargv, ਅਚਲ ਅੱਖਰ *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ਵਾਪਸ (getopt_ਅੰਦਰੂਨੀ(nargc, nargv, options, ਨਿਰਾ, ਨਿਰਾ, 0));
}

#ਜੇ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ਪੂਰਨ
getopt_long(ਪੂਰਨ nargc, ਅੱਖਰ * ਅਚਲ *nargv, ਅਚਲ ਅੱਖਰ *options,
    ਅਚਲ ਬਣਤਰ option *long_options, ਪੂਰਨ *idx)
{

	ਵਾਪਸ (getopt_ਅੰਦਰੂਨੀ(nargc, nargv, options, long_options, idx,
	    FLAG_ਕ੍ਰਮ_ਬਦਲੋ));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ਪੂਰਨ
getopt_long_only(ਪੂਰਨ nargc, ਅੱਖਰ * ਅਚਲ *nargv, ਅਚਲ ਅੱਖਰ *options,
    ਅਚਲ ਬਣਤਰ option *long_options, ਪੂਰਨ *idx)
{

	ਵਾਪਸ (getopt_ਅੰਦਰੂਨੀ(nargc, nargv, options, long_options, idx,
	    FLAG_ਕ੍ਰਮ_ਬਦਲੋ|FLAG_LONGONLY));
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
