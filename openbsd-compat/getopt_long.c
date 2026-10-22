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
#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#যদি 0
#অন্তর্ভাব <err.h>
#অন্তর্ভাব <getopt.h>
#endif
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "log.h"

সংরচনা option {
	/* name of long option */
	ধ্রুব বর্ণ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	পূর্ণাঙ্ক has_arg;
	/* if not NULL, set *flag to val when option found */
	পূর্ণাঙ্ক *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	পূর্ণাঙ্ক val;
};

পূর্ণাঙ্ক	opterr = 1;		/* if error message should be printed */
পূর্ণাঙ্ক	optind = 1;		/* index into parent argv vector */
পূর্ণাঙ্ক	optopt = '?';		/* character checked for validity */
পূর্ণাঙ্ক	optreset;		/* reset getopt */
বর্ণ    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(পূর্ণাঙ্ক)'?'
#define	BADARG		((*options == ':') ? (পূর্ণাঙ্ক)':' : (পূর্ণাঙ্ক)'?')
#define	মধ্যক্রম		(পূর্ণাঙ্ক)1

#define	EMSG		""

স্থির পূর্ণাঙ্ক getopt_internal(পূর্ণাঙ্ক, বর্ণ * ধ্রুব *, ধ্রুব বর্ণ *,
			   ধ্রুব সংরচনা option *, পূর্ণাঙ্ক *, পূর্ণাঙ্ক);
স্থির পূর্ণাঙ্ক parse_long_options(বর্ণ * ধ্রুব *, ধ্রুব বর্ণ *,
			      ধ্রুব সংরচনা option *, পূর্ণাঙ্ক *, পূর্ণাঙ্ক);
স্থির পূর্ণাঙ্ক gcd(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
স্থির শূন্য permute_args(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, বর্ণ * ধ্রুব *);

স্থির বর্ণ *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
স্থির পূর্ণাঙ্ক nonopt_start = -1; /* first non option argument (for permute) */
স্থির পূর্ণাঙ্ক nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
স্থির ধ্রুব বর্ণ recargchar[] = "option requires an argument -- %c";
স্থির ধ্রুব বর্ণ recargstring[] = "option requires an argument -- %s";
স্থির ধ্রুব বর্ণ ambig[] = "ambiguous option -- %.*s";
স্থির ধ্রুব বর্ণ noarg[] = "option doesn't take an argument -- %.*s";
স্থির ধ্রুব বর্ণ illoptchar[] = "unknown option -- %c";
স্থির ধ্রুব বর্ণ illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
স্থির পূর্ণাঙ্ক
gcd(পূর্ণাঙ্ক a, পূর্ণাঙ্ক b)
{
	পূর্ণাঙ্ক c;

	c = a % b;
	যাবত্ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	প্রত্যাগম (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
স্থির শূন্য
permute_args(পূর্ণাঙ্ক panonopt_start, পূর্ণাঙ্ক panonopt_end, পূর্ণাঙ্ক opt_end,
	বর্ণ * ধ্রুব *nargv)
{
	পূর্ণাঙ্ক cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	বর্ণ *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	প্রতি (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		প্রতি (j = 0; j < cyclelen; j++) {
			যদি (pos >= panonopt_end)
				pos -= nnonopts;
			অন্যথা
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((বর্ণ **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((বর্ণ **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
স্থির পূর্ণাঙ্ক
parse_long_options(বর্ণ * ধ্রুব *nargv, ধ্রুব বর্ণ *options,
	ধ্রুব সংরচনা option *long_options, পূর্ণাঙ্ক *idx, পূর্ণাঙ্ক short_too)
{
	বর্ণ *current_argv, *has_equal;
	size_t current_argv_len;
	পূর্ণাঙ্ক i, match;

	current_argv = place;
	match = -1;

	optind++;

	যদি ((has_equal = strchr(current_argv, '=')) != রিক্ত) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} অন্যথা
		current_argv_len = strlen(current_argv);

	প্রতি (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		যদি (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			অনুবর্ত;

		যদি (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			ভঙ্গ;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		যদি (short_too && current_argv_len == 1)
			অনুবর্ত;

		যদি (match == -1)	/* partial match */
			match = i;
		অন্যথা {
			/* ambiguous abbreviation */
			যদি (PRINT_ERROR)
				warnx(ambig, (পূর্ণাঙ্ক)current_argv_len,
				     current_argv);
			optopt = 0;
			প্রত্যাগম (BADCH);
		}
	}
	যদি (match != -1) {		/* option found */
		যদি (long_options[match].has_arg == no_argument
		    && has_equal) {
			যদি (PRINT_ERROR)
				warnx(noarg, (পূর্ণাঙ্ক)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			যদি (long_options[match].flag == রিক্ত)
				optopt = long_options[match].val;
			অন্যথা
				optopt = 0;
			প্রত্যাগম (BADARG);
		}
		যদি (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			যদি (has_equal)
				optarg = has_equal;
			অন্যথা যদি (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		যদি ((long_options[match].has_arg == required_argument)
		    && (optarg == রিক্ত)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			যদি (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			যদি (long_options[match].flag == রিক্ত)
				optopt = long_options[match].val;
			অন্যথা
				optopt = 0;
			--optind;
			প্রত্যাগম (BADARG);
		}
	} অন্যথা {			/* unknown option */
		যদি (short_too) {
			--optind;
			প্রত্যাগম (-1);
		}
		যদি (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		প্রত্যাগম (BADCH);
	}
	যদি (idx)
		*idx = match;
	যদি (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		প্রত্যাগম (0);
	} অন্যথা
		প্রত্যাগম (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
স্থির পূর্ণাঙ্ক
getopt_internal(পূর্ণাঙ্ক nargc, বর্ণ * ধ্রুব *nargv, ধ্রুব বর্ণ *options,
	ধ্রুব সংরচনা option *long_options, পূর্ণাঙ্ক *idx, পূর্ণাঙ্ক flags)
{
	বর্ণ *oli;				/* option letter list index */
	পূর্ণাঙ্ক optchar, short_too;
	স্থির পূর্ণাঙ্ক posixly_correct = -1;

	যদি (options == রিক্ত)
		প্রত্যাগম (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	যদি (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	যদি (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != রিক্ত);
	যদি (*options == '-')
		flags |= FLAG_ALLARGS;
	অন্যথা যদি (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	যদি (*options == '+' || *options == '-')
		options++;

	optarg = রিক্ত;
	যদি (optreset)
		nonopt_start = nonopt_end = -1;
start:
	যদি (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		যদি (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			যদি (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			অন্যথা যদি (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			প্রত্যাগম (-1);
		}
		যদি (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == রিক্ত)) {
			place = EMSG;		/* found non-option */
			যদি (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				প্রত্যাগম (মধ্যক্রম);
			}
			যদি (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				প্রত্যাগম (-1);
			}
			/* do permutation */
			যদি (nonopt_start == -1)
				nonopt_start = optind;
			অন্যথা যদি (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			গচ্ছ start;
		}
		যদি (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		যদি (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			যদি (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			প্রত্যাগম (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	যদি (long_options != রিক্ত && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		যদি (*place == '-')
			place++;		/* --foo long option */
		অন্যথা যদি (*place != ':' && strchr(options, *place) != রিক্ত)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		যদি (optchar != -1) {
			place = EMSG;
			প্রত্যাগম (optchar);
		}
	}

	যদি ((optchar = (পূর্ণাঙ্ক)*place++) == (পূর্ণাঙ্ক)':' ||
	    (optchar == (পূর্ণাঙ্ক)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == রিক্ত) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		যদি (optchar == (পূর্ণাঙ্ক)'-' && *place == '\0')
			প্রত্যাগম (-1);
		যদি (!*place)
			++optind;
		যদি (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		প্রত্যাগম (BADCH);
	}
	যদি (long_options != রিক্ত && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		যদি (*place)			/* no space */
			/* NOTHING */;
		অন্যথা যদি (++optind >= nargc) {	/* no arg */
			place = EMSG;
			যদি (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			প্রত্যাগম (BADARG);
		} অন্যথা				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		প্রত্যাগম (optchar);
	}
	যদি (*++oli != ':') {			/* doesn't take argument */
		যদি (!*place)
			++optind;
	} অন্যথা {				/* takes (optional) argument */
		optarg = রিক্ত;
		যদি (*place)			/* no white space */
			optarg = place;
		অন্যথা যদি (oli[1] != ':') {	/* arg not optional */
			যদি (++optind >= nargc) {	/* no arg */
				place = EMSG;
				যদি (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				প্রত্যাগম (BADARG);
			} অন্যথা
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	প্রত্যাগম (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
পূর্ণাঙ্ক
getopt(পূর্ণাঙ্ক nargc, বর্ণ * ধ্রুব *nargv, ধ্রুব বর্ণ *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	প্রত্যাগম (getopt_internal(nargc, nargv, options, রিক্ত, রিক্ত, 0));
}

#যদি 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
পূর্ণাঙ্ক
getopt_long(পূর্ণাঙ্ক nargc, বর্ণ * ধ্রুব *nargv, ধ্রুব বর্ণ *options,
    ধ্রুব সংরচনা option *long_options, পূর্ণাঙ্ক *idx)
{

	প্রত্যাগম (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
পূর্ণাঙ্ক
getopt_long_only(পূর্ণাঙ্ক nargc, বর্ণ * ধ্রুব *nargv, ধ্রুব বর্ণ *options,
    ধ্রুব সংরচনা option *long_options, পূর্ণাঙ্ক *idx)
{

	প্রত্যাগম (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
