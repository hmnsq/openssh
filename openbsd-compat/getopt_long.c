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
#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#ଯଦି 0
#ଅନ୍ତର୍ଭାଵ <err.h>
#ଅନ୍ତର୍ଭାଵ <getopt.h>
#endif
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

ସଂରଚନା option {
	/* name of long option */
	ଅଚଳ ଅକ୍ଷର *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା has_arg;
	/* if not NULL, set *flag to val when option found */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	opterr = 1;		/* if error message should be printed */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	optind = 1;		/* index into parent argv vector */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	optopt = '?';		/* character checked for validity */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	optreset;		/* reset getopt */
ଅକ୍ଷର    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(ପୂର୍ଣ୍ଣସଂଖ୍ୟା)'?'
#define	BADARG		((*options == ':') ? (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)':' : (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)'?')
#define	ମଧ୍ୟକ୍ରମ		(ପୂର୍ଣ୍ଣସଂଖ୍ୟା)1

#define	EMSG		""

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା getopt_internal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର * ଅଚଳ *, ଅଚଳ ଅକ୍ଷର *,
			   ଅଚଳ ସଂରଚନା option *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା parse_long_options(ଅକ୍ଷର * ଅଚଳ *, ଅଚଳ ଅକ୍ଷର *,
			      ଅଚଳ ସଂରଚନା option *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା gcd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ଶୂନ୍ୟ permute_args(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର * ଅଚଳ *);

ସ୍ଥିର ଅକ୍ଷର *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonopt_start = -1; /* first non option argument (for permute) */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର recargchar[] = "option requires an argument -- %c";
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର recargstring[] = "option requires an argument -- %s";
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର ambig[] = "ambiguous option -- %.*s";
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର noarg[] = "option doesn't take an argument -- %.*s";
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର illoptchar[] = "unknown option -- %c";
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
gcd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c;

	c = a % b;
	ଯେତେବେଳେ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ଫେରନ୍ତୁ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ସ୍ଥିର ଶୂନ୍ୟ
permute_args(ପୂର୍ଣ୍ଣସଂଖ୍ୟା panonopt_start, ପୂର୍ଣ୍ଣସଂଖ୍ୟା panonopt_end, ପୂର୍ଣ୍ଣସଂଖ୍ୟା opt_end,
	ଅକ୍ଷର * ଅଚଳ *nargv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	ଅକ୍ଷର *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	ପାଇଁ (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		ପାଇଁ (j = 0; j < cyclelen; j++) {
			ଯଦି (pos >= panonopt_end)
				pos -= nnonopts;
			ଅନ୍ୟଥା
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((ଅକ୍ଷର **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((ଅକ୍ଷର **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_long_options(ଅକ୍ଷର * ଅଚଳ *nargv, ଅଚଳ ଅକ୍ଷର *options,
	ଅଚଳ ସଂରଚନା option *long_options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *idx, ପୂର୍ଣ୍ଣସଂଖ୍ୟା short_too)
{
	ଅକ୍ଷର *current_argv, *has_equal;
	size_t current_argv_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, match;

	current_argv = place;
	match = -1;

	optind++;

	ଯଦି ((has_equal = strchr(current_argv, '=')) != ଖାଲି) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} ଅନ୍ୟଥା
		current_argv_len = strlen(current_argv);

	ପାଇଁ (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ଯଦି (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			ଜାରି;

		ଯଦି (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			ଭାଙ୍ଗ;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ଯଦି (short_too && current_argv_len == 1)
			ଜାରି;

		ଯଦି (match == -1)	/* partial match */
			match = i;
		ଅନ୍ୟଥା {
			/* ambiguous abbreviation */
			ଯଦି (PRINT_ERROR)
				warnx(ambig, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)current_argv_len,
				     current_argv);
			optopt = 0;
			ଫେରନ୍ତୁ (BADCH);
		}
	}
	ଯଦି (match != -1) {		/* option found */
		ଯଦି (long_options[match].has_arg == no_argument
		    && has_equal) {
			ଯଦି (PRINT_ERROR)
				warnx(noarg, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ଯଦି (long_options[match].flag == ଖାଲି)
				optopt = long_options[match].val;
			ଅନ୍ୟଥା
				optopt = 0;
			ଫେରନ୍ତୁ (BADARG);
		}
		ଯଦି (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			ଯଦି (has_equal)
				optarg = has_equal;
			ଅନ୍ୟଥା ଯଦି (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ଯଦି ((long_options[match].has_arg == required_argument)
		    && (optarg == ଖାଲି)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ଯଦି (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ଯଦି (long_options[match].flag == ଖାଲି)
				optopt = long_options[match].val;
			ଅନ୍ୟଥା
				optopt = 0;
			--optind;
			ଫେରନ୍ତୁ (BADARG);
		}
	} ଅନ୍ୟଥା {			/* unknown option */
		ଯଦି (short_too) {
			--optind;
			ଫେରନ୍ତୁ (-1);
		}
		ଯଦି (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ଫେରନ୍ତୁ (BADCH);
	}
	ଯଦି (idx)
		*idx = match;
	ଯଦି (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		ଫେରନ୍ତୁ (0);
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getopt_internal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nargc, ଅକ୍ଷର * ଅଚଳ *nargv, ଅଚଳ ଅକ୍ଷର *options,
	ଅଚଳ ସଂରଚନା option *long_options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *idx, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ଅକ୍ଷର *oli;				/* option letter list index */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା optchar, short_too;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା posixly_correct = -1;

	ଯଦି (options == ଖାଲି)
		ଫେରନ୍ତୁ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ଯଦି (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ଯଦି (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ଖାଲି);
	ଯଦି (*options == '-')
		flags |= FLAG_ALLARGS;
	ଅନ୍ୟଥା ଯଦି (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	ଯଦି (*options == '+' || *options == '-')
		options++;

	optarg = ଖାଲି;
	ଯଦି (optreset)
		nonopt_start = nonopt_end = -1;
start:
	ଯଦି (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		ଯଦି (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			ଯଦି (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			ଅନ୍ୟଥା ଯଦି (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ଫେରନ୍ତୁ (-1);
		}
		ଯଦି (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == ଖାଲି)) {
			place = EMSG;		/* found non-option */
			ଯଦି (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ଫେରନ୍ତୁ (ମଧ୍ୟକ୍ରମ);
			}
			ଯଦି (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ଫେରନ୍ତୁ (-1);
			}
			/* do permutation */
			ଯଦି (nonopt_start == -1)
				nonopt_start = optind;
			ଅନ୍ୟଥା ଯଦି (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			ଯାଅ start;
		}
		ଯଦି (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ଯଦି (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ଯଦି (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			ଫେରନ୍ତୁ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ଯଦି (long_options != ଖାଲି && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ଯଦି (*place == '-')
			place++;		/* --foo long option */
		ଅନ୍ୟଥା ଯଦି (*place != ':' && strchr(options, *place) != ଖାଲି)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ଯଦି (optchar != -1) {
			place = EMSG;
			ଫେରନ୍ତୁ (optchar);
		}
	}

	ଯଦି ((optchar = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)*place++) == (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)':' ||
	    (optchar == (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == ଖାଲି) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ଯଦି (optchar == (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)'-' && *place == '\0')
			ଫେରନ୍ତୁ (-1);
		ଯଦି (!*place)
			++optind;
		ଯଦି (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ଫେରନ୍ତୁ (BADCH);
	}
	ଯଦି (long_options != ଖାଲି && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ଯଦି (*place)			/* no space */
			/* NOTHING */;
		ଅନ୍ୟଥା ଯଦି (++optind >= nargc) {	/* no arg */
			place = EMSG;
			ଯଦି (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ଫେରନ୍ତୁ (BADARG);
		} ଅନ୍ୟଥା				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		ଫେରନ୍ତୁ (optchar);
	}
	ଯଦି (*++oli != ':') {			/* doesn't take argument */
		ଯଦି (!*place)
			++optind;
	} ଅନ୍ୟଥା {				/* takes (optional) argument */
		optarg = ଖାଲି;
		ଯଦି (*place)			/* no white space */
			optarg = place;
		ଅନ୍ୟଥା ଯଦି (oli[1] != ':') {	/* arg not optional */
			ଯଦି (++optind >= nargc) {	/* no arg */
				place = EMSG;
				ଯଦି (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ଫେରନ୍ତୁ (BADARG);
			} ଅନ୍ୟଥା
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	ଫେରନ୍ତୁ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getopt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nargc, ଅକ୍ଷର * ଅଚଳ *nargv, ଅଚଳ ଅକ୍ଷର *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ଫେରନ୍ତୁ (getopt_internal(nargc, nargv, options, ଖାଲି, ଖାଲି, 0));
}

#ଯଦି 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getopt_long(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nargc, ଅକ୍ଷର * ଅଚଳ *nargv, ଅଚଳ ଅକ୍ଷର *options,
    ଅଚଳ ସଂରଚନା option *long_options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *idx)
{

	ଫେରନ୍ତୁ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getopt_long_only(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nargc, ଅକ୍ଷର * ଅଚଳ *nargv, ଅଚଳ ଅକ୍ଷର *options,
    ଅଚଳ ସଂରଚନା option *long_options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *idx)
{

	ଫେରନ୍ତୁ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
