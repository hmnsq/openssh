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
#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#నిర్వచించు warnx		logit

#ఒకవేళ 0
#అన్తర్భావ <err.h>
#అన్తర్భావ <getopt.h>
#అయితే_ముగింపు
#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "log.h"

నిర్మాణం option {
	/* name of long option */
	స్థిరరాశి అక్షరం *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	పూర్ణాంకం has_arg;
	/* if not NULL, set *flag to val when option found */
	పూర్ణాంకం *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	పూర్ణాంకం val;
};

పూర్ణాంకం	opterr = 1;		/* if error message should be printed */
పూర్ణాంకం	optind = 1;		/* index into parent argv vector */
పూర్ణాంకం	optopt = '?';		/* character checked for validity */
పూర్ణాంకం	optreset;		/* reset getopt */
అక్షరం    *optarg;		/* argument associated with option */

#నిర్వచించు PRINT_ERROR	((opterr) && (*options != ':'))

#నిర్వచించు FLAG_క్రమమార్పు	0x01	/* permute non-options to the end of argv */
#నిర్వచించు FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#నిర్వచించు FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#నిర్వచించు	BADCH		(పూర్ణాంకం)'?'
#నిర్వచించు	BADARG		((*options == ':') ? (పూర్ణాంకం)':' : (పూర్ణాంకం)'?')
#నిర్వచించు	మధ్యక్రమం		(పూర్ణాంకం)1

#నిర్వచించు	EMSG		""

స్థిర పూర్ణాంకం getopt_అంతర్గత(పూర్ణాంకం, అక్షరం * స్థిరరాశి *, స్థిరరాశి అక్షరం *,
			   స్థిరరాశి నిర్మాణం option *, పూర్ణాంకం *, పూర్ణాంకం);
స్థిర పూర్ణాంకం parse_long_options(అక్షరం * స్థిరరాశి *, స్థిరరాశి అక్షరం *,
			      స్థిరరాశి నిర్మాణం option *, పూర్ణాంకం *, పూర్ణాంకం);
స్థిర పూర్ణాంకం గరిష్ఠ_సామాన్య_భాజకం(పూర్ణాంకం, పూర్ణాంకం);
స్థిర శూన్య క్రమమార్పు_వాదనలు(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, అక్షరం * స్థిరరాశి *);

స్థిర అక్షరం *ఉంచు = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
స్థిర పూర్ణాంకం nonopt_ప్రారంభం = -1; /* first non option argument (for permute) */
స్థిర పూర్ణాంకం nonopt_చివర = -1;   /* first option after non options (for permute) */

/* Error messages */
స్థిర స్థిరరాశి అక్షరం recargchar[] = "option requires an argument -- %c";
స్థిర స్థిరరాశి అక్షరం recargstring[] = "option requires an argument -- %s";
స్థిర స్థిరరాశి అక్షరం ambig[] = "ambiguous option -- %.*s";
స్థిర స్థిరరాశి అక్షరం noarg[] = "option doesn't take an argument -- %.*s";
స్థిర స్థిరరాశి అక్షరం illoptchar[] = "unknown option -- %c";
స్థిర స్థిరరాశి అక్షరం illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
స్థిర పూర్ణాంకం
గరిష్ఠ_సామాన్య_భాజకం(పూర్ణాంకం a, పూర్ణాంకం b)
{
	పూర్ణాంకం c;

	c = a % b;
	అయితే (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	తిరిగి (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
స్థిర శూన్య
క్రమమార్పు_వాదనలు(పూర్ణాంకం panonopt_ప్రారంభం, పూర్ణాంకం panonopt_చివర, పూర్ణాంకం opt_చివర,
	అక్షరం * స్థిరరాశి *nargv)
{
	పూర్ణాంకం cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	అక్షరం *మార్పిడి;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_చివర - panonopt_ప్రారంభం;
	nopts = opt_చివర - panonopt_చివర;
	ncycle = గరిష్ఠ_సామాన్య_భాజకం(nnonopts, nopts);
	cyclelen = (opt_చివర - panonopt_ప్రారంభం) / ncycle;

	కొరకు (i = 0; i < ncycle; i++) {
		cstart = panonopt_చివర+i;
		pos = cstart;
		కొరకు (j = 0; j < cyclelen; j++) {
			ఒకవేళ (pos >= panonopt_చివర)
				pos -= nnonopts;
			లేకపోతే
				pos += nopts;
			మార్పిడి = nargv[pos];
			/* LINTED const cast */
			((అక్షరం **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((అక్షరం **)nargv)[cstart] = మార్పిడి;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
స్థిర పూర్ణాంకం
parse_long_options(అక్షరం * స్థిరరాశి *nargv, స్థిరరాశి అక్షరం *options,
	స్థిరరాశి నిర్మాణం option *long_options, పూర్ణాంకం *idx, పూర్ణాంకం short_too)
{
	అక్షరం *current_argv, *has_equal;
	కొలత_t current_argv_len;
	పూర్ణాంకం i, సరిపోలిక;

	current_argv = ఉంచు;
	సరిపోలిక = -1;

	optind++;

	ఒకవేళ ((has_equal = strchr(current_argv, '=')) != ఖాళీ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} లేకపోతే
		current_argv_len = అక్షరశ్రేణి_పొడవు(current_argv);

	కొరకు (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(current_argv, long_options[i].name,
		    current_argv_len))
			కొనసాగు;

		ఒకవేళ (అక్షరశ్రేణి_పొడవు(long_options[i].name) == current_argv_len) {
			/* exact match */
			సరిపోలిక = i;
			ఆపు;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		ఒకవేళ (short_too && current_argv_len == 1)
			కొనసాగు;

		ఒకవేళ (సరిపోలిక == -1)	/* partial match */
			సరిపోలిక = i;
		లేకపోతే {
			/* ambiguous abbreviation */
			ఒకవేళ (PRINT_ERROR)
				warnx(ambig, (పూర్ణాంకం)current_argv_len,
				     current_argv);
			optopt = 0;
			తిరిగి (BADCH);
		}
	}
	ఒకవేళ (సరిపోలిక != -1) {		/* option found */
		ఒకవేళ (long_options[సరిపోలిక].has_arg == no_argument
		    && has_equal) {
			ఒకవేళ (PRINT_ERROR)
				warnx(noarg, (పూర్ణాంకం)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ఒకవేళ (long_options[సరిపోలిక].flag == ఖాళీ)
				optopt = long_options[సరిపోలిక].val;
			లేకపోతే
				optopt = 0;
			తిరిగి (BADARG);
		}
		ఒకవేళ (long_options[సరిపోలిక].has_arg == required_argument ||
		    long_options[సరిపోలిక].has_arg == optional_argument) {
			ఒకవేళ (has_equal)
				optarg = has_equal;
			లేకపోతే ఒకవేళ (long_options[సరిపోలిక].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		ఒకవేళ ((long_options[సరిపోలిక].has_arg == required_argument)
		    && (optarg == ఖాళీ)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			ఒకవేళ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			ఒకవేళ (long_options[సరిపోలిక].flag == ఖాళీ)
				optopt = long_options[సరిపోలిక].val;
			లేకపోతే
				optopt = 0;
			--optind;
			తిరిగి (BADARG);
		}
	} లేకపోతే {			/* unknown option */
		ఒకవేళ (short_too) {
			--optind;
			తిరిగి (-1);
		}
		ఒకవేళ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		తిరిగి (BADCH);
	}
	ఒకవేళ (idx)
		*idx = సరిపోలిక;
	ఒకవేళ (long_options[సరిపోలిక].flag) {
		*long_options[సరిపోలిక].flag = long_options[సరిపోలిక].val;
		తిరిగి (0);
	} లేకపోతే
		తిరిగి (long_options[సరిపోలిక].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
స్థిర పూర్ణాంకం
getopt_అంతర్గత(పూర్ణాంకం nargc, అక్షరం * స్థిరరాశి *nargv, స్థిరరాశి అక్షరం *options,
	స్థిరరాశి నిర్మాణం option *long_options, పూర్ణాంకం *idx, పూర్ణాంకం flags)
{
	అక్షరం *oli;				/* option letter list index */
	పూర్ణాంకం optchar, short_too;
	స్థిర పూర్ణాంకం posixly_correct = -1;

	ఒకవేళ (options == ఖాళీ)
		తిరిగి (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	ఒకవేళ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	ఒకవేళ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ఖాళీ);
	ఒకవేళ (*options == '-')
		flags |= FLAG_ALLARGS;
	లేకపోతే ఒకవేళ (posixly_correct || *options == '+')
		flags &= ~FLAG_క్రమమార్పు;
	ఒకవేళ (*options == '+' || *options == '-')
		options++;

	optarg = ఖాళీ;
	ఒకవేళ (optreset)
		nonopt_ప్రారంభం = nonopt_చివర = -1;
ప్రారంభం:
	ఒకవేళ (optreset || !*ఉంచు) {		/* update scanning pointer */
		optreset = 0;
		ఒకవేళ (optind >= nargc) {          /* end of argument vector */
			ఉంచు = EMSG;
			ఒకవేళ (nonopt_చివర != -1) {
				/* do permutation, if we have to */
				క్రమమార్పు_వాదనలు(nonopt_ప్రారంభం, nonopt_చివర,
				    optind, nargv);
				optind -= nonopt_చివర - nonopt_ప్రారంభం;
			}
			లేకపోతే ఒకవేళ (nonopt_ప్రారంభం != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_ప్రారంభం;
			}
			nonopt_ప్రారంభం = nonopt_చివర = -1;
			తిరిగి (-1);
		}
		ఒకవేళ (*(ఉంచు = nargv[optind]) != '-' ||
		    (ఉంచు[1] == '\0' && strchr(options, '-') == ఖాళీ)) {
			ఉంచు = EMSG;		/* found non-option */
			ఒకవేళ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				తిరిగి (మధ్యక్రమం);
			}
			ఒకవేళ (!(flags & FLAG_క్రమమార్పు)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				తిరిగి (-1);
			}
			/* do permutation */
			ఒకవేళ (nonopt_ప్రారంభం == -1)
				nonopt_ప్రారంభం = optind;
			లేకపోతే ఒకవేళ (nonopt_చివర != -1) {
				క్రమమార్పు_వాదనలు(nonopt_ప్రారంభం, nonopt_చివర,
				    optind, nargv);
				nonopt_ప్రారంభం = optind -
				    (nonopt_చివర - nonopt_ప్రారంభం);
				nonopt_చివర = -1;
			}
			optind++;
			/* process next argument */
			వెళ్ళు ప్రారంభం;
		}
		ఒకవేళ (nonopt_ప్రారంభం != -1 && nonopt_చివర == -1)
			nonopt_చివర = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		ఒకవేళ (ఉంచు[1] != '\0' && *++ఉంచు == '-' && ఉంచు[1] == '\0') {
			optind++;
			ఉంచు = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			ఒకవేళ (nonopt_చివర != -1) {
				క్రమమార్పు_వాదనలు(nonopt_ప్రారంభం, nonopt_చివర,
				    optind, nargv);
				optind -= nonopt_చివర - nonopt_ప్రారంభం;
			}
			nonopt_ప్రారంభం = nonopt_చివర = -1;
			తిరిగి (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	ఒకవేళ (long_options != ఖాళీ && ఉంచు != nargv[optind] &&
	    (*ఉంచు == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		ఒకవేళ (*ఉంచు == '-')
			ఉంచు++;		/* --foo long option */
		లేకపోతే ఒకవేళ (*ఉంచు != ':' && strchr(options, *ఉంచు) != ఖాళీ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		ఒకవేళ (optchar != -1) {
			ఉంచు = EMSG;
			తిరిగి (optchar);
		}
	}

	ఒకవేళ ((optchar = (పూర్ణాంకం)*ఉంచు++) == (పూర్ణాంకం)':' ||
	    (optchar == (పూర్ణాంకం)'-' && *ఉంచు != '\0') ||
	    (oli = strchr(options, optchar)) == ఖాళీ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		ఒకవేళ (optchar == (పూర్ణాంకం)'-' && *ఉంచు == '\0')
			తిరిగి (-1);
		ఒకవేళ (!*ఉంచు)
			++optind;
		ఒకవేళ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		తిరిగి (BADCH);
	}
	ఒకవేళ (long_options != ఖాళీ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		ఒకవేళ (*ఉంచు)			/* no space */
			/* NOTHING */;
		లేకపోతే ఒకవేళ (++optind >= nargc) {	/* no arg */
			ఉంచు = EMSG;
			ఒకవేళ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			తిరిగి (BADARG);
		} లేకపోతే				/* white space */
			ఉంచు = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		ఉంచు = EMSG;
		తిరిగి (optchar);
	}
	ఒకవేళ (*++oli != ':') {			/* doesn't take argument */
		ఒకవేళ (!*ఉంచు)
			++optind;
	} లేకపోతే {				/* takes (optional) argument */
		optarg = ఖాళీ;
		ఒకవేళ (*ఉంచు)			/* no white space */
			optarg = ఉంచు;
		లేకపోతే ఒకవేళ (oli[1] != ':') {	/* arg not optional */
			ఒకవేళ (++optind >= nargc) {	/* no arg */
				ఉంచు = EMSG;
				ఒకవేళ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				తిరిగి (BADARG);
			} లేకపోతే
				optarg = nargv[optind];
		}
		ఉంచు = EMSG;
		++optind;
	}
	/* dump back option letter */
	తిరిగి (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
పూర్ణాంకం
getopt(పూర్ణాంకం nargc, అక్షరం * స్థిరరాశి *nargv, స్థిరరాశి అక్షరం *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	తిరిగి (getopt_అంతర్గత(nargc, nargv, options, ఖాళీ, ఖాళీ, 0));
}

#ఒకవేళ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
పూర్ణాంకం
getopt_long(పూర్ణాంకం nargc, అక్షరం * స్థిరరాశి *nargv, స్థిరరాశి అక్షరం *options,
    స్థిరరాశి నిర్మాణం option *long_options, పూర్ణాంకం *idx)
{

	తిరిగి (getopt_అంతర్గత(nargc, nargv, options, long_options, idx,
	    FLAG_క్రమమార్పు));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
పూర్ణాంకం
getopt_long_only(పూర్ణాంకం nargc, అక్షరం * స్థిరరాశి *nargv, స్థిరరాశి అక్షరం *options,
    స్థిరరాశి నిర్మాణం option *long_options, పూర్ణాంకం *idx)
{

	తిరిగి (getopt_అంతర్గత(nargc, nargv, options, long_options, idx,
	    FLAG_క్రమమార్పు|FLAG_LONGONLY));
}
#అయితే_ముగింపు

#అయితే_ముగింపు /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
