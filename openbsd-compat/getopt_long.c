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

কাঠামো option {
	/* name of long option */
	ধ্রুবক অক্ষর *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	পূর্ণসংখ্যা has_arg;
	/* if not NULL, set *flag to val when option found */
	পূর্ণসংখ্যা *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	পূর্ণসংখ্যা val;
};

পূর্ণসংখ্যা	opterr = 1;		/* if error message should be printed */
পূর্ণসংখ্যা	optind = 1;		/* index into parent argv vector */
পূর্ণসংখ্যা	optopt = '?';		/* character checked for validity */
পূর্ণসংখ্যা	optreset;		/* reset getopt */
অক্ষর    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(পূর্ণসংখ্যা)'?'
#define	BADARG		((*options == ':') ? (পূর্ণসংখ্যা)':' : (পূর্ণসংখ্যা)'?')
#define	মধ্যক্রম		(পূর্ণসংখ্যা)1

#define	EMSG		""

স্থির পূর্ণসংখ্যা getopt_internal(পূর্ণসংখ্যা, অক্ষর * ধ্রুবক *, ধ্রুবক অক্ষর *,
			   ধ্রুবক কাঠামো option *, পূর্ণসংখ্যা *, পূর্ণসংখ্যা);
স্থির পূর্ণসংখ্যা parse_long_options(অক্ষর * ধ্রুবক *, ধ্রুবক অক্ষর *,
			      ধ্রুবক কাঠামো option *, পূর্ণসংখ্যা *, পূর্ণসংখ্যা);
স্থির পূর্ণসংখ্যা gcd(পূর্ণসংখ্যা, পূর্ণসংখ্যা);
স্থির শূন্য permute_args(পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর * ধ্রুবক *);

স্থির অক্ষর *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
স্থির পূর্ণসংখ্যা nonopt_start = -1; /* first non option argument (for permute) */
স্থির পূর্ণসংখ্যা nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
স্থির ধ্রুবক অক্ষর recargchar[] = "option requires an argument -- %c";
স্থির ধ্রুবক অক্ষর recargstring[] = "option requires an argument -- %s";
স্থির ধ্রুবক অক্ষর ambig[] = "ambiguous option -- %.*s";
স্থির ধ্রুবক অক্ষর noarg[] = "option doesn't take an argument -- %.*s";
স্থির ধ্রুবক অক্ষর illoptchar[] = "unknown option -- %c";
স্থির ধ্রুবক অক্ষর illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
স্থির পূর্ণসংখ্যা
gcd(পূর্ণসংখ্যা a, পূর্ণসংখ্যা b)
{
	পূর্ণসংখ্যা c;

	c = a % b;
	যখন (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	ফেরত (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
স্থির শূন্য
permute_args(পূর্ণসংখ্যা panonopt_start, পূর্ণসংখ্যা panonopt_end, পূর্ণসংখ্যা opt_end,
	অক্ষর * ধ্রুবক *nargv)
{
	পূর্ণসংখ্যা cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	অক্ষর *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	জন্য (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		জন্য (j = 0; j < cyclelen; j++) {
			যদি (pos >= panonopt_end)
				pos -= nnonopts;
			অন্যথা
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((অক্ষর **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((অক্ষর **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
স্থির পূর্ণসংখ্যা
parse_long_options(অক্ষর * ধ্রুবক *nargv, ধ্রুবক অক্ষর *options,
	ধ্রুবক কাঠামো option *long_options, পূর্ণসংখ্যা *idx, পূর্ণসংখ্যা short_too)
{
	অক্ষর *current_argv, *has_equal;
	আকার_t current_argv_len;
	পূর্ণসংখ্যা i, match;

	current_argv = place;
	match = -1;

	optind++;

	যদি ((has_equal = strchr(current_argv, '=')) != ফাঁকা) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} অন্যথা
		current_argv_len = strlen(current_argv);

	জন্য (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		যদি (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			চালু;

		যদি (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			বিরতি;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		যদি (short_too && current_argv_len == 1)
			চালু;

		যদি (match == -1)	/* partial match */
			match = i;
		অন্যথা {
			/* ambiguous abbreviation */
			যদি (PRINT_ERROR)
				warnx(ambig, (পূর্ণসংখ্যা)current_argv_len,
				     current_argv);
			optopt = 0;
			ফেরত (BADCH);
		}
	}
	যদি (match != -1) {		/* option found */
		যদি (long_options[match].has_arg == no_argument
		    && has_equal) {
			যদি (PRINT_ERROR)
				warnx(noarg, (পূর্ণসংখ্যা)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			যদি (long_options[match].flag == ফাঁকা)
				optopt = long_options[match].val;
			অন্যথা
				optopt = 0;
			ফেরত (BADARG);
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
		    && (optarg == ফাঁকা)) {
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
			যদি (long_options[match].flag == ফাঁকা)
				optopt = long_options[match].val;
			অন্যথা
				optopt = 0;
			--optind;
			ফেরত (BADARG);
		}
	} অন্যথা {			/* unknown option */
		যদি (short_too) {
			--optind;
			ফেরত (-1);
		}
		যদি (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		ফেরত (BADCH);
	}
	যদি (idx)
		*idx = match;
	যদি (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		ফেরত (0);
	} অন্যথা
		ফেরত (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
স্থির পূর্ণসংখ্যা
getopt_internal(পূর্ণসংখ্যা nargc, অক্ষর * ধ্রুবক *nargv, ধ্রুবক অক্ষর *options,
	ধ্রুবক কাঠামো option *long_options, পূর্ণসংখ্যা *idx, পূর্ণসংখ্যা flags)
{
	অক্ষর *oli;				/* option letter list index */
	পূর্ণসংখ্যা optchar, short_too;
	স্থির পূর্ণসংখ্যা posixly_correct = -1;

	যদি (options == ফাঁকা)
		ফেরত (-1);

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
		posixly_correct = (getenv("POSIXLY_CORRECT") != ফাঁকা);
	যদি (*options == '-')
		flags |= FLAG_ALLARGS;
	অন্যথা যদি (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	যদি (*options == '+' || *options == '-')
		options++;

	optarg = ফাঁকা;
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
			ফেরত (-1);
		}
		যদি (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == ফাঁকা)) {
			place = EMSG;		/* found non-option */
			যদি (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				ফেরত (মধ্যক্রম);
			}
			যদি (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				ফেরত (-1);
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
			যাও start;
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
			ফেরত (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	যদি (long_options != ফাঁকা && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		যদি (*place == '-')
			place++;		/* --foo long option */
		অন্যথা যদি (*place != ':' && strchr(options, *place) != ফাঁকা)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		যদি (optchar != -1) {
			place = EMSG;
			ফেরত (optchar);
		}
	}

	যদি ((optchar = (পূর্ণসংখ্যা)*place++) == (পূর্ণসংখ্যা)':' ||
	    (optchar == (পূর্ণসংখ্যা)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == ফাঁকা) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		যদি (optchar == (পূর্ণসংখ্যা)'-' && *place == '\0')
			ফেরত (-1);
		যদি (!*place)
			++optind;
		যদি (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		ফেরত (BADCH);
	}
	যদি (long_options != ফাঁকা && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		যদি (*place)			/* no space */
			/* NOTHING */;
		অন্যথা যদি (++optind >= nargc) {	/* no arg */
			place = EMSG;
			যদি (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			ফেরত (BADARG);
		} অন্যথা				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		ফেরত (optchar);
	}
	যদি (*++oli != ':') {			/* doesn't take argument */
		যদি (!*place)
			++optind;
	} অন্যথা {				/* takes (optional) argument */
		optarg = ফাঁকা;
		যদি (*place)			/* no white space */
			optarg = place;
		অন্যথা যদি (oli[1] != ':') {	/* arg not optional */
			যদি (++optind >= nargc) {	/* no arg */
				place = EMSG;
				যদি (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				ফেরত (BADARG);
			} অন্যথা
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	ফেরত (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
পূর্ণসংখ্যা
getopt(পূর্ণসংখ্যা nargc, অক্ষর * ধ্রুবক *nargv, ধ্রুবক অক্ষর *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	ফেরত (getopt_internal(nargc, nargv, options, ফাঁকা, ফাঁকা, 0));
}

#যদি 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
পূর্ণসংখ্যা
getopt_long(পূর্ণসংখ্যা nargc, অক্ষর * ধ্রুবক *nargv, ধ্রুবক অক্ষর *options,
    ধ্রুবক কাঠামো option *long_options, পূর্ণসংখ্যা *idx)
{

	ফেরত (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
পূর্ণসংখ্যা
getopt_long_only(পূর্ণসংখ্যা nargc, অক্ষর * ধ্রুবক *nargv, ধ্রুবক অক্ষর *options,
    ধ্রুবক কাঠামো option *long_options, পূর্ণসংখ্যা *idx)
{

	ফেরত (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
