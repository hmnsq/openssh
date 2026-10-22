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
#ضمن "includes.h"

#إذا !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#وصف_ڪريو warnx		logit

#إذا 0
#ضمن <err.h>
#ضمن <getopt.h>
#جيڪڏهن_پورو
#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "log.h"

بنية option {
	/* name of long option */
	ثابت حرف *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	صحيح has_arg;
	/* if not NULL, set *flag to val when option found */
	صحيح *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	صحيح val;
};

صحيح	opterr = 1;		/* if error message should be printed */
صحيح	optind = 1;		/* index into parent argv vector */
صحيح	optopt = '?';		/* character checked for validity */
صحيح	optreset;		/* reset getopt */
حرف    *optarg;		/* argument associated with option */

#وصف_ڪريو PRINT_ERROR	((opterr) && (*options != ':'))

#وصف_ڪريو FLAG_ترتيب_بدلايو	0x01	/* permute non-options to the end of argv */
#وصف_ڪريو FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#وصف_ڪريو FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#وصف_ڪريو	BADCH		(صحيح)'?'
#وصف_ڪريو	BADARG		((*options == ':') ? (صحيح)':' : (صحيح)'?')
#وصف_ڪريو	وچين_ترتيب		(صحيح)1

#وصف_ڪريو	EMSG		""

ساكن صحيح getopt_اندروني(صحيح, حرف * ثابت *, ثابت حرف *,
			   ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح parse_long_options(حرف * ثابت *, ثابت حرف *,
			      ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح وڏو_گڏيل_ونڊيندڙ(صحيح, صحيح);
ساكن فراغ ترتيب_بدلايو_دليلون(صحيح, صحيح, صحيح, حرف * ثابت *);

ساكن حرف *رکو = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ساكن صحيح nonopt_شروعات = -1; /* first non option argument (for permute) */
ساكن صحيح nonopt_پڇاڙي = -1;   /* first option after non options (for permute) */

/* Error messages */
ساكن ثابت حرف recargchar[] = "option requires an argument -- %c";
ساكن ثابت حرف recargstring[] = "option requires an argument -- %s";
ساكن ثابت حرف ambig[] = "ambiguous option -- %.*s";
ساكن ثابت حرف noarg[] = "option doesn't take an argument -- %.*s";
ساكن ثابت حرف illoptchar[] = "unknown option -- %c";
ساكن ثابت حرف illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ساكن صحيح
وڏو_گڏيل_ونڊيندڙ(صحيح a, صحيح b)
{
	صحيح c;

	c = a % b;
	طالما (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	أرجع (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ساكن فراغ
ترتيب_بدلايو_دليلون(صحيح panonopt_شروعات, صحيح panonopt_پڇاڙي, صحيح opt_پڇاڙي,
	حرف * ثابت *nargv)
{
	صحيح cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	حرف *مٽا_سٽا;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_پڇاڙي - panonopt_شروعات;
	nopts = opt_پڇاڙي - panonopt_پڇاڙي;
	ncycle = وڏو_گڏيل_ونڊيندڙ(nnonopts, nopts);
	cyclelen = (opt_پڇاڙي - panonopt_شروعات) / ncycle;

	لكل (i = 0; i < ncycle; i++) {
		cstart = panonopt_پڇاڙي+i;
		pos = cstart;
		لكل (j = 0; j < cyclelen; j++) {
			إذا (pos >= panonopt_پڇاڙي)
				pos -= nnonopts;
			وإلا
				pos += nopts;
			مٽا_سٽا = nargv[pos];
			/* LINTED const cast */
			((حرف **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((حرف **)nargv)[cstart] = مٽا_سٽا;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ساكن صحيح
parse_long_options(حرف * ثابت *nargv, ثابت حرف *options,
	ثابت بنية option *long_options, صحيح *idx, صحيح short_too)
{
	حرف *current_argv, *has_equal;
	سائيز_t current_argv_len;
	صحيح i, ميلاپ;

	current_argv = رکو;
	ميلاپ = -1;

	optind++;

	إذا ((has_equal = strchr(current_argv, '=')) != عدم) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} وإلا
		current_argv_len = لڙي_ڊيگهه(current_argv);

	لكل (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		إذا (لڙي_ڀيٽ(current_argv, long_options[i].name,
		    current_argv_len))
			استمر;

		إذا (لڙي_ڊيگهه(long_options[i].name) == current_argv_len) {
			/* exact match */
			ميلاپ = i;
			اكسر;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		إذا (short_too && current_argv_len == 1)
			استمر;

		إذا (ميلاپ == -1)	/* partial match */
			ميلاپ = i;
		وإلا {
			/* ambiguous abbreviation */
			إذا (PRINT_ERROR)
				warnx(ambig, (صحيح)current_argv_len,
				     current_argv);
			optopt = 0;
			أرجع (BADCH);
		}
	}
	إذا (ميلاپ != -1) {		/* option found */
		إذا (long_options[ميلاپ].has_arg == no_argument
		    && has_equal) {
			إذا (PRINT_ERROR)
				warnx(noarg, (صحيح)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			إذا (long_options[ميلاپ].flag == عدم)
				optopt = long_options[ميلاپ].val;
			وإلا
				optopt = 0;
			أرجع (BADARG);
		}
		إذا (long_options[ميلاپ].has_arg == required_argument ||
		    long_options[ميلاپ].has_arg == optional_argument) {
			إذا (has_equal)
				optarg = has_equal;
			وإلا إذا (long_options[ميلاپ].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		إذا ((long_options[ميلاپ].has_arg == required_argument)
		    && (optarg == عدم)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			إذا (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			إذا (long_options[ميلاپ].flag == عدم)
				optopt = long_options[ميلاپ].val;
			وإلا
				optopt = 0;
			--optind;
			أرجع (BADARG);
		}
	} وإلا {			/* unknown option */
		إذا (short_too) {
			--optind;
			أرجع (-1);
		}
		إذا (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		أرجع (BADCH);
	}
	إذا (idx)
		*idx = ميلاپ;
	إذا (long_options[ميلاپ].flag) {
		*long_options[ميلاپ].flag = long_options[ميلاپ].val;
		أرجع (0);
	} وإلا
		أرجع (long_options[ميلاپ].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ساكن صحيح
getopt_اندروني(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
	ثابت بنية option *long_options, صحيح *idx, صحيح flags)
{
	حرف *oli;				/* option letter list index */
	صحيح optchar, short_too;
	ساكن صحيح posixly_correct = -1;

	إذا (options == عدم)
		أرجع (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	إذا (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	إذا (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != عدم);
	إذا (*options == '-')
		flags |= FLAG_ALLARGS;
	وإلا إذا (posixly_correct || *options == '+')
		flags &= ~FLAG_ترتيب_بدلايو;
	إذا (*options == '+' || *options == '-')
		options++;

	optarg = عدم;
	إذا (optreset)
		nonopt_شروعات = nonopt_پڇاڙي = -1;
شروعات:
	إذا (optreset || !*رکو) {		/* update scanning pointer */
		optreset = 0;
		إذا (optind >= nargc) {          /* end of argument vector */
			رکو = EMSG;
			إذا (nonopt_پڇاڙي != -1) {
				/* do permutation, if we have to */
				ترتيب_بدلايو_دليلون(nonopt_شروعات, nonopt_پڇاڙي,
				    optind, nargv);
				optind -= nonopt_پڇاڙي - nonopt_شروعات;
			}
			وإلا إذا (nonopt_شروعات != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_شروعات;
			}
			nonopt_شروعات = nonopt_پڇاڙي = -1;
			أرجع (-1);
		}
		إذا (*(رکو = nargv[optind]) != '-' ||
		    (رکو[1] == '\0' && strchr(options, '-') == عدم)) {
			رکو = EMSG;		/* found non-option */
			إذا (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				أرجع (وچين_ترتيب);
			}
			إذا (!(flags & FLAG_ترتيب_بدلايو)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				أرجع (-1);
			}
			/* do permutation */
			إذا (nonopt_شروعات == -1)
				nonopt_شروعات = optind;
			وإلا إذا (nonopt_پڇاڙي != -1) {
				ترتيب_بدلايو_دليلون(nonopt_شروعات, nonopt_پڇاڙي,
				    optind, nargv);
				nonopt_شروعات = optind -
				    (nonopt_پڇاڙي - nonopt_شروعات);
				nonopt_پڇاڙي = -1;
			}
			optind++;
			/* process next argument */
			اذهب شروعات;
		}
		إذا (nonopt_شروعات != -1 && nonopt_پڇاڙي == -1)
			nonopt_پڇاڙي = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		إذا (رکو[1] != '\0' && *++رکو == '-' && رکو[1] == '\0') {
			optind++;
			رکو = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			إذا (nonopt_پڇاڙي != -1) {
				ترتيب_بدلايو_دليلون(nonopt_شروعات, nonopt_پڇاڙي,
				    optind, nargv);
				optind -= nonopt_پڇاڙي - nonopt_شروعات;
			}
			nonopt_شروعات = nonopt_پڇاڙي = -1;
			أرجع (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	إذا (long_options != عدم && رکو != nargv[optind] &&
	    (*رکو == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		إذا (*رکو == '-')
			رکو++;		/* --foo long option */
		وإلا إذا (*رکو != ':' && strchr(options, *رکو) != عدم)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		إذا (optchar != -1) {
			رکو = EMSG;
			أرجع (optchar);
		}
	}

	إذا ((optchar = (صحيح)*رکو++) == (صحيح)':' ||
	    (optchar == (صحيح)'-' && *رکو != '\0') ||
	    (oli = strchr(options, optchar)) == عدم) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		إذا (optchar == (صحيح)'-' && *رکو == '\0')
			أرجع (-1);
		إذا (!*رکو)
			++optind;
		إذا (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		أرجع (BADCH);
	}
	إذا (long_options != عدم && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		إذا (*رکو)			/* no space */
			/* NOTHING */;
		وإلا إذا (++optind >= nargc) {	/* no arg */
			رکو = EMSG;
			إذا (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			أرجع (BADARG);
		} وإلا				/* white space */
			رکو = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		رکو = EMSG;
		أرجع (optchar);
	}
	إذا (*++oli != ':') {			/* doesn't take argument */
		إذا (!*رکو)
			++optind;
	} وإلا {				/* takes (optional) argument */
		optarg = عدم;
		إذا (*رکو)			/* no white space */
			optarg = رکو;
		وإلا إذا (oli[1] != ':') {	/* arg not optional */
			إذا (++optind >= nargc) {	/* no arg */
				رکو = EMSG;
				إذا (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				أرجع (BADARG);
			} وإلا
				optarg = nargv[optind];
		}
		رکو = EMSG;
		++optind;
	}
	/* dump back option letter */
	أرجع (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
صحيح
getopt(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	أرجع (getopt_اندروني(nargc, nargv, options, عدم, عدم, 0));
}

#إذا 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
صحيح
getopt_long(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت بنية option *long_options, صحيح *idx)
{

	أرجع (getopt_اندروني(nargc, nargv, options, long_options, idx,
	    FLAG_ترتيب_بدلايو));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
صحيح
getopt_long_only(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت بنية option *long_options, صحيح *idx)
{

	أرجع (getopt_اندروني(nargc, nargv, options, long_options, idx,
	    FLAG_ترتيب_بدلايو|FLAG_LONGONLY));
}
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
