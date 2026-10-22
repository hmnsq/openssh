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
#شامل "includes.h"

#اگر !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#تعریف_کرو warnx		logit

#اگر 0
#شامل <err.h>
#شامل <getopt.h>
#اگر_ختم
#شامل <errno.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"

ساخت option {
	/* name of long option */
	ثابت حرف *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	صحیح has_arg;
	/* if not NULL, set *flag to val when option found */
	صحیح *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	صحیح val;
};

صحیح	opterr = 1;		/* if error message should be printed */
صحیح	optind = 1;		/* index into parent argv vector */
صحیح	optopt = '?';		/* character checked for validity */
صحیح	optreset;		/* reset getopt */
حرف    *optarg;		/* argument associated with option */

#تعریف_کرو PRINT_ERROR	((opterr) && (*options != ':'))

#تعریف_کرو FLAG_ترتیب_بدلو	0x01	/* permute non-options to the end of argv */
#تعریف_کرو FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#تعریف_کرو FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#تعریف_کرو	BADCH		(صحیح)'?'
#تعریف_کرو	BADARG		((*options == ':') ? (صحیح)':' : (صحیح)'?')
#تعریف_کرو	درمیانی_ترتیب		(صحیح)1

#تعریف_کرو	EMSG		""

ساکن صحیح getopt_اندرونی(صحیح, حرف * ثابت *, ثابت حرف *,
			   ثابت ساخت option *, صحیح *, صحیح);
ساکن صحیح parse_long_options(حرف * ثابت *, ثابت حرف *,
			      ثابت ساخت option *, صحیح *, صحیح);
ساکن صحیح عاد_اعظم(صحیح, صحیح);
ساکن خالی ترتیب_بدلو_دلائل(صحیح, صحیح, صحیح, حرف * ثابت *);

ساکن حرف *رکھو = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ساکن صحیح nonopt_آغاز = -1; /* first non option argument (for permute) */
ساکن صحیح nonopt_انتہا = -1;   /* first option after non options (for permute) */

/* Error messages */
ساکن ثابت حرف recargchar[] = "option requires an argument -- %c";
ساکن ثابت حرف recargstring[] = "option requires an argument -- %s";
ساکن ثابت حرف ambig[] = "ambiguous option -- %.*s";
ساکن ثابت حرف noarg[] = "option doesn't take an argument -- %.*s";
ساکن ثابت حرف illoptchar[] = "unknown option -- %c";
ساکن ثابت حرف illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ساکن صحیح
عاد_اعظم(صحیح a, صحیح b)
{
	صحیح c;

	c = a % b;
	جب (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	واپس (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ساکن خالی
ترتیب_بدلو_دلائل(صحیح panonopt_آغاز, صحیح panonopt_انتہا, صحیح opt_انتہا,
	حرف * ثابت *nargv)
{
	صحیح cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	حرف *تبادلہ;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_انتہا - panonopt_آغاز;
	nopts = opt_انتہا - panonopt_انتہا;
	ncycle = عاد_اعظم(nnonopts, nopts);
	cyclelen = (opt_انتہا - panonopt_آغاز) / ncycle;

	برائے (i = 0; i < ncycle; i++) {
		cstart = panonopt_انتہا+i;
		pos = cstart;
		برائے (j = 0; j < cyclelen; j++) {
			اگر (pos >= panonopt_انتہا)
				pos -= nnonopts;
			ورنہ
				pos += nopts;
			تبادلہ = nargv[pos];
			/* LINTED const cast */
			((حرف **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((حرف **)nargv)[cstart] = تبادلہ;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ساکن صحیح
parse_long_options(حرف * ثابت *nargv, ثابت حرف *options,
	ثابت ساخت option *long_options, صحیح *idx, صحیح short_too)
{
	حرف *current_argv, *has_equal;
	سائز_t current_argv_len;
	صحیح i, مطابقت;

	current_argv = رکھو;
	مطابقت = -1;

	optind++;

	اگر ((has_equal = strchr(current_argv, '=')) != تہی) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} ورنہ
		current_argv_len = لڑی_لمبائی(current_argv);

	برائے (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		اگر (لڑی_موازنہ(current_argv, long_options[i].name,
		    current_argv_len))
			جاری;

		اگر (لڑی_لمبائی(long_options[i].name) == current_argv_len) {
			/* exact match */
			مطابقت = i;
			توڑو;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		اگر (short_too && current_argv_len == 1)
			جاری;

		اگر (مطابقت == -1)	/* partial match */
			مطابقت = i;
		ورنہ {
			/* ambiguous abbreviation */
			اگر (PRINT_ERROR)
				warnx(ambig, (صحیح)current_argv_len,
				     current_argv);
			optopt = 0;
			واپس (BADCH);
		}
	}
	اگر (مطابقت != -1) {		/* option found */
		اگر (long_options[مطابقت].has_arg == no_argument
		    && has_equal) {
			اگر (PRINT_ERROR)
				warnx(noarg, (صحیح)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			اگر (long_options[مطابقت].flag == تہی)
				optopt = long_options[مطابقت].val;
			ورنہ
				optopt = 0;
			واپس (BADARG);
		}
		اگر (long_options[مطابقت].has_arg == required_argument ||
		    long_options[مطابقت].has_arg == optional_argument) {
			اگر (has_equal)
				optarg = has_equal;
			ورنہ اگر (long_options[مطابقت].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		اگر ((long_options[مطابقت].has_arg == required_argument)
		    && (optarg == تہی)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			اگر (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			اگر (long_options[مطابقت].flag == تہی)
				optopt = long_options[مطابقت].val;
			ورنہ
				optopt = 0;
			--optind;
			واپس (BADARG);
		}
	} ورنہ {			/* unknown option */
		اگر (short_too) {
			--optind;
			واپس (-1);
		}
		اگر (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		واپس (BADCH);
	}
	اگر (idx)
		*idx = مطابقت;
	اگر (long_options[مطابقت].flag) {
		*long_options[مطابقت].flag = long_options[مطابقت].val;
		واپس (0);
	} ورنہ
		واپس (long_options[مطابقت].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ساکن صحیح
getopt_اندرونی(صحیح nargc, حرف * ثابت *nargv, ثابت حرف *options,
	ثابت ساخت option *long_options, صحیح *idx, صحیح flags)
{
	حرف *oli;				/* option letter list index */
	صحیح optchar, short_too;
	ساکن صحیح posixly_correct = -1;

	اگر (options == تہی)
		واپس (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	اگر (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	اگر (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != تہی);
	اگر (*options == '-')
		flags |= FLAG_ALLARGS;
	ورنہ اگر (posixly_correct || *options == '+')
		flags &= ~FLAG_ترتیب_بدلو;
	اگر (*options == '+' || *options == '-')
		options++;

	optarg = تہی;
	اگر (optreset)
		nonopt_آغاز = nonopt_انتہا = -1;
آغاز:
	اگر (optreset || !*رکھو) {		/* update scanning pointer */
		optreset = 0;
		اگر (optind >= nargc) {          /* end of argument vector */
			رکھو = EMSG;
			اگر (nonopt_انتہا != -1) {
				/* do permutation, if we have to */
				ترتیب_بدلو_دلائل(nonopt_آغاز, nonopt_انتہا,
				    optind, nargv);
				optind -= nonopt_انتہا - nonopt_آغاز;
			}
			ورنہ اگر (nonopt_آغاز != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_آغاز;
			}
			nonopt_آغاز = nonopt_انتہا = -1;
			واپس (-1);
		}
		اگر (*(رکھو = nargv[optind]) != '-' ||
		    (رکھو[1] == '\0' && strchr(options, '-') == تہی)) {
			رکھو = EMSG;		/* found non-option */
			اگر (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				واپس (درمیانی_ترتیب);
			}
			اگر (!(flags & FLAG_ترتیب_بدلو)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				واپس (-1);
			}
			/* do permutation */
			اگر (nonopt_آغاز == -1)
				nonopt_آغاز = optind;
			ورنہ اگر (nonopt_انتہا != -1) {
				ترتیب_بدلو_دلائل(nonopt_آغاز, nonopt_انتہا,
				    optind, nargv);
				nonopt_آغاز = optind -
				    (nonopt_انتہا - nonopt_آغاز);
				nonopt_انتہا = -1;
			}
			optind++;
			/* process next argument */
			جاؤ آغاز;
		}
		اگر (nonopt_آغاز != -1 && nonopt_انتہا == -1)
			nonopt_انتہا = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		اگر (رکھو[1] != '\0' && *++رکھو == '-' && رکھو[1] == '\0') {
			optind++;
			رکھو = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			اگر (nonopt_انتہا != -1) {
				ترتیب_بدلو_دلائل(nonopt_آغاز, nonopt_انتہا,
				    optind, nargv);
				optind -= nonopt_انتہا - nonopt_آغاز;
			}
			nonopt_آغاز = nonopt_انتہا = -1;
			واپس (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	اگر (long_options != تہی && رکھو != nargv[optind] &&
	    (*رکھو == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		اگر (*رکھو == '-')
			رکھو++;		/* --foo long option */
		ورنہ اگر (*رکھو != ':' && strchr(options, *رکھو) != تہی)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		اگر (optchar != -1) {
			رکھو = EMSG;
			واپس (optchar);
		}
	}

	اگر ((optchar = (صحیح)*رکھو++) == (صحیح)':' ||
	    (optchar == (صحیح)'-' && *رکھو != '\0') ||
	    (oli = strchr(options, optchar)) == تہی) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		اگر (optchar == (صحیح)'-' && *رکھو == '\0')
			واپس (-1);
		اگر (!*رکھو)
			++optind;
		اگر (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		واپس (BADCH);
	}
	اگر (long_options != تہی && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		اگر (*رکھو)			/* no space */
			/* NOTHING */;
		ورنہ اگر (++optind >= nargc) {	/* no arg */
			رکھو = EMSG;
			اگر (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			واپس (BADARG);
		} ورنہ				/* white space */
			رکھو = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		رکھو = EMSG;
		واپس (optchar);
	}
	اگر (*++oli != ':') {			/* doesn't take argument */
		اگر (!*رکھو)
			++optind;
	} ورنہ {				/* takes (optional) argument */
		optarg = تہی;
		اگر (*رکھو)			/* no white space */
			optarg = رکھو;
		ورنہ اگر (oli[1] != ':') {	/* arg not optional */
			اگر (++optind >= nargc) {	/* no arg */
				رکھو = EMSG;
				اگر (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				واپس (BADARG);
			} ورنہ
				optarg = nargv[optind];
		}
		رکھو = EMSG;
		++optind;
	}
	/* dump back option letter */
	واپس (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
صحیح
getopt(صحیح nargc, حرف * ثابت *nargv, ثابت حرف *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	واپس (getopt_اندرونی(nargc, nargv, options, تہی, تہی, 0));
}

#اگر 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
صحیح
getopt_long(صحیح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت ساخت option *long_options, صحیح *idx)
{

	واپس (getopt_اندرونی(nargc, nargv, options, long_options, idx,
	    FLAG_ترتیب_بدلو));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
صحیح
getopt_long_only(صحیح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت ساخت option *long_options, صحیح *idx)
{

	واپس (getopt_اندرونی(nargc, nargv, options, long_options, idx,
	    FLAG_ترتیب_بدلو|FLAG_LONGONLY));
}
#اگر_ختم

#اگر_ختم /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
