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
#تعریف_کړه warnx		logit

#إذا 0
#ضمن <err.h>
#ضمن <getopt.h>
#د_که_پای
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

#تعریف_کړه PRINT_ERROR	((opterr) && (*options != ':'))

#تعریف_کړه FLAG_ترتیب_بدلول	0x01	/* permute non-options to the end of argv */
#تعریف_کړه FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#تعریف_کړه FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#تعریف_کړه	BADCH		(صحيح)'?'
#تعریف_کړه	BADARG		((*options == ':') ? (صحيح)':' : (صحيح)'?')
#تعریف_کړه	منځنی_ترتیب		(صحيح)1

#تعریف_کړه	EMSG		""

ساكن صحيح getopt_دننی(صحيح, حرف * ثابت *, ثابت حرف *,
			   ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح parse_long_options(حرف * ثابت *, ثابت حرف *,
			      ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح لوی_ګډ_وېشونکی(صحيح, صحيح);
ساكن فراغ ترتیب_بدلول_دلیلونه(صحيح, صحيح, صحيح, حرف * ثابت *);

ساكن حرف *ځای_پرځای_کړه = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ساكن صحيح nonopt_پیل = -1; /* first non option argument (for permute) */
ساكن صحيح nonopt_پای_ټکی = -1;   /* first option after non options (for permute) */

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
لوی_ګډ_وېشونکی(صحيح a, صحيح b)
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
ترتیب_بدلول_دلیلونه(صحيح panonopt_پیل, صحيح panonopt_پای_ټکی, صحيح opt_پای_ټکی,
	حرف * ثابت *nargv)
{
	صحيح cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	حرف *بدلون;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_پای_ټکی - panonopt_پیل;
	nopts = opt_پای_ټکی - panonopt_پای_ټکی;
	ncycle = لوی_ګډ_وېشونکی(nnonopts, nopts);
	cyclelen = (opt_پای_ټکی - panonopt_پیل) / ncycle;

	لكل (i = 0; i < ncycle; i++) {
		cstart = panonopt_پای_ټکی+i;
		pos = cstart;
		لكل (j = 0; j < cyclelen; j++) {
			إذا (pos >= panonopt_پای_ټکی)
				pos -= nnonopts;
			وإلا
				pos += nopts;
			بدلون = nargv[pos];
			/* LINTED const cast */
			((حرف **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((حرف **)nargv)[cstart] = بدلون;
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
	اندازه_t current_argv_len;
	صحيح i, سمون;

	current_argv = ځای_پرځای_کړه;
	سمون = -1;

	optind++;

	إذا ((has_equal = strchr(current_argv, '=')) != عدم) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} وإلا
		current_argv_len = مزي_اوږدوالی(current_argv);

	لكل (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		إذا (مزي_پرتله(current_argv, long_options[i].name,
		    current_argv_len))
			استمر;

		إذا (مزي_اوږدوالی(long_options[i].name) == current_argv_len) {
			/* exact match */
			سمون = i;
			اكسر;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		إذا (short_too && current_argv_len == 1)
			استمر;

		إذا (سمون == -1)	/* partial match */
			سمون = i;
		وإلا {
			/* ambiguous abbreviation */
			إذا (PRINT_ERROR)
				warnx(ambig, (صحيح)current_argv_len,
				     current_argv);
			optopt = 0;
			أرجع (BADCH);
		}
	}
	إذا (سمون != -1) {		/* option found */
		إذا (long_options[سمون].has_arg == no_argument
		    && has_equal) {
			إذا (PRINT_ERROR)
				warnx(noarg, (صحيح)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			إذا (long_options[سمون].flag == عدم)
				optopt = long_options[سمون].val;
			وإلا
				optopt = 0;
			أرجع (BADARG);
		}
		إذا (long_options[سمون].has_arg == required_argument ||
		    long_options[سمون].has_arg == optional_argument) {
			إذا (has_equal)
				optarg = has_equal;
			وإلا إذا (long_options[سمون].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		إذا ((long_options[سمون].has_arg == required_argument)
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
			إذا (long_options[سمون].flag == عدم)
				optopt = long_options[سمون].val;
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
		*idx = سمون;
	إذا (long_options[سمون].flag) {
		*long_options[سمون].flag = long_options[سمون].val;
		أرجع (0);
	} وإلا
		أرجع (long_options[سمون].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ساكن صحيح
getopt_دننی(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
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
		flags &= ~FLAG_ترتیب_بدلول;
	إذا (*options == '+' || *options == '-')
		options++;

	optarg = عدم;
	إذا (optreset)
		nonopt_پیل = nonopt_پای_ټکی = -1;
پیل:
	إذا (optreset || !*ځای_پرځای_کړه) {		/* update scanning pointer */
		optreset = 0;
		إذا (optind >= nargc) {          /* end of argument vector */
			ځای_پرځای_کړه = EMSG;
			إذا (nonopt_پای_ټکی != -1) {
				/* do permutation, if we have to */
				ترتیب_بدلول_دلیلونه(nonopt_پیل, nonopt_پای_ټکی,
				    optind, nargv);
				optind -= nonopt_پای_ټکی - nonopt_پیل;
			}
			وإلا إذا (nonopt_پیل != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_پیل;
			}
			nonopt_پیل = nonopt_پای_ټکی = -1;
			أرجع (-1);
		}
		إذا (*(ځای_پرځای_کړه = nargv[optind]) != '-' ||
		    (ځای_پرځای_کړه[1] == '\0' && strchr(options, '-') == عدم)) {
			ځای_پرځای_کړه = EMSG;		/* found non-option */
			إذا (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				أرجع (منځنی_ترتیب);
			}
			إذا (!(flags & FLAG_ترتیب_بدلول)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				أرجع (-1);
			}
			/* do permutation */
			إذا (nonopt_پیل == -1)
				nonopt_پیل = optind;
			وإلا إذا (nonopt_پای_ټکی != -1) {
				ترتیب_بدلول_دلیلونه(nonopt_پیل, nonopt_پای_ټکی,
				    optind, nargv);
				nonopt_پیل = optind -
				    (nonopt_پای_ټکی - nonopt_پیل);
				nonopt_پای_ټکی = -1;
			}
			optind++;
			/* process next argument */
			اذهب پیل;
		}
		إذا (nonopt_پیل != -1 && nonopt_پای_ټکی == -1)
			nonopt_پای_ټکی = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		إذا (ځای_پرځای_کړه[1] != '\0' && *++ځای_پرځای_کړه == '-' && ځای_پرځای_کړه[1] == '\0') {
			optind++;
			ځای_پرځای_کړه = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			إذا (nonopt_پای_ټکی != -1) {
				ترتیب_بدلول_دلیلونه(nonopt_پیل, nonopt_پای_ټکی,
				    optind, nargv);
				optind -= nonopt_پای_ټکی - nonopt_پیل;
			}
			nonopt_پیل = nonopt_پای_ټکی = -1;
			أرجع (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	إذا (long_options != عدم && ځای_پرځای_کړه != nargv[optind] &&
	    (*ځای_پرځای_کړه == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		إذا (*ځای_پرځای_کړه == '-')
			ځای_پرځای_کړه++;		/* --foo long option */
		وإلا إذا (*ځای_پرځای_کړه != ':' && strchr(options, *ځای_پرځای_کړه) != عدم)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		إذا (optchar != -1) {
			ځای_پرځای_کړه = EMSG;
			أرجع (optchar);
		}
	}

	إذا ((optchar = (صحيح)*ځای_پرځای_کړه++) == (صحيح)':' ||
	    (optchar == (صحيح)'-' && *ځای_پرځای_کړه != '\0') ||
	    (oli = strchr(options, optchar)) == عدم) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		إذا (optchar == (صحيح)'-' && *ځای_پرځای_کړه == '\0')
			أرجع (-1);
		إذا (!*ځای_پرځای_کړه)
			++optind;
		إذا (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		أرجع (BADCH);
	}
	إذا (long_options != عدم && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		إذا (*ځای_پرځای_کړه)			/* no space */
			/* NOTHING */;
		وإلا إذا (++optind >= nargc) {	/* no arg */
			ځای_پرځای_کړه = EMSG;
			إذا (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			أرجع (BADARG);
		} وإلا				/* white space */
			ځای_پرځای_کړه = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		ځای_پرځای_کړه = EMSG;
		أرجع (optchar);
	}
	إذا (*++oli != ':') {			/* doesn't take argument */
		إذا (!*ځای_پرځای_کړه)
			++optind;
	} وإلا {				/* takes (optional) argument */
		optarg = عدم;
		إذا (*ځای_پرځای_کړه)			/* no white space */
			optarg = ځای_پرځای_کړه;
		وإلا إذا (oli[1] != ':') {	/* arg not optional */
			إذا (++optind >= nargc) {	/* no arg */
				ځای_پرځای_کړه = EMSG;
				إذا (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				أرجع (BADARG);
			} وإلا
				optarg = nargv[optind];
		}
		ځای_پرځای_کړه = EMSG;
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
	أرجع (getopt_دننی(nargc, nargv, options, عدم, عدم, 0));
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

	أرجع (getopt_دننی(nargc, nargv, options, long_options, idx,
	    FLAG_ترتیب_بدلول));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
صحيح
getopt_long_only(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت بنية option *long_options, صحيح *idx)
{

	أرجع (getopt_دننی(nargc, nargv, options, long_options, idx,
	    FLAG_ترتیب_بدلول|FLAG_LONGONLY));
}
#د_که_پای

#د_که_پای /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
