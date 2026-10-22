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
#define warnx		logit

#إذا 0
#ضمن <err.h>
#ضمن <getopt.h>
#endif
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

#define بغ_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(صحيح)'?'
#define	BADARG		((*options == ':') ? (صحيح)':' : (صحيح)'?')
#define	بس_ڟر		(صحيح)1

#define	EMSG		""

ساكن صحيح getopt_internal(صحيح, حرف * ثابت *, ثابت حرف *,
			   ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح parse_long_options(حرف * ثابت *, ثابت حرف *,
			      ثابت بنية option *, صحيح *, صحيح);
ساكن صحيح gcd(صحيح, صحيح);
ساكن فراغ permute_حجوجي(صحيح, صحيح, صحيح, حرف * ثابت *);

ساكن حرف *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ساكن صحيح nonopt_start = -1; /* first non option argument (for permute) */
ساكن صحيح nonopt_end = -1;   /* first option after non options (for permute) */

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
gcd(صحيح a, صحيح b)
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
permute_حجوجي(صحيح panonopt_start, صحيح panonopt_end, صحيح opt_end,
	حرف * ثابت *nargv)
{
	صحيح cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	حرف *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	لكل (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		لكل (j = 0; j < cyclelen; j++) {
			إذا (pos >= panonopt_end)
				pos -= nnonopts;
			وإلا
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((حرف **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((حرف **)nargv)[cstart] = swap;
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
	size_t current_argv_len;
	صحيح i, match;

	current_argv = place;
	match = -1;

	optind++;

	إذا ((has_equal = strchr(current_argv, '=')) != عدم) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} وإلا
		current_argv_len = strlen(current_argv);

	لكل (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		إذا (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			استمر;

		إذا (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			اكسر;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		إذا (short_too && current_argv_len == 1)
			استمر;

		إذا (match == -1)	/* partial match */
			match = i;
		وإلا {
			/* ambiguous abbreviation */
			إذا (بغ_ERROR)
				warnx(ambig, (صحيح)current_argv_len,
				     current_argv);
			optopt = 0;
			أرجع (BADCH);
		}
	}
	إذا (match != -1) {		/* option found */
		إذا (long_options[match].has_arg == no_argument
		    && has_equal) {
			إذا (بغ_ERROR)
				warnx(noarg, (صحيح)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			إذا (long_options[match].flag == عدم)
				optopt = long_options[match].val;
			وإلا
				optopt = 0;
			أرجع (BADARG);
		}
		إذا (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			إذا (has_equal)
				optarg = has_equal;
			وإلا إذا (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		إذا ((long_options[match].has_arg == required_argument)
		    && (optarg == عدم)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			إذا (بغ_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			إذا (long_options[match].flag == عدم)
				optopt = long_options[match].val;
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
		إذا (بغ_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		أرجع (BADCH);
	}
	إذا (idx)
		*idx = match;
	إذا (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		أرجع (0);
	} وإلا
		أرجع (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ساكن صحيح
getopt_internal(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
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
		flags &= ~FLAG_PERMUTE;
	إذا (*options == '+' || *options == '-')
		options++;

	optarg = عدم;
	إذا (optreset)
		nonopt_start = nonopt_end = -1;
start:
	إذا (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		إذا (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			إذا (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_حجوجي(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			وإلا إذا (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			أرجع (-1);
		}
		إذا (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == عدم)) {
			place = EMSG;		/* found non-option */
			إذا (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				أرجع (بس_ڟر);
			}
			إذا (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				أرجع (-1);
			}
			/* do permutation */
			إذا (nonopt_start == -1)
				nonopt_start = optind;
			وإلا إذا (nonopt_end != -1) {
				permute_حجوجي(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			اذهب start;
		}
		إذا (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		إذا (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			إذا (nonopt_end != -1) {
				permute_حجوجي(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			أرجع (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	إذا (long_options != عدم && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		إذا (*place == '-')
			place++;		/* --foo long option */
		وإلا إذا (*place != ':' && strchr(options, *place) != عدم)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		إذا (optchar != -1) {
			place = EMSG;
			أرجع (optchar);
		}
	}

	إذا ((optchar = (صحيح)*place++) == (صحيح)':' ||
	    (optchar == (صحيح)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == عدم) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		إذا (optchar == (صحيح)'-' && *place == '\0')
			أرجع (-1);
		إذا (!*place)
			++optind;
		إذا (بغ_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		أرجع (BADCH);
	}
	إذا (long_options != عدم && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		إذا (*place)			/* no space */
			/* NOTHING */;
		وإلا إذا (++optind >= nargc) {	/* no arg */
			place = EMSG;
			إذا (بغ_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			أرجع (BADARG);
		} وإلا				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		أرجع (optchar);
	}
	إذا (*++oli != ':') {			/* doesn't take argument */
		إذا (!*place)
			++optind;
	} وإلا {				/* takes (optional) argument */
		optarg = عدم;
		إذا (*place)			/* no white space */
			optarg = place;
		وإلا إذا (oli[1] != ':') {	/* arg not optional */
			إذا (++optind >= nargc) {	/* no arg */
				place = EMSG;
				إذا (بغ_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				أرجع (BADARG);
			} وإلا
				optarg = nargv[optind];
		}
		place = EMSG;
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
	أرجع (getopt_internal(nargc, nargv, options, عدم, عدم, 0));
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

	أرجع (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
صحيح
getopt_long_only(صحيح nargc, حرف * ثابت *nargv, ثابت حرف *options,
    ثابت بنية option *long_options, صحيح *idx)
{

	أرجع (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
