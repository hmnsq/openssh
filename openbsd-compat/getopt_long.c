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
#define warnx		logit

#اگر 0
#شامل <err.h>
#شامل <getopt.h>
#endif
#شامل <errno.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"

ساختار option {
	/* name of long option */
	ثابت نویسه *name;
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
نویسه    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(صحیح)'?'
#define	BADARG		((*options == ':') ? (صحیح)':' : (صحیح)'?')
#define	میان_ترتیب		(صحیح)1

#define	EMSG		""

ایستا صحیح getopt_internal(صحیح, نویسه * ثابت *, ثابت نویسه *,
			   ثابت ساختار option *, صحیح *, صحیح);
ایستا صحیح parse_long_options(نویسه * ثابت *, ثابت نویسه *,
			      ثابت ساختار option *, صحیح *, صحیح);
ایستا صحیح gcd(صحیح, صحیح);
ایستا تهی permute_args(صحیح, صحیح, صحیح, نویسه * ثابت *);

ایستا نویسه *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
ایستا صحیح nonopt_start = -1; /* first non option argument (for permute) */
ایستا صحیح nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
ایستا ثابت نویسه recargchar[] = "option requires an argument -- %c";
ایستا ثابت نویسه recargstring[] = "option requires an argument -- %s";
ایستا ثابت نویسه ambig[] = "ambiguous option -- %.*s";
ایستا ثابت نویسه noarg[] = "option doesn't take an argument -- %.*s";
ایستا ثابت نویسه illoptchar[] = "unknown option -- %c";
ایستا ثابت نویسه illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
ایستا صحیح
gcd(صحیح a, صحیح b)
{
	صحیح c;

	c = a % b;
	وقتی (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	بازگشت (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
ایستا تهی
permute_args(صحیح panonopt_start, صحیح panonopt_end, صحیح opt_end,
	نویسه * ثابت *nargv)
{
	صحیح cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	نویسه *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	برای (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		برای (j = 0; j < cyclelen; j++) {
			اگر (pos >= panonopt_end)
				pos -= nnonopts;
			وگرنه
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((نویسه **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((نویسه **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
ایستا صحیح
parse_long_options(نویسه * ثابت *nargv, ثابت نویسه *options,
	ثابت ساختار option *long_options, صحیح *idx, صحیح short_too)
{
	نویسه *current_argv, *has_equal;
	size_t current_argv_len;
	صحیح i, match;

	current_argv = place;
	match = -1;

	optind++;

	اگر ((has_equal = strchr(current_argv, '=')) != پوچ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} وگرنه
		current_argv_len = strlen(current_argv);

	برای (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		اگر (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			ادامه;

		اگر (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			بشکن;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		اگر (short_too && current_argv_len == 1)
			ادامه;

		اگر (match == -1)	/* partial match */
			match = i;
		وگرنه {
			/* ambiguous abbreviation */
			اگر (PRINT_ERROR)
				warnx(ambig, (صحیح)current_argv_len,
				     current_argv);
			optopt = 0;
			بازگشت (BADCH);
		}
	}
	اگر (match != -1) {		/* option found */
		اگر (long_options[match].has_arg == no_argument
		    && has_equal) {
			اگر (PRINT_ERROR)
				warnx(noarg, (صحیح)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			اگر (long_options[match].flag == پوچ)
				optopt = long_options[match].val;
			وگرنه
				optopt = 0;
			بازگشت (BADARG);
		}
		اگر (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			اگر (has_equal)
				optarg = has_equal;
			وگرنه اگر (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		اگر ((long_options[match].has_arg == required_argument)
		    && (optarg == پوچ)) {
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
			اگر (long_options[match].flag == پوچ)
				optopt = long_options[match].val;
			وگرنه
				optopt = 0;
			--optind;
			بازگشت (BADARG);
		}
	} وگرنه {			/* unknown option */
		اگر (short_too) {
			--optind;
			بازگشت (-1);
		}
		اگر (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		بازگشت (BADCH);
	}
	اگر (idx)
		*idx = match;
	اگر (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		بازگشت (0);
	} وگرنه
		بازگشت (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
ایستا صحیح
getopt_internal(صحیح nargc, نویسه * ثابت *nargv, ثابت نویسه *options,
	ثابت ساختار option *long_options, صحیح *idx, صحیح flags)
{
	نویسه *oli;				/* option letter list index */
	صحیح optchar, short_too;
	ایستا صحیح posixly_correct = -1;

	اگر (options == پوچ)
		بازگشت (-1);

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
		posixly_correct = (getenv("POSIXLY_CORRECT") != پوچ);
	اگر (*options == '-')
		flags |= FLAG_ALLARGS;
	وگرنه اگر (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	اگر (*options == '+' || *options == '-')
		options++;

	optarg = پوچ;
	اگر (optreset)
		nonopt_start = nonopt_end = -1;
start:
	اگر (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		اگر (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			اگر (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			وگرنه اگر (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			بازگشت (-1);
		}
		اگر (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == پوچ)) {
			place = EMSG;		/* found non-option */
			اگر (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				بازگشت (میان_ترتیب);
			}
			اگر (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				بازگشت (-1);
			}
			/* do permutation */
			اگر (nonopt_start == -1)
				nonopt_start = optind;
			وگرنه اگر (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			برو start;
		}
		اگر (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		اگر (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			اگر (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			بازگشت (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	اگر (long_options != پوچ && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		اگر (*place == '-')
			place++;		/* --foo long option */
		وگرنه اگر (*place != ':' && strchr(options, *place) != پوچ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		اگر (optchar != -1) {
			place = EMSG;
			بازگشت (optchar);
		}
	}

	اگر ((optchar = (صحیح)*place++) == (صحیح)':' ||
	    (optchar == (صحیح)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == پوچ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		اگر (optchar == (صحیح)'-' && *place == '\0')
			بازگشت (-1);
		اگر (!*place)
			++optind;
		اگر (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		بازگشت (BADCH);
	}
	اگر (long_options != پوچ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		اگر (*place)			/* no space */
			/* NOTHING */;
		وگرنه اگر (++optind >= nargc) {	/* no arg */
			place = EMSG;
			اگر (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			بازگشت (BADARG);
		} وگرنه				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		بازگشت (optchar);
	}
	اگر (*++oli != ':') {			/* doesn't take argument */
		اگر (!*place)
			++optind;
	} وگرنه {				/* takes (optional) argument */
		optarg = پوچ;
		اگر (*place)			/* no white space */
			optarg = place;
		وگرنه اگر (oli[1] != ':') {	/* arg not optional */
			اگر (++optind >= nargc) {	/* no arg */
				place = EMSG;
				اگر (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				بازگشت (BADARG);
			} وگرنه
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	بازگشت (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
صحیح
getopt(صحیح nargc, نویسه * ثابت *nargv, ثابت نویسه *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	بازگشت (getopt_internal(nargc, nargv, options, پوچ, پوچ, 0));
}

#اگر 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
صحیح
getopt_long(صحیح nargc, نویسه * ثابت *nargv, ثابت نویسه *options,
    ثابت ساختار option *long_options, صحیح *idx)
{

	بازگشت (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
صحیح
getopt_long_only(صحیح nargc, نویسه * ثابت *nargv, ثابت نویسه *options,
    ثابت ساختار option *long_options, صحیح *idx)
{

	بازگشت (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
