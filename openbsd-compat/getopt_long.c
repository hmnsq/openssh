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
#அந்தர்பாவ "includes.h"

#எனில் !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#எனில் 0
#அந்தர்பாவ <err.h>
#அந்தர்பாவ <getopt.h>
#endif
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "log.h"

கட்டமைப்பு option {
	/* name of long option */
	மாறிலி எழுத்து *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	முழு has_arg;
	/* if not NULL, set *flag to val when option found */
	முழு *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	முழு val;
};

முழு	opterr = 1;		/* if error message should be printed */
முழு	optind = 1;		/* index into parent argv vector */
முழு	optopt = '?';		/* character checked for validity */
முழு	optreset;		/* reset getopt */
எழுத்து    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(முழு)'?'
#define	BADARG		((*options == ':') ? (முழு)':' : (முழு)'?')
#define	இடைவரிசை		(முழு)1

#define	EMSG		""

நிலையான முழு getopt_internal(முழு, எழுத்து * மாறிலி *, மாறிலி எழுத்து *,
			   மாறிலி கட்டமைப்பு option *, முழு *, முழு);
நிலையான முழு parse_long_options(எழுத்து * மாறிலி *, மாறிலி எழுத்து *,
			      மாறிலி கட்டமைப்பு option *, முழு *, முழு);
நிலையான முழு gcd(முழு, முழு);
நிலையான வெறுமை permute_args(முழு, முழு, முழு, எழுத்து * மாறிலி *);

நிலையான எழுத்து *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
நிலையான முழு nonopt_start = -1; /* first non option argument (for permute) */
நிலையான முழு nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
நிலையான மாறிலி எழுத்து recargchar[] = "option requires an argument -- %c";
நிலையான மாறிலி எழுத்து recargstring[] = "option requires an argument -- %s";
நிலையான மாறிலி எழுத்து ambig[] = "ambiguous option -- %.*s";
நிலையான மாறிலி எழுத்து noarg[] = "option doesn't take an argument -- %.*s";
நிலையான மாறிலி எழுத்து illoptchar[] = "unknown option -- %c";
நிலையான மாறிலி எழுத்து illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
நிலையான முழு
gcd(முழு a, முழு b)
{
	முழு c;

	c = a % b;
	போது (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	திரும்பு (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
நிலையான வெறுமை
permute_args(முழு panonopt_start, முழு panonopt_end, முழு opt_end,
	எழுத்து * மாறிலி *nargv)
{
	முழு cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	எழுத்து *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	க்கு (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		க்கு (j = 0; j < cyclelen; j++) {
			எனில் (pos >= panonopt_end)
				pos -= nnonopts;
			இல்லையெனில்
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((எழுத்து **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((எழுத்து **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
நிலையான முழு
parse_long_options(எழுத்து * மாறிலி *nargv, மாறிலி எழுத்து *options,
	மாறிலி கட்டமைப்பு option *long_options, முழு *idx, முழு short_too)
{
	எழுத்து *current_argv, *has_equal;
	size_t current_argv_len;
	முழு i, match;

	current_argv = place;
	match = -1;

	optind++;

	எனில் ((has_equal = strchr(current_argv, '=')) != வெற்று) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} இல்லையெனில்
		current_argv_len = strlen(current_argv);

	க்கு (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		எனில் (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			தொடர்;

		எனில் (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			நிறுத்து;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		எனில் (short_too && current_argv_len == 1)
			தொடர்;

		எனில் (match == -1)	/* partial match */
			match = i;
		இல்லையெனில் {
			/* ambiguous abbreviation */
			எனில் (PRINT_ERROR)
				warnx(ambig, (முழு)current_argv_len,
				     current_argv);
			optopt = 0;
			திரும்பு (BADCH);
		}
	}
	எனில் (match != -1) {		/* option found */
		எனில் (long_options[match].has_arg == no_argument
		    && has_equal) {
			எனில் (PRINT_ERROR)
				warnx(noarg, (முழு)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			எனில் (long_options[match].flag == வெற்று)
				optopt = long_options[match].val;
			இல்லையெனில்
				optopt = 0;
			திரும்பு (BADARG);
		}
		எனில் (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			எனில் (has_equal)
				optarg = has_equal;
			இல்லையெனில் எனில் (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		எனில் ((long_options[match].has_arg == required_argument)
		    && (optarg == வெற்று)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			எனில் (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			எனில் (long_options[match].flag == வெற்று)
				optopt = long_options[match].val;
			இல்லையெனில்
				optopt = 0;
			--optind;
			திரும்பு (BADARG);
		}
	} இல்லையெனில் {			/* unknown option */
		எனில் (short_too) {
			--optind;
			திரும்பு (-1);
		}
		எனில் (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		திரும்பு (BADCH);
	}
	எனில் (idx)
		*idx = match;
	எனில் (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		திரும்பு (0);
	} இல்லையெனில்
		திரும்பு (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
நிலையான முழு
getopt_internal(முழு nargc, எழுத்து * மாறிலி *nargv, மாறிலி எழுத்து *options,
	மாறிலி கட்டமைப்பு option *long_options, முழு *idx, முழு flags)
{
	எழுத்து *oli;				/* option letter list index */
	முழு optchar, short_too;
	நிலையான முழு posixly_correct = -1;

	எனில் (options == வெற்று)
		திரும்பு (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	எனில் (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	எனில் (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != வெற்று);
	எனில் (*options == '-')
		flags |= FLAG_ALLARGS;
	இல்லையெனில் எனில் (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	எனில் (*options == '+' || *options == '-')
		options++;

	optarg = வெற்று;
	எனில் (optreset)
		nonopt_start = nonopt_end = -1;
start:
	எனில் (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		எனில் (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			எனில் (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			இல்லையெனில் எனில் (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			திரும்பு (-1);
		}
		எனில் (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == வெற்று)) {
			place = EMSG;		/* found non-option */
			எனில் (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				திரும்பு (இடைவரிசை);
			}
			எனில் (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				திரும்பு (-1);
			}
			/* do permutation */
			எனில் (nonopt_start == -1)
				nonopt_start = optind;
			இல்லையெனில் எனில் (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			செல் start;
		}
		எனில் (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		எனில் (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			எனில் (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			திரும்பு (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	எனில் (long_options != வெற்று && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		எனில் (*place == '-')
			place++;		/* --foo long option */
		இல்லையெனில் எனில் (*place != ':' && strchr(options, *place) != வெற்று)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		எனில் (optchar != -1) {
			place = EMSG;
			திரும்பு (optchar);
		}
	}

	எனில் ((optchar = (முழு)*place++) == (முழு)':' ||
	    (optchar == (முழு)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == வெற்று) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		எனில் (optchar == (முழு)'-' && *place == '\0')
			திரும்பு (-1);
		எனில் (!*place)
			++optind;
		எனில் (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		திரும்பு (BADCH);
	}
	எனில் (long_options != வெற்று && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		எனில் (*place)			/* no space */
			/* NOTHING */;
		இல்லையெனில் எனில் (++optind >= nargc) {	/* no arg */
			place = EMSG;
			எனில் (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			திரும்பு (BADARG);
		} இல்லையெனில்				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		திரும்பு (optchar);
	}
	எனில் (*++oli != ':') {			/* doesn't take argument */
		எனில் (!*place)
			++optind;
	} இல்லையெனில் {				/* takes (optional) argument */
		optarg = வெற்று;
		எனில் (*place)			/* no white space */
			optarg = place;
		இல்லையெனில் எனில் (oli[1] != ':') {	/* arg not optional */
			எனில் (++optind >= nargc) {	/* no arg */
				place = EMSG;
				எனில் (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				திரும்பு (BADARG);
			} இல்லையெனில்
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	திரும்பு (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
முழு
getopt(முழு nargc, எழுத்து * மாறிலி *nargv, மாறிலி எழுத்து *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	திரும்பு (getopt_internal(nargc, nargv, options, வெற்று, வெற்று, 0));
}

#எனில் 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
முழு
getopt_long(முழு nargc, எழுத்து * மாறிலி *nargv, மாறிலி எழுத்து *options,
    மாறிலி கட்டமைப்பு option *long_options, முழு *idx)
{

	திரும்பு (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
முழு
getopt_long_only(முழு nargc, எழுத்து * மாறிலி *nargv, மாறிலி எழுத்து *options,
    மாறிலி கட்டமைப்பு option *long_options, முழு *idx)
{

	திரும்பு (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
