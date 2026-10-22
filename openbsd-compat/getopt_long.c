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
#अन्तर्भाव "includes.h"

#यदि !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#यदि 0
#अन्तर्भाव <err.h>
#अन्तर्भाव <getopt.h>
#endif
#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "log.h"

संरचना option {
	/* name of long option */
	ध्रुव वर्ण *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	पूर्णाङ्क has_arg;
	/* if not NULL, set *flag to val when option found */
	पूर्णाङ्क *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	पूर्णाङ्क val;
};

पूर्णाङ्क	opterr = 1;		/* if error message should be printed */
पूर्णाङ्क	optind = 1;		/* index into parent argv vector */
पूर्णाङ्क	optopt = '?';		/* character checked for validity */
पूर्णाङ्क	optreset;		/* reset getopt */
वर्ण    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(पूर्णाङ्क)'?'
#define	BADARG		((*options == ':') ? (पूर्णाङ्क)':' : (पूर्णाङ्क)'?')
#define	मध्यक्रम		(पूर्णाङ्क)1

#define	EMSG		""

स्थिर पूर्णाङ्क getopt_internal(पूर्णाङ्क, वर्ण * ध्रुव *, ध्रुव वर्ण *,
			   ध्रुव संरचना option *, पूर्णाङ्क *, पूर्णाङ्क);
स्थिर पूर्णाङ्क parse_long_options(वर्ण * ध्रुव *, ध्रुव वर्ण *,
			      ध्रुव संरचना option *, पूर्णाङ्क *, पूर्णाङ्क);
स्थिर पूर्णाङ्क gcd(पूर्णाङ्क, पूर्णाङ्क);
स्थिर शून्य permute_args(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, वर्ण * ध्रुव *);

स्थिर वर्ण *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
स्थिर पूर्णाङ्क nonopt_start = -1; /* first non option argument (for permute) */
स्थिर पूर्णाङ्क nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
स्थिर ध्रुव वर्ण recargchar[] = "option requires an argument -- %c";
स्थिर ध्रुव वर्ण recargstring[] = "option requires an argument -- %s";
स्थिर ध्रुव वर्ण ambig[] = "ambiguous option -- %.*s";
स्थिर ध्रुव वर्ण noarg[] = "option doesn't take an argument -- %.*s";
स्थिर ध्रुव वर्ण illoptchar[] = "unknown option -- %c";
स्थिर ध्रुव वर्ण illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
स्थिर पूर्णाङ्क
gcd(पूर्णाङ्क a, पूर्णाङ्क b)
{
	पूर्णाङ्क c;

	c = a % b;
	यावत् (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	प्रत्यागम (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
स्थिर शून्य
permute_args(पूर्णाङ्क panonopt_start, पूर्णाङ्क panonopt_end, पूर्णाङ्क opt_end,
	वर्ण * ध्रुव *nargv)
{
	पूर्णाङ्क cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	वर्ण *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	प्रति (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		प्रति (j = 0; j < cyclelen; j++) {
			यदि (pos >= panonopt_end)
				pos -= nnonopts;
			अन्यथा
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((वर्ण **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((वर्ण **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
स्थिर पूर्णाङ्क
parse_long_options(वर्ण * ध्रुव *nargv, ध्रुव वर्ण *options,
	ध्रुव संरचना option *long_options, पूर्णाङ्क *idx, पूर्णाङ्क short_too)
{
	वर्ण *current_argv, *has_equal;
	size_t current_argv_len;
	पूर्णाङ्क i, match;

	current_argv = place;
	match = -1;

	optind++;

	यदि ((has_equal = strchr(current_argv, '=')) != रिक्त) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} अन्यथा
		current_argv_len = strlen(current_argv);

	प्रति (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		यदि (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			अनुवर्त;

		यदि (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			भङ्ग;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		यदि (short_too && current_argv_len == 1)
			अनुवर्त;

		यदि (match == -1)	/* partial match */
			match = i;
		अन्यथा {
			/* ambiguous abbreviation */
			यदि (PRINT_ERROR)
				warnx(ambig, (पूर्णाङ्क)current_argv_len,
				     current_argv);
			optopt = 0;
			प्रत्यागम (BADCH);
		}
	}
	यदि (match != -1) {		/* option found */
		यदि (long_options[match].has_arg == no_argument
		    && has_equal) {
			यदि (PRINT_ERROR)
				warnx(noarg, (पूर्णाङ्क)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			यदि (long_options[match].flag == रिक्त)
				optopt = long_options[match].val;
			अन्यथा
				optopt = 0;
			प्रत्यागम (BADARG);
		}
		यदि (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			यदि (has_equal)
				optarg = has_equal;
			अन्यथा यदि (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		यदि ((long_options[match].has_arg == required_argument)
		    && (optarg == रिक्त)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			यदि (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			यदि (long_options[match].flag == रिक्त)
				optopt = long_options[match].val;
			अन्यथा
				optopt = 0;
			--optind;
			प्रत्यागम (BADARG);
		}
	} अन्यथा {			/* unknown option */
		यदि (short_too) {
			--optind;
			प्रत्यागम (-1);
		}
		यदि (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		प्रत्यागम (BADCH);
	}
	यदि (idx)
		*idx = match;
	यदि (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		प्रत्यागम (0);
	} अन्यथा
		प्रत्यागम (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
स्थिर पूर्णाङ्क
getopt_internal(पूर्णाङ्क nargc, वर्ण * ध्रुव *nargv, ध्रुव वर्ण *options,
	ध्रुव संरचना option *long_options, पूर्णाङ्क *idx, पूर्णाङ्क flags)
{
	वर्ण *oli;				/* option letter list index */
	पूर्णाङ्क optchar, short_too;
	स्थिर पूर्णाङ्क posixly_correct = -1;

	यदि (options == रिक्त)
		प्रत्यागम (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	यदि (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	यदि (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != रिक्त);
	यदि (*options == '-')
		flags |= FLAG_ALLARGS;
	अन्यथा यदि (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	यदि (*options == '+' || *options == '-')
		options++;

	optarg = रिक्त;
	यदि (optreset)
		nonopt_start = nonopt_end = -1;
start:
	यदि (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		यदि (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			यदि (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			अन्यथा यदि (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			प्रत्यागम (-1);
		}
		यदि (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == रिक्त)) {
			place = EMSG;		/* found non-option */
			यदि (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				प्रत्यागम (मध्यक्रम);
			}
			यदि (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				प्रत्यागम (-1);
			}
			/* do permutation */
			यदि (nonopt_start == -1)
				nonopt_start = optind;
			अन्यथा यदि (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			गच्छ start;
		}
		यदि (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		यदि (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			यदि (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			प्रत्यागम (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	यदि (long_options != रिक्त && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		यदि (*place == '-')
			place++;		/* --foo long option */
		अन्यथा यदि (*place != ':' && strchr(options, *place) != रिक्त)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		यदि (optchar != -1) {
			place = EMSG;
			प्रत्यागम (optchar);
		}
	}

	यदि ((optchar = (पूर्णाङ्क)*place++) == (पूर्णाङ्क)':' ||
	    (optchar == (पूर्णाङ्क)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == रिक्त) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		यदि (optchar == (पूर्णाङ्क)'-' && *place == '\0')
			प्रत्यागम (-1);
		यदि (!*place)
			++optind;
		यदि (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		प्रत्यागम (BADCH);
	}
	यदि (long_options != रिक्त && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		यदि (*place)			/* no space */
			/* NOTHING */;
		अन्यथा यदि (++optind >= nargc) {	/* no arg */
			place = EMSG;
			यदि (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			प्रत्यागम (BADARG);
		} अन्यथा				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		प्रत्यागम (optchar);
	}
	यदि (*++oli != ':') {			/* doesn't take argument */
		यदि (!*place)
			++optind;
	} अन्यथा {				/* takes (optional) argument */
		optarg = रिक्त;
		यदि (*place)			/* no white space */
			optarg = place;
		अन्यथा यदि (oli[1] != ':') {	/* arg not optional */
			यदि (++optind >= nargc) {	/* no arg */
				place = EMSG;
				यदि (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				प्रत्यागम (BADARG);
			} अन्यथा
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	प्रत्यागम (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
पूर्णाङ्क
getopt(पूर्णाङ्क nargc, वर्ण * ध्रुव *nargv, ध्रुव वर्ण *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	प्रत्यागम (getopt_internal(nargc, nargv, options, रिक्त, रिक्त, 0));
}

#यदि 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
पूर्णाङ्क
getopt_long(पूर्णाङ्क nargc, वर्ण * ध्रुव *nargv, ध्रुव वर्ण *options,
    ध्रुव संरचना option *long_options, पूर्णाङ्क *idx)
{

	प्रत्यागम (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
पूर्णाङ्क
getopt_long_only(पूर्णाङ्क nargc, वर्ण * ध्रुव *nargv, ध्रुव वर्ण *options,
    ध्रुव संरचना option *long_options, पूर्णाङ्क *idx)
{

	प्रत्यागम (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
