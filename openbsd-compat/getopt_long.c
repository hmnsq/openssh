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
#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#എങ്കിൽ 0
#അന്തര്ഭാവ <err.h>
#അന്തര്ഭാവ <getopt.h>
#endif
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "log.h"

ഘടന option {
	/* name of long option */
	സ്ഥിരം അക്ഷരം *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	പൂർണ്ണസംഖ്യ has_arg;
	/* if not NULL, set *flag to val when option found */
	പൂർണ്ണസംഖ്യ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	പൂർണ്ണസംഖ്യ val;
};

പൂർണ്ണസംഖ്യ	opterr = 1;		/* if error message should be printed */
പൂർണ്ണസംഖ്യ	optind = 1;		/* index into parent argv vector */
പൂർണ്ണസംഖ്യ	optopt = '?';		/* character checked for validity */
പൂർണ്ണസംഖ്യ	optreset;		/* reset getopt */
അക്ഷരം    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(പൂർണ്ണസംഖ്യ)'?'
#define	BADARG		((*options == ':') ? (പൂർണ്ണസംഖ്യ)':' : (പൂർണ്ണസംഖ്യ)'?')
#define	മധ്യക്രമം		(പൂർണ്ണസംഖ്യ)1

#define	EMSG		""

സ്ഥിതം പൂർണ്ണസംഖ്യ getopt_internal(പൂർണ്ണസംഖ്യ, അക്ഷരം * സ്ഥിരം *, സ്ഥിരം അക്ഷരം *,
			   സ്ഥിരം ഘടന option *, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം പൂർണ്ണസംഖ്യ parse_long_options(അക്ഷരം * സ്ഥിരം *, സ്ഥിരം അക്ഷരം *,
			      സ്ഥിരം ഘടന option *, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം പൂർണ്ണസംഖ്യ gcd(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
സ്ഥിതം ശൂന്യം permute_args(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, അക്ഷരം * സ്ഥിരം *);

സ്ഥിതം അക്ഷരം *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
സ്ഥിതം പൂർണ്ണസംഖ്യ nonopt_start = -1; /* first non option argument (for permute) */
സ്ഥിതം പൂർണ്ണസംഖ്യ nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
സ്ഥിതം സ്ഥിരം അക്ഷരം recargchar[] = "option requires an argument -- %c";
സ്ഥിതം സ്ഥിരം അക്ഷരം recargstring[] = "option requires an argument -- %s";
സ്ഥിതം സ്ഥിരം അക്ഷരം ambig[] = "ambiguous option -- %.*s";
സ്ഥിതം സ്ഥിരം അക്ഷരം noarg[] = "option doesn't take an argument -- %.*s";
സ്ഥിതം സ്ഥിരം അക്ഷരം illoptchar[] = "unknown option -- %c";
സ്ഥിതം സ്ഥിരം അക്ഷരം illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
gcd(പൂർണ്ണസംഖ്യ a, പൂർണ്ണസംഖ്യ b)
{
	പൂർണ്ണസംഖ്യ c;

	c = a % b;
	ആകുമ്പോൾ (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	തിരികെ (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
സ്ഥിതം ശൂന്യം
permute_args(പൂർണ്ണസംഖ്യ panonopt_start, പൂർണ്ണസംഖ്യ panonopt_end, പൂർണ്ണസംഖ്യ opt_end,
	അക്ഷരം * സ്ഥിരം *nargv)
{
	പൂർണ്ണസംഖ്യ cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	അക്ഷരം *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	വേണ്ടി (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		വേണ്ടി (j = 0; j < cyclelen; j++) {
			എങ്കിൽ (pos >= panonopt_end)
				pos -= nnonopts;
			അല്ലെങ്കിൽ
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((അക്ഷരം **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((അക്ഷരം **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_long_options(അക്ഷരം * സ്ഥിരം *nargv, സ്ഥിരം അക്ഷരം *options,
	സ്ഥിരം ഘടന option *long_options, പൂർണ്ണസംഖ്യ *idx, പൂർണ്ണസംഖ്യ short_too)
{
	അക്ഷരം *current_argv, *has_equal;
	size_t current_argv_len;
	പൂർണ്ണസംഖ്യ i, match;

	current_argv = place;
	match = -1;

	optind++;

	എങ്കിൽ ((has_equal = strchr(current_argv, '=')) != ശൂന്യ) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} അല്ലെങ്കിൽ
		current_argv_len = strlen(current_argv);

	വേണ്ടി (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		എങ്കിൽ (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			തുടരുക;

		എങ്കിൽ (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			നിർത്തുക;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		എങ്കിൽ (short_too && current_argv_len == 1)
			തുടരുക;

		എങ്കിൽ (match == -1)	/* partial match */
			match = i;
		അല്ലെങ്കിൽ {
			/* ambiguous abbreviation */
			എങ്കിൽ (PRINT_ERROR)
				warnx(ambig, (പൂർണ്ണസംഖ്യ)current_argv_len,
				     current_argv);
			optopt = 0;
			തിരികെ (BADCH);
		}
	}
	എങ്കിൽ (match != -1) {		/* option found */
		എങ്കിൽ (long_options[match].has_arg == no_argument
		    && has_equal) {
			എങ്കിൽ (PRINT_ERROR)
				warnx(noarg, (പൂർണ്ണസംഖ്യ)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			എങ്കിൽ (long_options[match].flag == ശൂന്യ)
				optopt = long_options[match].val;
			അല്ലെങ്കിൽ
				optopt = 0;
			തിരികെ (BADARG);
		}
		എങ്കിൽ (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			എങ്കിൽ (has_equal)
				optarg = has_equal;
			അല്ലെങ്കിൽ എങ്കിൽ (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		എങ്കിൽ ((long_options[match].has_arg == required_argument)
		    && (optarg == ശൂന്യ)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			എങ്കിൽ (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			എങ്കിൽ (long_options[match].flag == ശൂന്യ)
				optopt = long_options[match].val;
			അല്ലെങ്കിൽ
				optopt = 0;
			--optind;
			തിരികെ (BADARG);
		}
	} അല്ലെങ്കിൽ {			/* unknown option */
		എങ്കിൽ (short_too) {
			--optind;
			തിരികെ (-1);
		}
		എങ്കിൽ (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		തിരികെ (BADCH);
	}
	എങ്കിൽ (idx)
		*idx = match;
	എങ്കിൽ (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		തിരികെ (0);
	} അല്ലെങ്കിൽ
		തിരികെ (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
getopt_internal(പൂർണ്ണസംഖ്യ nargc, അക്ഷരം * സ്ഥിരം *nargv, സ്ഥിരം അക്ഷരം *options,
	സ്ഥിരം ഘടന option *long_options, പൂർണ്ണസംഖ്യ *idx, പൂർണ്ണസംഖ്യ flags)
{
	അക്ഷരം *oli;				/* option letter list index */
	പൂർണ്ണസംഖ്യ optchar, short_too;
	സ്ഥിതം പൂർണ്ണസംഖ്യ posixly_correct = -1;

	എങ്കിൽ (options == ശൂന്യ)
		തിരികെ (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	എങ്കിൽ (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	എങ്കിൽ (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ശൂന്യ);
	എങ്കിൽ (*options == '-')
		flags |= FLAG_ALLARGS;
	അല്ലെങ്കിൽ എങ്കിൽ (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	എങ്കിൽ (*options == '+' || *options == '-')
		options++;

	optarg = ശൂന്യ;
	എങ്കിൽ (optreset)
		nonopt_start = nonopt_end = -1;
start:
	എങ്കിൽ (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		എങ്കിൽ (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			എങ്കിൽ (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			അല്ലെങ്കിൽ എങ്കിൽ (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			തിരികെ (-1);
		}
		എങ്കിൽ (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == ശൂന്യ)) {
			place = EMSG;		/* found non-option */
			എങ്കിൽ (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				തിരികെ (മധ്യക്രമം);
			}
			എങ്കിൽ (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				തിരികെ (-1);
			}
			/* do permutation */
			എങ്കിൽ (nonopt_start == -1)
				nonopt_start = optind;
			അല്ലെങ്കിൽ എങ്കിൽ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			പോകുക start;
		}
		എങ്കിൽ (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		എങ്കിൽ (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			എങ്കിൽ (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			തിരികെ (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	എങ്കിൽ (long_options != ശൂന്യ && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		എങ്കിൽ (*place == '-')
			place++;		/* --foo long option */
		അല്ലെങ്കിൽ എങ്കിൽ (*place != ':' && strchr(options, *place) != ശൂന്യ)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		എങ്കിൽ (optchar != -1) {
			place = EMSG;
			തിരികെ (optchar);
		}
	}

	എങ്കിൽ ((optchar = (പൂർണ്ണസംഖ്യ)*place++) == (പൂർണ്ണസംഖ്യ)':' ||
	    (optchar == (പൂർണ്ണസംഖ്യ)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == ശൂന്യ) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		എങ്കിൽ (optchar == (പൂർണ്ണസംഖ്യ)'-' && *place == '\0')
			തിരികെ (-1);
		എങ്കിൽ (!*place)
			++optind;
		എങ്കിൽ (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		തിരികെ (BADCH);
	}
	എങ്കിൽ (long_options != ശൂന്യ && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		എങ്കിൽ (*place)			/* no space */
			/* NOTHING */;
		അല്ലെങ്കിൽ എങ്കിൽ (++optind >= nargc) {	/* no arg */
			place = EMSG;
			എങ്കിൽ (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			തിരികെ (BADARG);
		} അല്ലെങ്കിൽ				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		തിരികെ (optchar);
	}
	എങ്കിൽ (*++oli != ':') {			/* doesn't take argument */
		എങ്കിൽ (!*place)
			++optind;
	} അല്ലെങ്കിൽ {				/* takes (optional) argument */
		optarg = ശൂന്യ;
		എങ്കിൽ (*place)			/* no white space */
			optarg = place;
		അല്ലെങ്കിൽ എങ്കിൽ (oli[1] != ':') {	/* arg not optional */
			എങ്കിൽ (++optind >= nargc) {	/* no arg */
				place = EMSG;
				എങ്കിൽ (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				തിരികെ (BADARG);
			} അല്ലെങ്കിൽ
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	തിരികെ (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
പൂർണ്ണസംഖ്യ
getopt(പൂർണ്ണസംഖ്യ nargc, അക്ഷരം * സ്ഥിരം *nargv, സ്ഥിരം അക്ഷരം *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	തിരികെ (getopt_internal(nargc, nargv, options, ശൂന്യ, ശൂന്യ, 0));
}

#എങ്കിൽ 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
പൂർണ്ണസംഖ്യ
getopt_long(പൂർണ്ണസംഖ്യ nargc, അക്ഷരം * സ്ഥിരം *nargv, സ്ഥിരം അക്ഷരം *options,
    സ്ഥിരം ഘടന option *long_options, പൂർണ്ണസംഖ്യ *idx)
{

	തിരികെ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
പൂർണ്ണസംഖ്യ
getopt_long_only(പൂർണ്ണസംഖ്യ nargc, അക്ഷരം * സ്ഥിരം *nargv, സ്ഥിരം അക്ഷരം *options,
    സ്ഥിരം ഘടന option *long_options, പൂർണ്ണസംഖ്യ *idx)
{

	തിരികെ (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
