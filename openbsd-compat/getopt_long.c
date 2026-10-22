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
#અન્તર્ભાવ "includes.h"

#જો !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#define warnx		logit

#જો 0
#અન્તર્ભાવ <err.h>
#અન્તર્ભાવ <getopt.h>
#endif
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "log.h"

સંરચના option {
	/* name of long option */
	અચલ અક્ષર *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	પૂર્ણાંક has_arg;
	/* if not NULL, set *flag to val when option found */
	પૂર્ણાંક *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	પૂર્ણાંક val;
};

પૂર્ણાંક	opterr = 1;		/* if error message should be printed */
પૂર્ણાંક	optind = 1;		/* index into parent argv vector */
પૂર્ણાંક	optopt = '?';		/* character checked for validity */
પૂર્ણાંક	optreset;		/* reset getopt */
અક્ષર    *optarg;		/* argument associated with option */

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(પૂર્ણાંક)'?'
#define	BADARG		((*options == ':') ? (પૂર્ણાંક)':' : (પૂર્ણાંક)'?')
#define	મધ્યક્રમ		(પૂર્ણાંક)1

#define	EMSG		""

સ્થિર પૂર્ણાંક getopt_internal(પૂર્ણાંક, અક્ષર * અચલ *, અચલ અક્ષર *,
			   અચલ સંરચના option *, પૂર્ણાંક *, પૂર્ણાંક);
સ્થિર પૂર્ણાંક parse_long_options(અક્ષર * અચલ *, અચલ અક્ષર *,
			      અચલ સંરચના option *, પૂર્ણાંક *, પૂર્ણાંક);
સ્થિર પૂર્ણાંક gcd(પૂર્ણાંક, પૂર્ણાંક);
સ્થિર શૂન્ય permute_args(પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, અક્ષર * અચલ *);

સ્થિર અક્ષર *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
સ્થિર પૂર્ણાંક nonopt_start = -1; /* first non option argument (for permute) */
સ્થિર પૂર્ણાંક nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
સ્થિર અચલ અક્ષર recargchar[] = "option requires an argument -- %c";
સ્થિર અચલ અક્ષર recargstring[] = "option requires an argument -- %s";
સ્થિર અચલ અક્ષર ambig[] = "ambiguous option -- %.*s";
સ્થિર અચલ અક્ષર noarg[] = "option doesn't take an argument -- %.*s";
સ્થિર અચલ અક્ષર illoptchar[] = "unknown option -- %c";
સ્થિર અચલ અક્ષર illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
સ્થિર પૂર્ણાંક
gcd(પૂર્ણાંક a, પૂર્ણાંક b)
{
	પૂર્ણાંક c;

	c = a % b;
	જ્યારે (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	પાછા (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
સ્થિર શૂન્ય
permute_args(પૂર્ણાંક panonopt_start, પૂર્ણાંક panonopt_end, પૂર્ણાંક opt_end,
	અક્ષર * અચલ *nargv)
{
	પૂર્ણાંક cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	અક્ષર *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	માટે (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		માટે (j = 0; j < cyclelen; j++) {
			જો (pos >= panonopt_end)
				pos -= nnonopts;
			નહીંતર
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((અક્ષર **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((અક્ષર **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
સ્થિર પૂર્ણાંક
parse_long_options(અક્ષર * અચલ *nargv, અચલ અક્ષર *options,
	અચલ સંરચના option *long_options, પૂર્ણાંક *idx, પૂર્ણાંક short_too)
{
	અક્ષર *current_argv, *has_equal;
	size_t current_argv_len;
	પૂર્ણાંક i, match;

	current_argv = place;
	match = -1;

	optind++;

	જો ((has_equal = strchr(current_argv, '=')) != ખાલી) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} નહીંતર
		current_argv_len = strlen(current_argv);

	માટે (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		જો (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			ચાલુ;

		જો (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			તોડો;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		જો (short_too && current_argv_len == 1)
			ચાલુ;

		જો (match == -1)	/* partial match */
			match = i;
		નહીંતર {
			/* ambiguous abbreviation */
			જો (PRINT_ERROR)
				warnx(ambig, (પૂર્ણાંક)current_argv_len,
				     current_argv);
			optopt = 0;
			પાછા (BADCH);
		}
	}
	જો (match != -1) {		/* option found */
		જો (long_options[match].has_arg == no_argument
		    && has_equal) {
			જો (PRINT_ERROR)
				warnx(noarg, (પૂર્ણાંક)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			જો (long_options[match].flag == ખાલી)
				optopt = long_options[match].val;
			નહીંતર
				optopt = 0;
			પાછા (BADARG);
		}
		જો (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			જો (has_equal)
				optarg = has_equal;
			નહીંતર જો (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		જો ((long_options[match].has_arg == required_argument)
		    && (optarg == ખાલી)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			જો (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			જો (long_options[match].flag == ખાલી)
				optopt = long_options[match].val;
			નહીંતર
				optopt = 0;
			--optind;
			પાછા (BADARG);
		}
	} નહીંતર {			/* unknown option */
		જો (short_too) {
			--optind;
			પાછા (-1);
		}
		જો (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		પાછા (BADCH);
	}
	જો (idx)
		*idx = match;
	જો (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		પાછા (0);
	} નહીંતર
		પાછા (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
સ્થિર પૂર્ણાંક
getopt_internal(પૂર્ણાંક nargc, અક્ષર * અચલ *nargv, અચલ અક્ષર *options,
	અચલ સંરચના option *long_options, પૂર્ણાંક *idx, પૂર્ણાંક flags)
{
	અક્ષર *oli;				/* option letter list index */
	પૂર્ણાંક optchar, short_too;
	સ્થિર પૂર્ણાંક posixly_correct = -1;

	જો (options == ખાલી)
		પાછા (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	જો (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	જો (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != ખાલી);
	જો (*options == '-')
		flags |= FLAG_ALLARGS;
	નહીંતર જો (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	જો (*options == '+' || *options == '-')
		options++;

	optarg = ખાલી;
	જો (optreset)
		nonopt_start = nonopt_end = -1;
start:
	જો (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		જો (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			જો (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			નહીંતર જો (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			પાછા (-1);
		}
		જો (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && strchr(options, '-') == ખાલી)) {
			place = EMSG;		/* found non-option */
			જો (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				પાછા (મધ્યક્રમ);
			}
			જો (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				પાછા (-1);
			}
			/* do permutation */
			જો (nonopt_start == -1)
				nonopt_start = optind;
			નહીંતર જો (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			જાઓ start;
		}
		જો (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		જો (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			જો (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			પાછા (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	જો (long_options != ખાલી && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		જો (*place == '-')
			place++;		/* --foo long option */
		નહીંતર જો (*place != ':' && strchr(options, *place) != ખાલી)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		જો (optchar != -1) {
			place = EMSG;
			પાછા (optchar);
		}
	}

	જો ((optchar = (પૂર્ણાંક)*place++) == (પૂર્ણાંક)':' ||
	    (optchar == (પૂર્ણાંક)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == ખાલી) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		જો (optchar == (પૂર્ણાંક)'-' && *place == '\0')
			પાછા (-1);
		જો (!*place)
			++optind;
		જો (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		પાછા (BADCH);
	}
	જો (long_options != ખાલી && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		જો (*place)			/* no space */
			/* NOTHING */;
		નહીંતર જો (++optind >= nargc) {	/* no arg */
			place = EMSG;
			જો (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			પાછા (BADARG);
		} નહીંતર				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		પાછા (optchar);
	}
	જો (*++oli != ':') {			/* doesn't take argument */
		જો (!*place)
			++optind;
	} નહીંતર {				/* takes (optional) argument */
		optarg = ખાલી;
		જો (*place)			/* no white space */
			optarg = place;
		નહીંતર જો (oli[1] != ':') {	/* arg not optional */
			જો (++optind >= nargc) {	/* no arg */
				place = EMSG;
				જો (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				પાછા (BADARG);
			} નહીંતર
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	પાછા (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
પૂર્ણાંક
getopt(પૂર્ણાંક nargc, અક્ષર * અચલ *nargv, અચલ અક્ષર *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	પાછા (getopt_internal(nargc, nargv, options, ખાલી, ખાલી, 0));
}

#જો 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
પૂર્ણાંક
getopt_long(પૂર્ણાંક nargc, અક્ષર * અચલ *nargv, અચલ અક્ષર *options,
    અચલ સંરચના option *long_options, પૂર્ણાંક *idx)
{

	પાછા (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
પૂર્ણાંક
getopt_long_only(પૂર્ણાંક nargc, અક્ષર * અચલ *nargv, અચલ અક્ષર *options,
    અચલ સંરચના option *long_options, પૂર્ણાંક *idx)
{

	પાછા (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#endif

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
