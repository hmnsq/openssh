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
#समावेश "includes.h"

#अगर !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

/*
 * Some defines to make it easier to keep the code in sync with upstream.
 * getopt opterr optind optopt optreset optarg are all in defines.h which is
 * pulled in by includes.h.
 */
#घोषणा warnx		logit

#अगर 0
#समावेश <err.h>
#समावेश <getopt.h>
#पूर्ण_अगर
#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "log.h"

काष्ठा option {
	/* name of long option */
	स्थिर अक्षर *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	पूर्णांक has_arg;
	/* if not NULL, set *flag to val when option found */
	पूर्णांक *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	पूर्णांक val;
};

पूर्णांक	opterr = 1;		/* if error message should be printed */
पूर्णांक	optind = 1;		/* index into parent argv vector */
पूर्णांक	optopt = '?';		/* character checked for validity */
पूर्णांक	optreset;		/* reset getopt */
अक्षर    *optarg;		/* argument associated with option */

#घोषणा PRINT_ERROR	((opterr) && (*options != ':'))

#घोषणा FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#घोषणा FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#घोषणा FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#घोषणा	BADCH		(पूर्णांक)'?'
#घोषणा	BADARG		((*options == ':') ? (पूर्णांक)':' : (पूर्णांक)'?')
#घोषणा	मध्यक्रम		(पूर्णांक)1

#घोषणा	EMSG		""

अटल पूर्णांक getopt_internal(पूर्णांक, अक्षर * स्थिर *, स्थिर अक्षर *,
			   स्थिर काष्ठा option *, पूर्णांक *, पूर्णांक);
अटल पूर्णांक parse_long_options(अक्षर * स्थिर *, स्थिर अक्षर *,
			      स्थिर काष्ठा option *, पूर्णांक *, पूर्णांक);
अटल पूर्णांक gcd(पूर्णांक, पूर्णांक);
अटल व्योम permute_args(पूर्णांक, पूर्णांक, पूर्णांक, अक्षर * स्थिर *);

अटल अक्षर *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
अटल पूर्णांक nonopt_start = -1; /* first non option argument (for permute) */
अटल पूर्णांक nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
अटल स्थिर अक्षर recargchar[] = "option requires an argument -- %c";
अटल स्थिर अक्षर recargstring[] = "option requires an argument -- %s";
अटल स्थिर अक्षर ambig[] = "ambiguous option -- %.*s";
अटल स्थिर अक्षर noarg[] = "option doesn't take an argument -- %.*s";
अटल स्थिर अक्षर illoptchar[] = "unknown option -- %c";
अटल स्थिर अक्षर illoptstring[] = "unknown option -- %s";

/*
 * Compute the greatest common divisor of a and b.
 */
अटल पूर्णांक
gcd(पूर्णांक a, पूर्णांक b)
{
	पूर्णांक c;

	c = a % b;
	जबतक (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	वापस (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
अटल व्योम
permute_args(पूर्णांक panonopt_start, पूर्णांक panonopt_end, पूर्णांक opt_end,
	अक्षर * स्थिर *nargv)
{
	पूर्णांक cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	अक्षर *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	क्रम (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		क्रम (j = 0; j < cyclelen; j++) {
			अगर (pos >= panonopt_end)
				pos -= nnonopts;
			अन्यथा
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((अक्षर **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((अक्षर **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
अटल पूर्णांक
parse_long_options(अक्षर * स्थिर *nargv, स्थिर अक्षर *options,
	स्थिर काष्ठा option *long_options, पूर्णांक *idx, पूर्णांक short_too)
{
	अक्षर *current_argv, *has_equal;
	माप_प्रकार current_argv_len;
	पूर्णांक i, match;

	current_argv = place;
	match = -1;

	optind++;

	अगर ((has_equal = म_अक्षर(current_argv, '=')) != शून्य) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} अन्यथा
		current_argv_len = म_माप(current_argv);

	क्रम (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		अगर (म_भेदन(current_argv, long_options[i].name,
		    current_argv_len))
			जारी;

		अगर (म_माप(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			अवरोध;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		अगर (short_too && current_argv_len == 1)
			जारी;

		अगर (match == -1)	/* partial match */
			match = i;
		अन्यथा {
			/* ambiguous abbreviation */
			अगर (PRINT_ERROR)
				warnx(ambig, (पूर्णांक)current_argv_len,
				     current_argv);
			optopt = 0;
			वापस (BADCH);
		}
	}
	अगर (match != -1) {		/* option found */
		अगर (long_options[match].has_arg == no_argument
		    && has_equal) {
			अगर (PRINT_ERROR)
				warnx(noarg, (पूर्णांक)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			अगर (long_options[match].flag == शून्य)
				optopt = long_options[match].val;
			अन्यथा
				optopt = 0;
			वापस (BADARG);
		}
		अगर (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			अगर (has_equal)
				optarg = has_equal;
			अन्यथा अगर (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		अगर ((long_options[match].has_arg == required_argument)
		    && (optarg == शून्य)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			अगर (PRINT_ERROR)
				warnx(recargstring,
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			अगर (long_options[match].flag == शून्य)
				optopt = long_options[match].val;
			अन्यथा
				optopt = 0;
			--optind;
			वापस (BADARG);
		}
	} अन्यथा {			/* unknown option */
		अगर (short_too) {
			--optind;
			वापस (-1);
		}
		अगर (PRINT_ERROR)
			warnx(illoptstring, current_argv);
		optopt = 0;
		वापस (BADCH);
	}
	अगर (idx)
		*idx = match;
	अगर (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		वापस (0);
	} अन्यथा
		वापस (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
अटल पूर्णांक
getopt_internal(पूर्णांक nargc, अक्षर * स्थिर *nargv, स्थिर अक्षर *options,
	स्थिर काष्ठा option *long_options, पूर्णांक *idx, पूर्णांक flags)
{
	अक्षर *oli;				/* option letter list index */
	पूर्णांक optchar, short_too;
	अटल पूर्णांक posixly_correct = -1;

	अगर (options == शून्य)
		वापस (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	अगर (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	अगर (posixly_correct == -1 || optreset)
		posixly_correct = (दो_पर्या("POSIXLY_CORRECT") != शून्य);
	अगर (*options == '-')
		flags |= FLAG_ALLARGS;
	अन्यथा अगर (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	अगर (*options == '+' || *options == '-')
		options++;

	optarg = शून्य;
	अगर (optreset)
		nonopt_start = nonopt_end = -1;
start:
	अगर (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		अगर (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			अगर (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			अन्यथा अगर (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			वापस (-1);
		}
		अगर (*(place = nargv[optind]) != '-' ||
		    (place[1] == '\0' && म_अक्षर(options, '-') == शून्य)) {
			place = EMSG;		/* found non-option */
			अगर (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				वापस (मध्यक्रम);
			}
			अगर (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				वापस (-1);
			}
			/* do permutation */
			अगर (nonopt_start == -1)
				nonopt_start = optind;
			अन्यथा अगर (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			जाओ start;
		}
		अगर (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		अगर (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			अगर (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			वापस (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	अगर (long_options != शून्य && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
		अगर (*place == '-')
			place++;		/* --foo long option */
		अन्यथा अगर (*place != ':' && म_अक्षर(options, *place) != शून्य)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too);
		अगर (optchar != -1) {
			place = EMSG;
			वापस (optchar);
		}
	}

	अगर ((optchar = (पूर्णांक)*place++) == (पूर्णांक)':' ||
	    (optchar == (पूर्णांक)'-' && *place != '\0') ||
	    (oli = म_अक्षर(options, optchar)) == शून्य) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		अगर (optchar == (पूर्णांक)'-' && *place == '\0')
			वापस (-1);
		अगर (!*place)
			++optind;
		अगर (PRINT_ERROR)
			warnx(illoptchar, optchar);
		optopt = optchar;
		वापस (BADCH);
	}
	अगर (long_options != शून्य && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		अगर (*place)			/* no space */
			/* NOTHING */;
		अन्यथा अगर (++optind >= nargc) {	/* no arg */
			place = EMSG;
			अगर (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			वापस (BADARG);
		} अन्यथा				/* white space */
			place = nargv[optind];
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0);
		place = EMSG;
		वापस (optchar);
	}
	अगर (*++oli != ':') {			/* doesn't take argument */
		अगर (!*place)
			++optind;
	} अन्यथा {				/* takes (optional) argument */
		optarg = शून्य;
		अगर (*place)			/* no white space */
			optarg = place;
		अन्यथा अगर (oli[1] != ':') {	/* arg not optional */
			अगर (++optind >= nargc) {	/* no arg */
				place = EMSG;
				अगर (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				वापस (BADARG);
			} अन्यथा
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	वापस (optchar);
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
पूर्णांक
getopt(पूर्णांक nargc, अक्षर * स्थिर *nargv, स्थिर अक्षर *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	वापस (getopt_internal(nargc, nargv, options, शून्य, शून्य, 0));
}

#अगर 0
/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
पूर्णांक
getopt_long(पूर्णांक nargc, अक्षर * स्थिर *nargv, स्थिर अक्षर *options,
    स्थिर काष्ठा option *long_options, पूर्णांक *idx)
{

	वापस (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
पूर्णांक
getopt_long_only(पूर्णांक nargc, अक्षर * स्थिर *nargv, स्थिर अक्षर *options,
    स्थिर काष्ठा option *long_options, पूर्णांक *idx)
{

	वापस (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
#पूर्ण_अगर

#पूर्ण_अगर /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
