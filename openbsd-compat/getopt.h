/*	$OpenBSD: getopt.h,v 1.2 2008/06/26 05:42:04 ray Exp $	*/
/*	$NetBSD: getopt.h,v 1.4 2000/07/07 10:43:54 ad Exp $	*/

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

#अगर_अघोषित _GETOPT_H_
#घोषणा _GETOPT_H_

#अगर_अघोषित __THROW
# अगर defined __cplusplus
#  define __THROW throw()
# अन्यथा
#  define __THROW
# endif
#पूर्ण_अगर

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#घोषणा no_argument        0
#घोषणा required_argument  1
#घोषणा optional_argument  2

#अगर 0
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

पूर्णांक	 getopt_long(पूर्णांक, अक्षर * स्थिर *, स्थिर अक्षर *,
	    स्थिर काष्ठा option *, पूर्णांक *);
पूर्णांक	 getopt_long_only(पूर्णांक, अक्षर * स्थिर *, स्थिर अक्षर *,
	    स्थिर काष्ठा option *, पूर्णांक *);
#पूर्ण_अगर

#अगर_अघोषित _GETOPT_DEFINED_
#घोषणा _GETOPT_DEFINED_
पूर्णांक	 getopt(पूर्णांक, अक्षर * स्थिर *, स्थिर अक्षर *) __THROW;
पूर्णांक	 getsubopt(अक्षर **, अक्षर * स्थिर *, अक्षर **) __THROW;

बाह्य   अक्षर *optarg;                  /* getopt(3) external variables */
बाह्य   पूर्णांक opterr;
बाह्य   पूर्णांक optind;
बाह्य   पूर्णांक optopt;
बाह्य   पूर्णांक optreset;
बाह्य   अक्षर *suboptarg;               /* getsubopt(3) external variable */
#पूर्ण_अगर
 
#पूर्ण_अगर /* !_GETOPT_H_ */
