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

#ifndef _GETOPT_H_
#define _GETOPT_H_

#ifndef __THROW
# सचे defined __cplusplus
#  define __THROW throw()
# अञ्ञथा
#  define __THROW
# endif
#endif

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

#सचे 0
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

पूर्णाङ्क	 getopt_long(पूर्णाङ्क, वर्ण * ध्रुव *, ध्रुव वर्ण *,
	    ध्रुव संरचना option *, पूर्णाङ्क *);
पूर्णाङ्क	 getopt_long_only(पूर्णाङ्क, वर्ण * ध्रुव *, ध्रुव वर्ण *,
	    ध्रुव संरचना option *, पूर्णाङ्क *);
#endif

#ifndef _GETOPT_DEFINED_
#define _GETOPT_DEFINED_
पूर्णाङ्क	 getopt(पूर्णाङ्क, वर्ण * ध्रुव *, ध्रुव वर्ण *) __THROW;
पूर्णाङ्क	 getsubopt(वर्ण **, वर्ण * ध्रुव *, वर्ण **) __THROW;

बाह्य   वर्ण *optarg;                  /* getopt(3) external variables */
बाह्य   पूर्णाङ्क opterr;
बाह्य   पूर्णाङ्क optind;
बाह्य   पूर्णाङ्क optopt;
बाह्य   पूर्णाङ्क optreset;
बाह्य   वर्ण *suboptarg;               /* getsubopt(3) external variable */
#endif
 
#endif /* !_GETOPT_H_ */
