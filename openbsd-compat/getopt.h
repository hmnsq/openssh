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
# اگر defined __cplusplus
#  define __THROW throw()
# وگرنه
#  define __THROW
# endif
#endif

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

#اگر 0
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

صحیح	 getopt_long(صحیح, نویسه * ثابت *, ثابت نویسه *,
	    ثابت ساختار option *, صحیح *);
صحیح	 getopt_long_only(صحیح, نویسه * ثابت *, ثابت نویسه *,
	    ثابت ساختار option *, صحیح *);
#endif

#ifndef _GETOPT_DEFINED_
#define _GETOPT_DEFINED_
صحیح	 getopt(صحیح, نویسه * ثابت *, ثابت نویسه *) __THROW;
صحیح	 getsubopt(نویسه **, نویسه * ثابت *, نویسه **) __THROW;

بیرونی   نویسه *optarg;                  /* getopt(3) external variables */
بیرونی   صحیح opterr;
بیرونی   صحیح optind;
بیرونی   صحیح optopt;
بیرونی   صحیح optreset;
بیرونی   نویسه *suboptarg;               /* getsubopt(3) external variable */
#endif
 
#endif /* !_GETOPT_H_ */
