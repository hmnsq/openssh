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

#اگر_تعریف_نشده _GETOPT_H_
#تعریف_کن _GETOPT_H_

#اگر_تعریف_نشده __THROW
# إذا defined __cplusplus
#  define __THROW throw()
# وإلا
#  define __THROW
# endif
#پایان_اگر

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#تعریف_کن no_argument        0
#تعریف_کن required_argument  1
#تعریف_کن optional_argument  2

#إذا 0
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

صحيح	 getopt_long(صحيح, حرف * ثابت *, ثابت حرف *,
	    ثابت بنية option *, صحيح *);
صحيح	 getopt_long_only(صحيح, حرف * ثابت *, ثابت حرف *,
	    ثابت بنية option *, صحيح *);
#پایان_اگر

#اگر_تعریف_نشده _GETOPT_DEFINED_
#تعریف_کن _GETOPT_DEFINED_
صحيح	 getopt(صحيح, حرف * ثابت *, ثابت حرف *) __THROW;
صحيح	 getsubopt(حرف **, حرف * ثابت *, حرف **) __THROW;

خارجي   حرف *optarg;                  /* getopt(3) external variables */
خارجي   صحيح opterr;
خارجي   صحيح optind;
خارجي   صحيح optopt;
خارجي   صحيح optreset;
خارجي   حرف *suboptarg;               /* getsubopt(3) external variable */
#پایان_اگر
 
#پایان_اگر /* !_GETOPT_H_ */
