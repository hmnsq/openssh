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

#اگر_غیر_تعریف_شدہ _GETOPT_H_
#تعریف_کرو _GETOPT_H_

#اگر_غیر_تعریف_شدہ __THROW
# اگر defined __cplusplus
#  define __THROW throw()
# ورنہ
#  define __THROW
# endif
#اگر_ختم

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#تعریف_کرو no_argument        0
#تعریف_کرو required_argument  1
#تعریف_کرو optional_argument  2

#اگر 0
ساخت option {
	/* name of long option */
	ثابت حرف *name;
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

صحیح	 getopt_long(صحیح, حرف * ثابت *, ثابت حرف *,
	    ثابت ساخت option *, صحیح *);
صحیح	 getopt_long_only(صحیح, حرف * ثابت *, ثابت حرف *,
	    ثابت ساخت option *, صحیح *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ _GETOPT_DEFINED_
#تعریف_کرو _GETOPT_DEFINED_
صحیح	 getopt(صحیح, حرف * ثابت *, ثابت حرف *) __THROW;
صحیح	 getsubopt(حرف **, حرف * ثابت *, حرف **) __THROW;

خارجی   حرف *optarg;                  /* getopt(3) external variables */
خارجی   صحیح opterr;
خارجی   صحیح optind;
خارجی   صحیح optopt;
خارجی   صحیح optreset;
خارجی   حرف *suboptarg;               /* getsubopt(3) external variable */
#اگر_ختم
 
#اگر_ختم /* !_GETOPT_H_ */
