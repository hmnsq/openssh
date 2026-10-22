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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _GETOPT_H_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _GETOPT_H_

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ __THROW
# ਜੇ defined __cplusplus
#  define __THROW throw()
# ਨਹੀਂਤਾਂ
#  define __THROW
# endif
#ਜੇ_ਅੰਤ

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ no_argument        0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ required_argument  1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ optional_argument  2

#ਜੇ 0
ਬਣਤਰ option {
	/* name of long option */
	ਅਚਲ ਅੱਖਰ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ਪੂਰਨ has_arg;
	/* if not NULL, set *flag to val when option found */
	ਪੂਰਨ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ਪੂਰਨ val;
};

ਪੂਰਨ	 getopt_long(ਪੂਰਨ, ਅੱਖਰ * ਅਚਲ *, ਅਚਲ ਅੱਖਰ *,
	    ਅਚਲ ਬਣਤਰ option *, ਪੂਰਨ *);
ਪੂਰਨ	 getopt_long_only(ਪੂਰਨ, ਅੱਖਰ * ਅਚਲ *, ਅਚਲ ਅੱਖਰ *,
	    ਅਚਲ ਬਣਤਰ option *, ਪੂਰਨ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _GETOPT_DEFINED_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _GETOPT_DEFINED_
ਪੂਰਨ	 getopt(ਪੂਰਨ, ਅੱਖਰ * ਅਚਲ *, ਅਚਲ ਅੱਖਰ *) __THROW;
ਪੂਰਨ	 getsubopt(ਅੱਖਰ **, ਅੱਖਰ * ਅਚਲ *, ਅੱਖਰ **) __THROW;

ਬਾਹਰੀ   ਅੱਖਰ *optarg;                  /* getopt(3) external variables */
ਬਾਹਰੀ   ਪੂਰਨ opterr;
ਬਾਹਰੀ   ਪੂਰਨ optind;
ਬਾਹਰੀ   ਪੂਰਨ optopt;
ਬਾਹਰੀ   ਪੂਰਨ optreset;
ਬਾਹਰੀ   ਅੱਖਰ *suboptarg;               /* getsubopt(3) external variable */
#ਜੇ_ਅੰਤ
 
#ਜੇ_ਅੰਤ /* !_GETOPT_H_ */
