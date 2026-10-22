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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _GETOPT_H_
#ವ್ಯಾಖ್ಯಾನಿಸು _GETOPT_H_

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __THROW
# ಆದರೆ defined __cplusplus
#  define __THROW throw()
# ಇಲ್ಲದಿದ್ದರೆ
#  define __THROW
# endif
#ಆದರೆ_ಅಂತ್ಯ

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#ವ್ಯಾಖ್ಯಾನಿಸು no_argument        0
#ವ್ಯಾಖ್ಯಾನಿಸು required_argument  1
#ವ್ಯಾಖ್ಯಾನಿಸು optional_argument  2

#ಆದರೆ 0
ರಚನೆ option {
	/* name of long option */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	/*
	 * one of no_argument, required_argument, and optional_argument:
	 * whether option takes an argument
	 */
	ಪೂರ್ಣಾಂಕ has_arg;
	/* if not NULL, set *flag to val when option found */
	ಪೂರ್ಣಾಂಕ *flag;
	/* if flag not NULL, value to set *flag to; else return value */
	ಪೂರ್ಣಾಂಕ val;
};

ಪೂರ್ಣಾಂಕ	 getopt_long(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ಸ್ಥಿರಾಂಕ ರಚನೆ option *, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 getopt_long_only(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ಸ್ಥಿರಾಂಕ ರಚನೆ option *, ಪೂರ್ಣಾಂಕ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _GETOPT_DEFINED_
#ವ್ಯಾಖ್ಯಾನಿಸು _GETOPT_DEFINED_
ಪೂರ್ಣಾಂಕ	 getopt(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *) __THROW;
ಪೂರ್ಣಾಂಕ	 getsubopt(ಅಕ್ಷರ **, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *, ಅಕ್ಷರ **) __THROW;

ಬಾಹ್ಯ   ಅಕ್ಷರ *optarg;                  /* getopt(3) external variables */
ಬಾಹ್ಯ   ಪೂರ್ಣಾಂಕ opterr;
ಬಾಹ್ಯ   ಪೂರ್ಣಾಂಕ optind;
ಬಾಹ್ಯ   ಪೂರ್ಣಾಂಕ optopt;
ಬಾಹ್ಯ   ಪೂರ್ಣಾಂಕ optreset;
ಬಾಹ್ಯ   ಅಕ್ಷರ *suboptarg;               /* getsubopt(3) external variable */
#ಆದರೆ_ಅಂತ್ಯ
 
#ಆದರೆ_ಅಂತ್ಯ /* !_GETOPT_H_ */
