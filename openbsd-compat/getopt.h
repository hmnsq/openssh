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
# എങ്കിൽ defined __cplusplus
#  define __THROW throw()
# അല്ലെങ്കിൽ
#  define __THROW
# endif
#endif

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

#എങ്കിൽ 0
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

പൂർണ്ണസംഖ്യ	 getopt_long(പൂർണ്ണസംഖ്യ, അക്ഷരം * സ്ഥിരം *, സ്ഥിരം അക്ഷരം *,
	    സ്ഥിരം ഘടന option *, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 getopt_long_only(പൂർണ്ണസംഖ്യ, അക്ഷരം * സ്ഥിരം *, സ്ഥിരം അക്ഷരം *,
	    സ്ഥിരം ഘടന option *, പൂർണ്ണസംഖ്യ *);
#endif

#ifndef _GETOPT_DEFINED_
#define _GETOPT_DEFINED_
പൂർണ്ണസംഖ്യ	 getopt(പൂർണ്ണസംഖ്യ, അക്ഷരം * സ്ഥിരം *, സ്ഥിരം അക്ഷരം *) __THROW;
പൂർണ്ണസംഖ്യ	 getsubopt(അക്ഷരം **, അക്ഷരം * സ്ഥിരം *, അക്ഷരം **) __THROW;

ബാഹ്യ   അക്ഷരം *optarg;                  /* getopt(3) external variables */
ബാഹ്യ   പൂർണ്ണസംഖ്യ opterr;
ബാഹ്യ   പൂർണ്ണസംഖ്യ optind;
ബാഹ്യ   പൂർണ്ണസംഖ്യ optopt;
ബാഹ്യ   പൂർണ്ണസംഖ്യ optreset;
ബാഹ്യ   അക്ഷരം *suboptarg;               /* getsubopt(3) external variable */
#endif
 
#endif /* !_GETOPT_H_ */
