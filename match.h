/* $OpenBSD: match.h,v 1.20 2020/07/05 23:59:45 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#ifndef MATCH_H
#define MATCH_H

പൂർണ്ണസംഖ്യ	 match_pattern(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 match_pattern_list(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 match_usergroup_pattern_list(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 match_hostname(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 match_host_and_ip(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 match_user(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
അക്ഷരം	*match_list(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, u_int *);
അക്ഷരം	*match_filter_denylist(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
അക്ഷരം	*match_filter_allowlist(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* addrmatch.c */
പൂർണ്ണസംഖ്യ	 addr_match_list(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 addr_match_cidr_list(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
#endif
