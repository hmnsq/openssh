/* $OpenBSD: compat.c,v 1.129 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

/* determine bug flags from SSH protocol banner */
ਖਾਲੀ
compat_banner(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਸੰਸਕਰਣ)
{
	ਪੂਰਨ i;
	ਸਥਿਰ ਬਣਤਰ {
		ਅੱਖਰ	*pat;
		uint32_t bugs;
	} check[] = {
		{ "OpenSSH_2.*,"
		  "OpenSSH_3.0*,"
		  "OpenSSH_3.1*",	SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_3.*",	SSH_OLD_FORWARD_ADDR|SSH_BUG_SIGTYPE },
		{ "Sun_SSH_1.0*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_2*,"
		  "OpenSSH_3*,"
		  "OpenSSH_4*",		SSH_BUG_SIGTYPE },
		{ "OpenSSH_5*",		SSH_NEW_OPENSSH|SSH_BUG_DYNAMIC_RPORT|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.6.1*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.5*,"
		  "OpenSSH_6.6*",	SSH_NEW_OPENSSH|SSH_BUG_CURVE25519PAD|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_7.4*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE|
					SSH_BUG_SIGTYPE74},
		{ "OpenSSH_7.0*,"
		  "OpenSSH_7.1*,"
		  "OpenSSH_7.2*,"
		  "OpenSSH_7.3*,"
		  "OpenSSH_7.5*,"
		  "OpenSSH_7.6*,"
		  "OpenSSH_7.7*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH*",		SSH_NEW_OPENSSH },
		{ "*MindTerm*",		0 },
		{ "3.0.*",		SSH_BUG_DEBUG },
		{ "Cisco-1.*",		SSH_BUG_DHGEX_LARGE|
					SSH_BUG_HOSTKEYS },
		{ "*SSH_Version_Mapper*",
					SSH_BUG_SCANNER },
		{ "PuTTY_Local:*,"	/* dev versions < Sep 2014 */
		  "PuTTY-Release-0.5*," /* 0.50-0.57, DH-GEX in >=0.52 */
		  "PuTTY_Release_0.5*,"	/* 0.58-0.59 */
		  "PuTTY_Release_0.60*,"
		  "PuTTY_Release_0.61*,"
		  "PuTTY_Release_0.62*,"
		  "PuTTY_Release_0.63*,"
		  "PuTTY_Release_0.64*",
					SSH_OLD_DHGEX },
		{ "FuTTY*",		SSH_OLD_DHGEX }, /* Putty Fork */
		{ "Probe-*",
					SSH_BUG_PROBE },
		{ "TeraTerm SSH*,"
		  "TTSSH/1.5.*,"
		  "TTSSH/2.1*,"
		  "TTSSH/2.2*,"
		  "TTSSH/2.3*,"
		  "TTSSH/2.4*,"
		  "TTSSH/2.5*,"
		  "TTSSH/2.6*,"
		  "TTSSH/2.70*,"
		  "TTSSH/2.71*,"
		  "TTSSH/2.72*",	SSH_BUG_HOSTKEYS },
		{ "WinSCP_release_4*,"
		  "WinSCP_release_5.0*,"
		  "WinSCP_release_5.1,"
		  "WinSCP_release_5.1.*,"
		  "WinSCP_release_5.5,"
		  "WinSCP_release_5.5.*,"
		  "WinSCP_release_5.6,"
		  "WinSCP_release_5.6.*,"
		  "WinSCP_release_5.7,"
		  "WinSCP_release_5.7.1,"
		  "WinSCP_release_5.7.2,"
		  "WinSCP_release_5.7.3,"
		  "WinSCP_release_5.7.4",
					SSH_OLD_DHGEX },
		{ "ConfD-*",
					SSH_BUG_UTF8TTYMODE },
		{ "Twisted_*",		0 },
		{ "Twisted*",		SSH_BUG_DEBUG },
		{ ਨਿਰਾ,			0 }
	};

	/* process table, return first match */
	ssh->compat = 0;
	ਲਈ (i = 0; check[i].pat; i++) {
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(ਸੰਸਕਰਣ, check[i].pat, 0) == 1) {
			debug_f("match: %s pat %s compat 0x%08x",
			    ਸੰਸਕਰਣ, check[i].pat, check[i].bugs);
			ssh->compat = check[i].bugs;
			ਵਾਪਸ;
		}
	}
	debug_f("no match: %s", ਸੰਸਕਰਣ);
}

/* Always returns pointer to allocated memory, caller must free. */
ਅੱਖਰ *
compat_kex_proposal(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *p)
{
	ਅੱਖਰ *cp = ਨਿਰਾ, *cp2 = ਨਿਰਾ;

	ਜੇ ((ssh->compat & (SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX)) == 0)
		ਵਾਪਸ xstrdup(p);
	debug2_f("original KEX proposal: %s", p);
	ਜੇ ((ssh->compat & SSH_BUG_CURVE25519PAD) != 0)
		ਜੇ ((cp = ਮੇਲ_filter_denylist(p,
		    "curve25519-sha256@libssh.org")) == ਨਿਰਾ)
			fatal("match_filter_denylist failed");
	ਜੇ ((ssh->compat & SSH_OLD_DHGEX) != 0) {
		ਜੇ ((cp2 = ਮੇਲ_filter_denylist(cp ? cp : p,
		    "diffie-hellman-group-exchange-sha256,"
		    "diffie-hellman-group-exchange-sha1")) == ਨਿਰਾ)
			fatal("match_filter_denylist failed");
		ਮੁਕਤ(cp);
		cp = cp2;
	}
	ਜੇ (cp == ਨਿਰਾ || *cp == '\0')
		fatal("No supported key exchange algorithms found");
	debug2_f("compat KEX proposal: %s", cp);
	ਵਾਪਸ cp;
}

