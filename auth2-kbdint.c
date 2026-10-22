/* $OpenBSD: auth2-kbdint.c,v 1.15 2024/05/17 00:30:23 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "ssherr.h"

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന authmethod_cfg methodcfg_kbdint;

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_kbdint(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *method)
{
	പൂർണ്ണസംഖ്യ r, authenticated = 0;
	അക്ഷരം *lang, *devs;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &lang, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &devs, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug("keyboard-interactive devs %s", devs);

	എങ്കിൽ (options.kbd_interactive_authentication)
		authenticated = auth2_challenge(ssh, devs);

	സ്വതന്ത്രം(devs);
	സ്വതന്ത്രം(lang);
	തിരികെ authenticated;
}

Authmethod method_kbdint = {
	&methodcfg_kbdint,
	userauth_kbdint,
};
