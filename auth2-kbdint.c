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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "ssherr.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం authmethod_cfg methodcfg_kbdint;

స్థిర పూర్ణాంకం
userauth_kbdint(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	పూర్ణాంకం r, authenticated = 0;
	అక్షరం *lang, *devs;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &lang, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &devs, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug("keyboard-interactive devs %s", devs);

	ఒకవేళ (options.kbd_interactive_authentication)
		authenticated = auth2_challenge(ssh, devs);

	విడుదల(devs);
	విడుదల(lang);
	తిరిగి authenticated;
}

Authmethod పద్ధతి_kbdint = {
	&methodcfg_kbdint,
	userauth_kbdint,
};
