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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "ssherr.h"

/* import */
வெளி ServerOptions options;
வெளி கட்டமைப்பு authmethod_cfg methodcfg_kbdint;

நிலையான முழு
userauth_kbdint(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *method)
{
	முழு r, authenticated = 0;
	எழுத்து *lang, *devs;

	எனில் ((r = sshpkt_get_cstring(ssh, &lang, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &devs, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug("keyboard-interactive devs %s", devs);

	எனில் (options.kbd_interactive_authentication)
		authenticated = auth2_challenge(ssh, devs);

	விடுவி(devs);
	விடுவி(lang);
	திரும்பு authenticated;
}

Authmethod method_kbdint = {
	&methodcfg_kbdint,
	userauth_kbdint,
};
