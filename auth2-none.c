/* $OpenBSD: auth2-none.c,v 1.26 2024/05/17 00:30:23 djm Exp $ */
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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "ssherr.h"
#ifdef GSSAPI
#অন্তর্ভাৱ "ssh-gss.h"
#endif
#অন্তর্ভাৱ "monitor_wrap.h"

/* import */
বাহ্য ServerOptions options;
বাহ্য সংরচনা authmethod_cfg methodcfg_none;

বাহ্য পূর্ণাঙ্ক none_enabled;

স্থির পূর্ণাঙ্ক
userauth_none(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *method)
{
	পূর্ণাঙ্ক r;

	none_enabled = 0;
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	যদি (options.permit_empty_passwd && options.password_authentication)
		ঘূৰাই mm_auth_password(ssh, "");
	ঘূৰাই (0);
}

Authmethod method_none = {
	&methodcfg_none,
	userauth_none,
};
