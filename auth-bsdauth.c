/* $OpenBSD: auth-bsdauth.c,v 1.16 2026/02/06 01:24:36 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"

ਸਥਿਰ ਖਾਲੀ *
bsdauth_init_ctx(Authctxt *authctxt)
{
	ਵਾਪਸ authctxt;
}

ਪੂਰਨ
bsdauth_query(ਖਾਲੀ *ctx, ਅੱਖਰ **name, ਅੱਖਰ **infotxt,
   u_int *numprompts, ਅੱਖਰ ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	ਅੱਖਰ *challenge = ਨਿਰਾ;

	*infotxt = ਨਿਰਾ;
	*numprompts = 0;
	*prompts = ਨਿਰਾ;
	*echo_on = ਨਿਰਾ;

	ਜੇ (authctxt->as != ਨਿਰਾ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		ਜੇ (challenge == ਨਿਰਾ) {
			auth_close(authctxt->as);
			authctxt->as = ਨਿਰਾ;
		}
	}

	ਜੇ (challenge == ਨਿਰਾ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		ਜੇ (authctxt->as == ਨਿਰਾ)
			challenge = ਨਿਰਾ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	ਜੇ (challenge == ਨਿਰਾ)
		ਵਾਪਸ -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ਆਕਾਰ(ਅੱਖਰ *));
	*echo_on = xcalloc(*numprompts, ਆਕਾਰ(u_int));
	(*prompts)[0] = xstrdup(challenge);

	ਵਾਪਸ 0;
}

ਪੂਰਨ
bsdauth_respond(ਖਾਲੀ *ctx, u_int numresponses, ਅੱਖਰ **responses)
{
	Authctxt *authctxt = ctx;
	ਪੂਰਨ authok;

	ਜੇ (!authctxt->valid)
		ਵਾਪਸ -1;

	ਜੇ (authctxt->as == ਨਿਰਾ)
		error("bsdauth_respond: no bsd auth session");

	ਜੇ (numresponses != 1)
		ਵਾਪਸ -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ਨਿਰਾ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	ਵਾਪਸ (authok == 0) ? -1 : 0;
}

ਸਥਿਰ ਖਾਲੀ
bsdauth_free_ctx(ਖਾਲੀ *ctx)
{
	Authctxt *authctxt = ctx;

	ਜੇ (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ਨਿਰਾ;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#ਜੇ_ਅੰਤ
