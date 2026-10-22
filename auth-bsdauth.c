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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>

#ifdef BSD_AUTH
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "log.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"

സ്ഥിതം ശൂന്യം *
bsdauth_init_ctx(Authctxt *authctxt)
{
	തിരികെ authctxt;
}

പൂർണ്ണസംഖ്യ
bsdauth_query(ശൂന്യം *ctx, അക്ഷരം **name, അക്ഷരം **infotxt,
   u_int *numprompts, അക്ഷരം ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	അക്ഷരം *challenge = ശൂന്യ;

	*infotxt = ശൂന്യ;
	*numprompts = 0;
	*prompts = ശൂന്യ;
	*echo_on = ശൂന്യ;

	എങ്കിൽ (authctxt->as != ശൂന്യ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		എങ്കിൽ (challenge == ശൂന്യ) {
			auth_close(authctxt->as);
			authctxt->as = ശൂന്യ;
		}
	}

	എങ്കിൽ (challenge == ശൂന്യ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		എങ്കിൽ (authctxt->as == ശൂന്യ)
			challenge = ശൂന്യ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	എങ്കിൽ (challenge == ശൂന്യ)
		തിരികെ -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, വലുപ്പം(അക്ഷരം *));
	*echo_on = xcalloc(*numprompts, വലുപ്പം(u_int));
	(*prompts)[0] = xstrdup(challenge);

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
bsdauth_respond(ശൂന്യം *ctx, u_int numresponses, അക്ഷരം **responses)
{
	Authctxt *authctxt = ctx;
	പൂർണ്ണസംഖ്യ authok;

	എങ്കിൽ (!authctxt->valid)
		തിരികെ -1;

	എങ്കിൽ (authctxt->as == ശൂന്യ)
		error("bsdauth_respond: no bsd auth session");

	എങ്കിൽ (numresponses != 1)
		തിരികെ -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ശൂന്യ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	തിരികെ (authok == 0) ? -1 : 0;
}

സ്ഥിതം ശൂന്യം
bsdauth_free_ctx(ശൂന്യം *ctx)
{
	Authctxt *authctxt = ctx;

	എങ്കിൽ (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ശൂന്യ;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#endif
