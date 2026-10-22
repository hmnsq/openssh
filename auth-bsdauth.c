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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#ifdef BSD_AUTH
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "log.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"

સ્થિર શૂન્ય *
bsdauth_init_ctx(Authctxt *authctxt)
{
	પાછા authctxt;
}

પૂર્ણાંક
bsdauth_query(શૂન્ય *ctx, અક્ષર **name, અક્ષર **infotxt,
   u_int *numprompts, અક્ષર ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	અક્ષર *challenge = ખાલી;

	*infotxt = ખાલી;
	*numprompts = 0;
	*prompts = ખાલી;
	*echo_on = ખાલી;

	જો (authctxt->as != ખાલી) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		જો (challenge == ખાલી) {
			auth_close(authctxt->as);
			authctxt->as = ખાલી;
		}
	}

	જો (challenge == ખાલી) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		જો (authctxt->as == ખાલી)
			challenge = ખાલી;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	જો (challenge == ખાલી)
		પાછા -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, કદ(અક્ષર *));
	*echo_on = xcalloc(*numprompts, કદ(u_int));
	(*prompts)[0] = xstrdup(challenge);

	પાછા 0;
}

પૂર્ણાંક
bsdauth_respond(શૂન્ય *ctx, u_int numresponses, અક્ષર **responses)
{
	Authctxt *authctxt = ctx;
	પૂર્ણાંક authok;

	જો (!authctxt->valid)
		પાછા -1;

	જો (authctxt->as == ખાલી)
		error("bsdauth_respond: no bsd auth session");

	જો (numresponses != 1)
		પાછા -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ખાલી;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	પાછા (authok == 0) ? -1 : 0;
}

સ્થિર શૂન્ય
bsdauth_free_ctx(શૂન્ય *ctx)
{
	Authctxt *authctxt = ctx;

	જો (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ખાલી;
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
