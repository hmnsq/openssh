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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ifdef BSD_AUTH
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"

ସ୍ଥିର ଶୂନ୍ୟ *
bsdauth_init_ctx(Authctxt *authctxt)
{
	ଫେରନ୍ତୁ authctxt;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
bsdauth_query(ଶୂନ୍ୟ *ctx, ଅକ୍ଷର **name, ଅକ୍ଷର **infotxt,
   u_int *numprompts, ଅକ୍ଷର ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	ଅକ୍ଷର *challenge = ଖାଲି;

	*infotxt = ଖାଲି;
	*numprompts = 0;
	*prompts = ଖାଲି;
	*echo_on = ଖାଲି;

	ଯଦି (authctxt->as != ଖାଲି) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		ଯଦି (challenge == ଖାଲି) {
			auth_close(authctxt->as);
			authctxt->as = ଖାଲି;
		}
	}

	ଯଦି (challenge == ଖାଲି) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		ଯଦି (authctxt->as == ଖାଲି)
			challenge = ଖାଲି;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	ଯଦି (challenge == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ଆକାର(ଅକ୍ଷର *));
	*echo_on = xcalloc(*numprompts, ଆକାର(u_int));
	(*prompts)[0] = xstrdup(challenge);

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
bsdauth_respond(ଶୂନ୍ୟ *ctx, u_int numresponses, ଅକ୍ଷର **responses)
{
	Authctxt *authctxt = ctx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା authok;

	ଯଦି (!authctxt->valid)
		ଫେରନ୍ତୁ -1;

	ଯଦି (authctxt->as == ଖାଲି)
		error("bsdauth_respond: no bsd auth session");

	ଯଦି (numresponses != 1)
		ଫେରନ୍ତୁ -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ଖାଲି;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	ଫେରନ୍ତୁ (authok == 0) ? -1 : 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
bsdauth_free_ctx(ଶୂନ୍ୟ *ctx)
{
	Authctxt *authctxt = ctx;

	ଯଦି (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ଖାଲି;
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
