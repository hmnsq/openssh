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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#ifdef BSD_AUTH
#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "log.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"

ایستا تهی *
bsdauth_init_ctx(Authctxt *authctxt)
{
	بازگشت authctxt;
}

صحیح
bsdauth_query(تهی *ctx, نویسه **name, نویسه **infotxt,
   u_int *numprompts, نویسه ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	نویسه *challenge = پوچ;

	*infotxt = پوچ;
	*numprompts = 0;
	*prompts = پوچ;
	*echo_on = پوچ;

	اگر (authctxt->as != پوچ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		اگر (challenge == پوچ) {
			auth_close(authctxt->as);
			authctxt->as = پوچ;
		}
	}

	اگر (challenge == پوچ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		اگر (authctxt->as == پوچ)
			challenge = پوچ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	اگر (challenge == پوچ)
		بازگشت -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, اندازه(نویسه *));
	*echo_on = xcalloc(*numprompts, اندازه(u_int));
	(*prompts)[0] = xstrdup(challenge);

	بازگشت 0;
}

صحیح
bsdauth_respond(تهی *ctx, u_int numresponses, نویسه **responses)
{
	Authctxt *authctxt = ctx;
	صحیح authok;

	اگر (!authctxt->valid)
		بازگشت -1;

	اگر (authctxt->as == پوچ)
		error("bsdauth_respond: no bsd auth session");

	اگر (numresponses != 1)
		بازگشت -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = پوچ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	بازگشت (authok == 0) ? -1 : 0;
}

ایستا تهی
bsdauth_free_ctx(تهی *ctx)
{
	Authctxt *authctxt = ctx;

	اگر (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = پوچ;
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
