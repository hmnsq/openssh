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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>

#اگر_تعریف_شده BSD_AUTH
#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "log.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"

ساكن فراغ *
bsdauth_init_ctx(Authctxt *authctxt)
{
	أرجع authctxt;
}

صحيح
bsdauth_query(فراغ *ctx, حرف **name, حرف **infotxt,
   u_int *numprompts, حرف ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	حرف *challenge = عدم;

	*infotxt = عدم;
	*numprompts = 0;
	*prompts = عدم;
	*echo_on = عدم;

	إذا (authctxt->as != عدم) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		إذا (challenge == عدم) {
			auth_close(authctxt->as);
			authctxt->as = عدم;
		}
	}

	إذا (challenge == عدم) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		إذا (authctxt->as == عدم)
			challenge = عدم;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	إذا (challenge == عدم)
		أرجع -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, حجم(حرف *));
	*echo_on = xcalloc(*numprompts, حجم(u_int));
	(*prompts)[0] = xstrdup(challenge);

	أرجع 0;
}

صحيح
bsdauth_respond(فراغ *ctx, u_int numresponses, حرف **responses)
{
	Authctxt *authctxt = ctx;
	صحيح authok;

	إذا (!authctxt->valid)
		أرجع -1;

	إذا (authctxt->as == عدم)
		error("bsdauth_respond: no bsd auth session");

	إذا (numresponses != 1)
		أرجع -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = عدم;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	أرجع (authok == 0) ? -1 : 0;
}

ساكن فراغ
bsdauth_free_ctx(فراغ *ctx)
{
	Authctxt *authctxt = ctx;

	إذا (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = عدم;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#پایان_اگر
