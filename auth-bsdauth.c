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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>

#ifdef BSD_AUTH
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "log.h"
#ifdef GSSAPI
#অন্তর্ভাৱ "ssh-gss.h"
#endif
#অন্তর্ভাৱ "monitor_wrap.h"

স্থির শূন্য *
bsdauth_init_ctx(Authctxt *authctxt)
{
	ঘূৰাই authctxt;
}

পূর্ণাঙ্ক
bsdauth_query(শূন্য *ctx, ৱর্ণ **name, ৱর্ণ **infotxt,
   u_int *numprompts, ৱর্ণ ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	ৱর্ণ *challenge = রিক্ত;

	*infotxt = রিক্ত;
	*numprompts = 0;
	*prompts = রিক্ত;
	*echo_on = রিক্ত;

	যদি (authctxt->as != রিক্ত) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		যদি (challenge == রিক্ত) {
			auth_close(authctxt->as);
			authctxt->as = রিক্ত;
		}
	}

	যদি (challenge == রিক্ত) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		যদি (authctxt->as == রিক্ত)
			challenge = রিক্ত;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	যদি (challenge == রিক্ত)
		ঘূৰাই -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, পরিমাণ(ৱর্ণ *));
	*echo_on = xcalloc(*numprompts, পরিমাণ(u_int));
	(*prompts)[0] = xstrdup(challenge);

	ঘূৰাই 0;
}

পূর্ণাঙ্ক
bsdauth_respond(শূন্য *ctx, u_int numresponses, ৱর্ণ **responses)
{
	Authctxt *authctxt = ctx;
	পূর্ণাঙ্ক authok;

	যদি (!authctxt->valid)
		ঘূৰাই -1;

	যদি (authctxt->as == রিক্ত)
		error("bsdauth_respond: no bsd auth session");

	যদি (numresponses != 1)
		ঘূৰাই -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = রিক্ত;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	ঘূৰাই (authok == 0) ? -1 : 0;
}

স্থির শূন্য
bsdauth_free_ctx(শূন্য *ctx)
{
	Authctxt *authctxt = ctx;

	যদি (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = রিক্ত;
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
