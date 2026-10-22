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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ifdef BSD_AUTH
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"

ಸ್ಥಿರ ಶೂನ್ಯ *
bsdauth_init_ctx(Authctxt *authctxt)
{
	ಪ್ರತ್ಯಾಗಮ authctxt;
}

ಪೂರ್ಣಾಙ್ಕ
bsdauth_query(ಶೂನ್ಯ *ctx, ವರ್ಣ **name, ವರ್ಣ **infotxt,
   u_int *numprompts, ವರ್ಣ ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	ವರ್ಣ *challenge = ರಿಕ್ತ;

	*infotxt = ರಿಕ್ತ;
	*numprompts = 0;
	*prompts = ರಿಕ್ತ;
	*echo_on = ರಿಕ್ತ;

	ಯದಿ (authctxt->as != ರಿಕ್ತ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		ಯದಿ (challenge == ರಿಕ್ತ) {
			auth_close(authctxt->as);
			authctxt->as = ರಿಕ್ತ;
		}
	}

	ಯದಿ (challenge == ರಿಕ್ತ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		ಯದಿ (authctxt->as == ರಿಕ್ತ)
			challenge = ರಿಕ್ತ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	ಯದಿ (challenge == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ಪರಿಮಾಣ(ವರ್ಣ *));
	*echo_on = xcalloc(*numprompts, ಪರಿಮಾಣ(u_int));
	(*prompts)[0] = xstrdup(challenge);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
bsdauth_respond(ಶೂನ್ಯ *ctx, u_int numresponses, ವರ್ಣ **responses)
{
	Authctxt *authctxt = ctx;
	ಪೂರ್ಣಾಙ್ಕ authok;

	ಯದಿ (!authctxt->valid)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (authctxt->as == ರಿಕ್ತ)
		error("bsdauth_respond: no bsd auth session");

	ಯದಿ (numresponses != 1)
		ಪ್ರತ್ಯಾಗಮ -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ರಿಕ್ತ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	ಪ್ರತ್ಯಾಗಮ (authok == 0) ? -1 : 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsdauth_free_ctx(ಶೂನ್ಯ *ctx)
{
	Authctxt *authctxt = ctx;

	ಯದಿ (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ರಿಕ್ತ;
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
