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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"

ಸ್ಥಿರ ಶೂನ್ಯ *
bsdauth_init_ctx(Authctxt *authctxt)
{
	ಹಿಂತಿರುಗಿ authctxt;
}

ಪೂರ್ಣಾಂಕ
bsdauth_query(ಶೂನ್ಯ *ctx, ಅಕ್ಷರ **name, ಅಕ್ಷರ **infotxt,
   u_int *numprompts, ಅಕ್ಷರ ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	ಅಕ್ಷರ *challenge = ಖಾಲಿ;

	*infotxt = ಖಾಲಿ;
	*numprompts = 0;
	*prompts = ಖಾಲಿ;
	*echo_on = ಖಾಲಿ;

	ಆದರೆ (authctxt->as != ಖಾಲಿ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		ಆದರೆ (challenge == ಖಾಲಿ) {
			auth_close(authctxt->as);
			authctxt->as = ಖಾಲಿ;
		}
	}

	ಆದರೆ (challenge == ಖಾಲಿ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		ಆದರೆ (authctxt->as == ಖಾಲಿ)
			challenge = ಖಾಲಿ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	ಆದರೆ (challenge == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, ಗಾತ್ರ(ಅಕ್ಷರ *));
	*echo_on = xcalloc(*numprompts, ಗಾತ್ರ(u_int));
	(*prompts)[0] = xstrdup(challenge);

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
bsdauth_respond(ಶೂನ್ಯ *ctx, u_int numresponses, ಅಕ್ಷರ **responses)
{
	Authctxt *authctxt = ctx;
	ಪೂರ್ಣಾಂಕ authok;

	ಆದರೆ (!authctxt->valid)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (authctxt->as == ಖಾಲಿ)
		error("bsdauth_respond: no bsd auth session");

	ಆದರೆ (numresponses != 1)
		ಹಿಂತಿರುಗಿ -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ಖಾಲಿ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	ಹಿಂತಿರುಗಿ (authok == 0) ? -1 : 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsdauth_free_ctx(ಶೂನ್ಯ *ctx)
{
	Authctxt *authctxt = ctx;

	ಆದರೆ (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ಖಾಲಿ;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#ಆದರೆ_ಅಂತ್ಯ
