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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#నిర్వచితమైతే BSD_AUTH
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "log.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"

స్థిర శూన్య *
bsdauth_init_ctx(Authctxt *authctxt)
{
	తిరిగి authctxt;
}

పూర్ణాంకం
bsdauth_query(శూన్య *ctx, అక్షరం **name, అక్షరం **infotxt,
   u_int *numprompts, అక్షరం ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	అక్షరం *challenge = ఖాళీ;

	*infotxt = ఖాళీ;
	*numprompts = 0;
	*prompts = ఖాళీ;
	*echo_on = ఖాళీ;

	ఒకవేళ (authctxt->as != ఖాళీ) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		ఒకవేళ (challenge == ఖాళీ) {
			auth_close(authctxt->as);
			authctxt->as = ఖాళీ;
		}
	}

	ఒకవేళ (challenge == ఖాళీ) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		ఒకవేళ (authctxt->as == ఖాళీ)
			challenge = ఖాళీ;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	ఒకవేళ (challenge == ఖాళీ)
		తిరిగి -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, పరిమాణం(అక్షరం *));
	*echo_on = xcalloc(*numprompts, పరిమాణం(u_int));
	(*prompts)[0] = xstrdup(challenge);

	తిరిగి 0;
}

పూర్ణాంకం
bsdauth_respond(శూన్య *ctx, u_int numresponses, అక్షరం **responses)
{
	Authctxt *authctxt = ctx;
	పూర్ణాంకం authok;

	ఒకవేళ (!authctxt->valid)
		తిరిగి -1;

	ఒకవేళ (authctxt->as == ఖాళీ)
		error("bsdauth_respond: no bsd auth session");

	ఒకవేళ (numresponses != 1)
		తిరిగి -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = ఖాళీ;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	తిరిగి (authok == 0) ? -1 : 0;
}

స్థిర శూన్య
bsdauth_free_ctx(శూన్య *ctx)
{
	Authctxt *authctxt = ctx;

	ఒకవేళ (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = ఖాళీ;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#అయితే_ముగింపు
