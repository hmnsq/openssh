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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>

#ifdef BSD_AUTH
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "log.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"

நிலையான வெறுமை *
bsdauth_init_ctx(Authctxt *authctxt)
{
	திரும்பு authctxt;
}

முழு
bsdauth_query(வெறுமை *ctx, எழுத்து **name, எழுத்து **infotxt,
   u_int *numprompts, எழுத்து ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	எழுத்து *challenge = வெற்று;

	*infotxt = வெற்று;
	*numprompts = 0;
	*prompts = வெற்று;
	*echo_on = வெற்று;

	எனில் (authctxt->as != வெற்று) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		எனில் (challenge == வெற்று) {
			auth_close(authctxt->as);
			authctxt->as = வெற்று;
		}
	}

	எனில் (challenge == வெற்று) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		எனில் (authctxt->as == வெற்று)
			challenge = வெற்று;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	எனில் (challenge == வெற்று)
		திரும்பு -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, அளவு(எழுத்து *));
	*echo_on = xcalloc(*numprompts, அளவு(u_int));
	(*prompts)[0] = xstrdup(challenge);

	திரும்பு 0;
}

முழு
bsdauth_respond(வெறுமை *ctx, u_int numresponses, எழுத்து **responses)
{
	Authctxt *authctxt = ctx;
	முழு authok;

	எனில் (!authctxt->valid)
		திரும்பு -1;

	எனில் (authctxt->as == வெற்று)
		error("bsdauth_respond: no bsd auth session");

	எனில் (numresponses != 1)
		திரும்பு -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = வெற்று;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	திரும்பு (authok == 0) ? -1 : 0;
}

நிலையான வெறுமை
bsdauth_free_ctx(வெறுமை *ctx)
{
	Authctxt *authctxt = ctx;

	எனில் (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = வெற்று;
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
