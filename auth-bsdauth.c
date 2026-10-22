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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#अगर_घोषित BSD_AUTH
#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "log.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"

अटल व्योम *
bsdauth_init_ctx(Authctxt *authctxt)
{
	वापस authctxt;
}

पूर्णांक
bsdauth_query(व्योम *ctx, अक्षर **name, अक्षर **infotxt,
   u_int *numprompts, अक्षर ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	अक्षर *challenge = शून्य;

	*infotxt = शून्य;
	*numprompts = 0;
	*prompts = शून्य;
	*echo_on = शून्य;

	अगर (authctxt->as != शून्य) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		अगर (challenge == शून्य) {
			auth_close(authctxt->as);
			authctxt->as = शून्य;
		}
	}

	अगर (challenge == शून्य) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		अगर (authctxt->as == शून्य)
			challenge = शून्य;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	अगर (challenge == शून्य)
		वापस -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, माप(अक्षर *));
	*echo_on = xcalloc(*numprompts, माप(u_int));
	(*prompts)[0] = xstrdup(challenge);

	वापस 0;
}

पूर्णांक
bsdauth_respond(व्योम *ctx, u_int numresponses, अक्षर **responses)
{
	Authctxt *authctxt = ctx;
	पूर्णांक authok;

	अगर (!authctxt->valid)
		वापस -1;

	अगर (authctxt->as == शून्य)
		error("bsdauth_respond: no bsd auth session");

	अगर (numresponses != 1)
		वापस -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = शून्य;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	वापस (authok == 0) ? -1 : 0;
}

अटल व्योम
bsdauth_free_ctx(व्योम *ctx)
{
	Authctxt *authctxt = ctx;

	अगर (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = शून्य;
	}
}

KbdintDevice mm_bsdauth_device = {
	"bsdauth",
	bsdauth_init_ctx,
	mm_bsdauth_query,
	mm_bsdauth_respond,
	bsdauth_free_ctx
};
#पूर्ण_अगर
