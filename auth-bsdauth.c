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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#ifdef BSD_AUTH
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "log.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"

स्थिर शून्य *
bsdauth_init_ctx(Authctxt *authctxt)
{
	परत authctxt;
}

पूर्णांक
bsdauth_query(शून्य *ctx, अक्षर **name, अक्षर **infotxt,
   u_int *numprompts, अक्षर ***prompts, u_int **echo_on)
{
	Authctxt *authctxt = ctx;
	अक्षर *challenge = रिक्त;

	*infotxt = रिक्त;
	*numprompts = 0;
	*prompts = रिक्त;
	*echo_on = रिक्त;

	जर (authctxt->as != रिक्त) {
		debug2("bsdauth_query: try reuse session");
		challenge = auth_getitem(authctxt->as, AUTHV_CHALLENGE);
		जर (challenge == रिक्त) {
			auth_close(authctxt->as);
			authctxt->as = रिक्त;
		}
	}

	जर (challenge == रिक्त) {
		debug2("bsdauth_query: new bsd auth session");
		debug3("bsdauth_query: style %s",
		    authctxt->style ? authctxt->style : "<default>");
		authctxt->as = auth_userchallenge(authctxt->user,
		    authctxt->style, "auth-ssh", &challenge);
		जर (authctxt->as == रिक्त)
			challenge = रिक्त;
		debug2("bsdauth_query: <%s>", challenge ? challenge : "empty");
	}

	जर (challenge == रिक्त)
		परत -1;

	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, आकार(अक्षर *));
	*echo_on = xcalloc(*numprompts, आकार(u_int));
	(*prompts)[0] = xstrdup(challenge);

	परत 0;
}

पूर्णांक
bsdauth_respond(शून्य *ctx, u_int numresponses, अक्षर **responses)
{
	Authctxt *authctxt = ctx;
	पूर्णांक authok;

	जर (!authctxt->valid)
		परत -1;

	जर (authctxt->as == रिक्त)
		error("bsdauth_respond: no bsd auth session");

	जर (numresponses != 1)
		परत -1;

	authok = auth_userresponse(authctxt->as, responses[0], 0);
	authctxt->as = रिक्त;
	debug3("bsdauth_respond: <%s> = <%d>", responses[0], authok);

	परत (authok == 0) ? -1 : 0;
}

स्थिर शून्य
bsdauth_free_ctx(शून्य *ctx)
{
	Authctxt *authctxt = ctx;

	जर (authctxt && authctxt->as) {
		auth_close(authctxt->as);
		authctxt->as = रिक्त;
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
