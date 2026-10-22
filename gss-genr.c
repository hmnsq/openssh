/* $OpenBSD: gss-genr.c,v 1.31 2026/02/08 19:54:31 dtucker Exp $ */

/*
 * Copyright (c) 2001-2007 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#अगर_घोषित GSSAPI

#समावेश <sys/types.h>

#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "ssh2.h"

#समावेश "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
पूर्णांक
ssh_gssapi_get_बफर_desc(काष्ठा sshbuf *b, gss_बफर_desc *g)
{
	पूर्णांक r;
	u_char *p;
	माप_प्रकार len;

	अगर ((r = sshbuf_get_string(b, &p, &len)) != 0)
		वापस r;
	g->मूल्य = p;
	g->लंबाई = len;
	वापस 0;
}

/* Check that the OID in a data stream matches that in the context */
पूर्णांक
ssh_gssapi_check_oid(Gssctxt *ctx, व्योम *तथ्य, माप_प्रकार len)
{
	वापस (ctx != शून्य && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->लंबाई == len &&
	    स_भेद(ctx->oid->elements, तथ्य, len) == 0);
}

/* Set the contexts OID from a data stream */
व्योम
ssh_gssapi_set_oid_तथ्य(Gssctxt *ctx, व्योम *तथ्य, माप_प्रकार len)
{
	अगर (ctx->oid != GSS_C_NO_OID) {
		मुक्त(ctx->oid->elements);
		मुक्त(ctx->oid);
	}
	ctx->oid = xcalloc(1, माप(gss_OID_desc));
	ctx->oid->लंबाई = len;
	ctx->oid->elements = xmalloc(len);
	स_नकल(ctx->oid->elements, तथ्य, len);
}

/* Set the contexts OID */
व्योम
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_तथ्य(ctx, oid->elements, oid->लंबाई);
}

/* All this effort to report an error ... */
व्योम
ssh_gssapi_error(Gssctxt *ctxt)
{
	अक्षर *s;

	s = ssh_gssapi_last_error(ctxt, शून्य, शून्य);
	debug("%s", s);
	मुक्त(s);
}

अक्षर *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_बफर_desc संदेश = GSS_C_EMPTY_बफर;
	OM_uint32 ctx;
	काष्ठा sshbuf *b;
	अक्षर *ret;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	अगर (major_status != शून्य)
		*major_status = ctxt->major;
	अगर (minor_status != शून्य)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	करो {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &संदेश);

		अगर ((r = sshbuf_put(b, संदेश.मूल्य, संदेश.लंबाई)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_बफर(&lmin, &संदेश);
	} जबतक (ctx != 0);

	/* The mechanism specific error */
	करो {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &संदेश);

		अगर ((r = sshbuf_put(b, संदेश.मूल्य, संदेश.लंबाई)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_बफर(&lmin, &संदेश);
	} जबतक (ctx != 0);

	अगर ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((स्थिर अक्षर *)sshbuf_ptr(b));
	sshbuf_free(b);
	वापस (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
व्योम
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, माप (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
व्योम
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	अगर ((*ctx) == शून्य)
		वापस;
	अगर ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_बफर);
	अगर ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	अगर ((*ctx)->oid != GSS_C_NO_OID) {
		मुक्त((*ctx)->oid->elements);
		मुक्त((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	अगर ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	अगर ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	अगर ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	मुक्त(*ctx);
	*ctx = शून्य;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, पूर्णांक deleg_creds, gss_बफर_desc *recv_tok,
    gss_बफर_desc* send_tok, OM_uint32 *flags)
{
	पूर्णांक deleg_flag = 0;

	अगर (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, शून्य, recv_tok, शून्य, send_tok, flags, शून्य);

	अगर (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	वापस (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, स्थिर अक्षर *host)
{
	gss_बफर_desc gssbuf;
	अक्षर *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.मूल्य = val;
	gssbuf.लंबाई = म_माप(gssbuf.मूल्य);

	अगर ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	मुक्त(gssbuf.मूल्य);
	वापस (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_बफर_t बफर, gss_बफर_t hash)
{
	अगर ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, बफर, hash)))
		ssh_gssapi_error(ctx);

	वापस (ctx->major);
}

व्योम
ssh_gssapi_buildmic(काष्ठा sshbuf *b, स्थिर अक्षर *user, स्थिर अक्षर *service,
    स्थिर अक्षर *context, स्थिर काष्ठा sshbuf *session_id)
{
	पूर्णांक r;

	sshbuf_reset(b);
	अगर ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

पूर्णांक
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, स्थिर अक्षर *host)
{
	gss_बफर_desc token = GSS_C_EMPTY_बफर;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (व्योम *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	अगर (oid->लंबाई == spnego_oid.लंबाई &&
	    (स_भेद(oid->elements, spnego_oid.elements, oid->लंबाई) == 0))
		वापस 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	अगर (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_बफर, &token,
		    शून्य);
		gss_release_बफर(&minor, &token);
		अगर ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_बफर);
	}

	अगर (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	वापस (!GSS_ERROR(major));
}

#पूर्ण_अगर /* GSSAPI */
