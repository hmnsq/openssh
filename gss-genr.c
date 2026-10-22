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

#شامل "includes.h"

#ifdef GSSAPI

#شامل <sys/types.h>

#شامل <limits.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "ssh2.h"

#شامل "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
صحیح
ssh_gssapi_get_buffer_desc(ساختار sshbuf *b, gss_buffer_desc *g)
{
	صحیح r;
	u_char *p;
	size_t len;

	اگر ((r = sshbuf_get_string(b, &p, &len)) != 0)
		بازگشت r;
	g->مقدار = p;
	g->length = len;
	بازگشت 0;
}

/* Check that the OID in a data stream matches that in the context */
صحیح
ssh_gssapi_check_oid(Gssctxt *ctx, تهی *data, size_t len)
{
	بازگشت (ctx != پوچ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
تهی
ssh_gssapi_set_oid_data(Gssctxt *ctx, تهی *data, size_t len)
{
	اگر (ctx->oid != GSS_C_NO_OID) {
		آزاد(ctx->oid->elements);
		آزاد(ctx->oid);
	}
	ctx->oid = xcalloc(1, اندازه(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
تهی
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
تهی
ssh_gssapi_error(Gssctxt *ctxt)
{
	نویسه *s;

	s = ssh_gssapi_last_error(ctxt, پوچ, پوچ);
	debug("%s", s);
	آزاد(s);
}

نویسه *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc پیام = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	ساختار sshbuf *b;
	نویسه *ret;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	اگر (major_status != پوچ)
		*major_status = ctxt->major;
	اگر (minor_status != پوچ)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	انجامبده {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &پیام);

		اگر ((r = sshbuf_put(b, پیام.مقدار, پیام.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &پیام);
	} وقتی (ctx != 0);

	/* The mechanism specific error */
	انجامبده {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &پیام);

		اگر ((r = sshbuf_put(b, پیام.مقدار, پیام.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &پیام);
	} وقتی (ctx != 0);

	اگر ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ثابت نویسه *)sshbuf_ptr(b));
	sshbuf_free(b);
	بازگشت (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
تهی
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, اندازه (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
تهی
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	اگر ((*ctx) == پوچ)
		بازگشت;
	اگر ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	اگر ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	اگر ((*ctx)->oid != GSS_C_NO_OID) {
		آزاد((*ctx)->oid->elements);
		آزاد((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	اگر ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	اگر ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	اگر ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	آزاد(*ctx);
	*ctx = پوچ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, صحیح deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	صحیح deleg_flag = 0;

	اگر (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, پوچ, recv_tok, پوچ, send_tok, flags, پوچ);

	اگر (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	بازگشت (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ثابت نویسه *host)
{
	gss_buffer_desc gssbuf;
	نویسه *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.مقدار = val;
	gssbuf.length = strlen(gssbuf.مقدار);

	اگر ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	آزاد(gssbuf.مقدار);
	بازگشت (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	اگر ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	بازگشت (ctx->major);
}

تهی
ssh_gssapi_buildmic(ساختار sshbuf *b, ثابت نویسه *user, ثابت نویسه *service,
    ثابت نویسه *context, ثابت ساختار sshbuf *session_id)
{
	صحیح r;

	sshbuf_reset(b);
	اگر ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

صحیح
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ثابت نویسه *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (تهی *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	اگر (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		بازگشت 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	اگر (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    پوچ);
		gss_release_buffer(&minor, &token);
		اگر ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	اگر (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	بازگشت (!GSS_ERROR(major));
}

#endif /* GSSAPI */
