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

#اگر_تعریف_شدہ GSSAPI

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
ssh_gssapi_get_بفر_desc(ساخت sshbuf *b, gss_بفر_desc *g)
{
	صحیح r;
	u_char *p;
	سائز_t len;

	اگر ((r = sshbuf_get_string(b, &p, &len)) != 0)
		واپس r;
	g->قدر = p;
	g->لمبائی = len;
	واپس 0;
}

/* Check that the OID in a data stream matches that in the context */
صحیح
ssh_gssapi_check_oid(Gssctxt *ctx, خالی *ڈیٹا, سائز_t len)
{
	واپس (ctx != تہی && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->لمبائی == len &&
	    memcmp(ctx->oid->elements, ڈیٹا, len) == 0);
}

/* Set the contexts OID from a data stream */
خالی
ssh_gssapi_سیٹ_oid_ڈیٹا(Gssctxt *ctx, خالی *ڈیٹا, سائز_t len)
{
	اگر (ctx->oid != GSS_C_NO_OID) {
		آزاد(ctx->oid->elements);
		آزاد(ctx->oid);
	}
	ctx->oid = xcalloc(1, حجم(gss_OID_desc));
	ctx->oid->لمبائی = len;
	ctx->oid->elements = xmalloc(len);
	حافظہ_نقل(ctx->oid->elements, ڈیٹا, len);
}

/* Set the contexts OID */
خالی
ssh_gssapi_سیٹ_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_سیٹ_oid_ڈیٹا(ctx, oid->elements, oid->لمبائی);
}

/* All this effort to report an error ... */
خالی
ssh_gssapi_error(Gssctxt *ctxt)
{
	حرف *s;

	s = ssh_gssapi_آخری_error(ctxt, تہی, تہی);
	debug("%s", s);
	آزاد(s);
}

حرف *
ssh_gssapi_آخری_error(Gssctxt *ctxt, OM_uint32 *major_حالت,
    OM_uint32 *minor_حالت)
{
	OM_uint32 lmin;
	gss_بفر_desc پیغام = GSS_C_خالی_خانے_بفر;
	OM_uint32 ctx;
	ساخت sshbuf *b;
	حرف *ret;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	اگر (major_حالت != تہی)
		*major_حالت = ctxt->major;
	اگر (minor_حالت != تہی)
		*minor_حالت = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	کرو {
		gss_display_حالت(&lmin, ctxt->major,
		    GSS_C_GSS_رمز, ctxt->oid, &ctx, &پیغام);

		اگر ((r = sshbuf_put(b, پیغام.قدر, پیغام.لمبائی)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_بفر(&lmin, &پیغام);
	} جب (ctx != 0);

	/* The mechanism specific error */
	کرو {
		gss_display_حالت(&lmin, ctxt->minor,
		    GSS_C_MECH_رمز, ctxt->oid, &ctx, &پیغام);

		اگر ((r = sshbuf_put(b, پیغام.قدر, پیغام.لمبائی)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_بفر(&lmin, &پیغام);
	} جب (ctx != 0);

	اگر ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ثابت حرف *)sshbuf_ptr(b));
	sshbuf_free(b);
	واپس (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
خالی
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, حجم (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
خالی
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	اگر ((*ctx) == تہی)
		واپس;
	اگر ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_بفر);
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
	*ctx = تہی;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, صحیح deleg_creds, gss_بفر_desc *recv_tok,
    gss_بفر_desc* send_tok, OM_uint32 *flags)
{
	صحیح deleg_flag = 0;

	اگر (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, تہی, recv_tok, تہی, send_tok, flags, تہی);

	اگر (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	واپس (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ثابت حرف *host)
{
	gss_بفر_desc gssbuf;
	حرف *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.قدر = val;
	gssbuf.لمبائی = لڑی_لمبائی(gssbuf.قدر);

	اگر ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	آزاد(gssbuf.قدر);
	واپس (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_بفر_t بفر, gss_بفر_t hash)
{
	اگر ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, بفر, hash)))
		ssh_gssapi_error(ctx);

	واپس (ctx->major);
}

خالی
ssh_gssapi_buildmic(ساخت sshbuf *b, ثابت حرف *user, ثابت حرف *service,
    ثابت حرف *context, ثابت ساخت sshbuf *session_id)
{
	صحیح r;

	sshbuf_reset(b);
	اگر ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

صحیح
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ثابت حرف *host)
{
	gss_بفر_desc token = GSS_C_خالی_خانے_بفر;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (خالی *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	اگر (oid->لمبائی == spnego_oid.لمبائی &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->لمبائی) == 0))
		واپس 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_سیٹ_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	اگر (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_بفر, &token,
		    تہی);
		gss_release_بفر(&minor, &token);
		اگر ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_بفر);
	}

	اگر (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	واپس (!GSS_ERROR(major));
}

#اگر_ختم /* GSSAPI */
