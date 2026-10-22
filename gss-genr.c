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

#ضمن "includes.h"

#ifdef GSSAPI

#ضمن <sys/types.h>

#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "ssh2.h"

#ضمن "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
صحيح
ssh_gssapi_get_buffer_desc(بنية sshbuf *b, gss_buffer_desc *g)
{
	صحيح r;
	u_char *p;
	size_t len;

	𐡄𐡍 ((r = sshbuf_get_string(b, &p, &len)) != 0)
		أرجع r;
	g->value = p;
	g->length = len;
	أرجع 0;
}

/* Check that the OID in a data stream matches that in the context */
صحيح
ssh_gssapi_check_oid(Gssctxt *ctx, فراغ *data, size_t len)
{
	أرجع (ctx != عدم && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
فراغ
ssh_gssapi_set_oid_data(Gssctxt *ctx, فراغ *data, size_t len)
{
	𐡄𐡍 (ctx->oid != GSS_C_NO_OID) {
		حرر(ctx->oid->elements);
		حرر(ctx->oid);
	}
	ctx->oid = xcalloc(1, حجم(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
فراغ
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
فراغ
ssh_gssapi_error(Gssctxt *ctxt)
{
	حرف *s;

	s = ssh_gssapi_last_error(ctxt, عدم, عدم);
	debug("%s", s);
	حرر(s);
}

حرف *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	بنية sshbuf *b;
	حرف *ret;
	صحيح r;

	𐡄𐡍 ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	𐡄𐡍 (major_status != عدم)
		*major_status = ctxt->major;
	𐡄𐡍 (minor_status != عدم)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	𐡏𐡁𐡃 {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &msg);

		𐡄𐡍 ((r = sshbuf_put(b, msg.value, msg.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &msg);
	} طالما (ctx != 0);

	/* The mechanism specific error */
	𐡏𐡁𐡃 {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &msg);

		𐡄𐡍 ((r = sshbuf_put(b, msg.value, msg.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &msg);
	} طالما (ctx != 0);

	𐡄𐡍 ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ثابت حرف *)sshbuf_ptr(b));
	sshbuf_free(b);
	أرجع (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
فراغ
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
فراغ
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	𐡄𐡍 ((*ctx) == عدم)
		أرجع;
	𐡄𐡍 ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	𐡄𐡍 ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	𐡄𐡍 ((*ctx)->oid != GSS_C_NO_OID) {
		حرر((*ctx)->oid->elements);
		حرر((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	𐡄𐡍 ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	𐡄𐡍 ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	𐡄𐡍 ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	حرر(*ctx);
	*ctx = عدم;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, صحيح deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	صحيح deleg_flag = 0;

	𐡄𐡍 (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, عدم, recv_tok, عدم, send_tok, flags, عدم);

	𐡄𐡍 (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	أرجع (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ثابت حرف *host)
{
	gss_buffer_desc gssbuf;
	حرف *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.value = val;
	gssbuf.length = strlen(gssbuf.value);

	𐡄𐡍 ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	حرر(gssbuf.value);
	أرجع (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	𐡄𐡍 ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	أرجع (ctx->major);
}

فراغ
ssh_gssapi_buildmic(بنية sshbuf *b, ثابت حرف *user, ثابت حرف *service,
    ثابت حرف *context, ثابت بنية sshbuf *session_id)
{
	صحيح r;

	sshbuf_reset(b);
	𐡄𐡍 ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

صحيح
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ثابت حرف *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (فراغ *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	𐡄𐡍 (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		أرجع 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	𐡄𐡍 (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    عدم);
		gss_release_buffer(&minor, &token);
		𐡄𐡍 ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	𐡄𐡍 (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	أرجع (!GSS_ERROR(major));
}

#endif /* GSSAPI */
