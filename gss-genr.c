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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
ਪੂਰਨ
ssh_gssapi_get_ਬਫਰ_desc(ਬਣਤਰ sshbuf *b, gss_ਬਫਰ_desc *g)
{
	ਪੂਰਨ r;
	u_char *p;
	ਮਾਪ_t len;

	ਜੇ ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ਵਾਪਸ r;
	g->ਮੁੱਲ = p;
	g->ਲੰਮਾਈ = len;
	ਵਾਪਸ 0;
}

/* Check that the OID in a data stream matches that in the context */
ਪੂਰਨ
ssh_gssapi_check_oid(Gssctxt *ctx, ਖਾਲੀ *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	ਵਾਪਸ (ctx != ਨਿਰਾ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->ਲੰਮਾਈ == len &&
	    memcmp(ctx->oid->elements, ਅੰਕੜੇ, len) == 0);
}

/* Set the contexts OID from a data stream */
ਖਾਲੀ
ssh_gssapi_ਸੈੱਟ_oid_ਅੰਕੜੇ(Gssctxt *ctx, ਖਾਲੀ *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	ਜੇ (ctx->oid != GSS_C_NO_OID) {
		ਮੁਕਤ(ctx->oid->elements);
		ਮੁਕਤ(ctx->oid);
	}
	ctx->oid = xcalloc(1, ਆਕਾਰ(gss_OID_desc));
	ctx->oid->ਲੰਮਾਈ = len;
	ctx->oid->elements = xmalloc(len);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->oid->elements, ਅੰਕੜੇ, len);
}

/* Set the contexts OID */
ਖਾਲੀ
ssh_gssapi_ਸੈੱਟ_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_ਸੈੱਟ_oid_ਅੰਕੜੇ(ctx, oid->elements, oid->ਲੰਮਾਈ);
}

/* All this effort to report an error ... */
ਖਾਲੀ
ssh_gssapi_error(Gssctxt *ctxt)
{
	ਅੱਖਰ *s;

	s = ssh_gssapi_ਆਖਰੀ_error(ctxt, ਨਿਰਾ, ਨਿਰਾ);
	debug("%s", s);
	ਮੁਕਤ(s);
}

ਅੱਖਰ *
ssh_gssapi_ਆਖਰੀ_error(Gssctxt *ctxt, OM_uint32 *major_ਸਥਿਤੀ,
    OM_uint32 *minor_ਸਥਿਤੀ)
{
	OM_uint32 lmin;
	gss_ਬਫਰ_desc ਸੁਨੇਹਾ = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	OM_uint32 ctx;
	ਬਣਤਰ sshbuf *b;
	ਅੱਖਰ *ret;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜੇ (major_ਸਥਿਤੀ != ਨਿਰਾ)
		*major_ਸਥਿਤੀ = ctxt->major;
	ਜੇ (minor_ਸਥਿਤੀ != ਨਿਰਾ)
		*minor_ਸਥਿਤੀ = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	ਕਰੋ {
		gss_display_ਸਥਿਤੀ(&lmin, ctxt->major,
		    GSS_C_GSS_ਕੋਡ, ctxt->oid, &ctx, &ਸੁਨੇਹਾ);

		ਜੇ ((r = sshbuf_put(b, ਸੁਨੇਹਾ.ਮੁੱਲ, ਸੁਨੇਹਾ.ਲੰਮਾਈ)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_ਬਫਰ(&lmin, &ਸੁਨੇਹਾ);
	} ਜਦੋਂ (ctx != 0);

	/* The mechanism specific error */
	ਕਰੋ {
		gss_display_ਸਥਿਤੀ(&lmin, ctxt->minor,
		    GSS_C_MECH_ਕੋਡ, ctxt->oid, &ctx, &ਸੁਨੇਹਾ);

		ਜੇ ((r = sshbuf_put(b, ਸੁਨੇਹਾ.ਮੁੱਲ, ਸੁਨੇਹਾ.ਲੰਮਾਈ)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_ਬਫਰ(&lmin, &ਸੁਨੇਹਾ);
	} ਜਦੋਂ (ctx != 0);

	ਜੇ ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(b));
	sshbuf_free(b);
	ਵਾਪਸ (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
ਖਾਲੀ
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, ਆਕਾਰ (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
ਖਾਲੀ
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	ਜੇ ((*ctx) == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_ਬਫਰ);
	ਜੇ ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	ਜੇ ((*ctx)->oid != GSS_C_NO_OID) {
		ਮੁਕਤ((*ctx)->oid->elements);
		ਮੁਕਤ((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	ਜੇ ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	ਜੇ ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	ਜੇ ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	ਮੁਕਤ(*ctx);
	*ctx = ਨਿਰਾ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, ਪੂਰਨ deleg_creds, gss_ਬਫਰ_desc *recv_tok,
    gss_ਬਫਰ_desc* send_tok, OM_uint32 *flags)
{
	ਪੂਰਨ deleg_flag = 0;

	ਜੇ (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ਨਿਰਾ, recv_tok, ਨਿਰਾ, send_tok, flags, ਨਿਰਾ);

	ਜੇ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ਵਾਪਸ (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ਅਚਲ ਅੱਖਰ *host)
{
	gss_ਬਫਰ_desc gssbuf;
	ਅੱਖਰ *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.ਮੁੱਲ = val;
	gssbuf.ਲੰਮਾਈ = ਲੜੀ_ਲੰਬਾਈ(gssbuf.ਮੁੱਲ);

	ਜੇ ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	ਮੁਕਤ(gssbuf.ਮੁੱਲ);
	ਵਾਪਸ (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_ਬਫਰ_t ਬਫਰ, gss_ਬਫਰ_t hash)
{
	ਜੇ ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, ਬਫਰ, hash)))
		ssh_gssapi_error(ctx);

	ਵਾਪਸ (ctx->major);
}

ਖਾਲੀ
ssh_gssapi_buildmic(ਬਣਤਰ sshbuf *b, ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *service,
    ਅਚਲ ਅੱਖਰ *context, ਅਚਲ ਬਣਤਰ sshbuf *session_id)
{
	ਪੂਰਨ r;

	sshbuf_reset(b);
	ਜੇ ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

ਪੂਰਨ
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ਅਚਲ ਅੱਖਰ *host)
{
	gss_ਬਫਰ_desc token = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (ਖਾਲੀ *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	ਜੇ (oid->ਲੰਮਾਈ == spnego_oid.ਲੰਮਾਈ &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->ਲੰਮਾਈ) == 0))
		ਵਾਪਸ 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_ਸੈੱਟ_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	ਜੇ (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_ਬਫਰ, &token,
		    ਨਿਰਾ);
		gss_release_ਬਫਰ(&minor, &token);
		ਜੇ ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_ਬਫਰ);
	}

	ਜੇ (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ਵਾਪਸ (!GSS_ERROR(major));
}

#ਜੇ_ਅੰਤ /* GSSAPI */
