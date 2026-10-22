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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef GSSAPI

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"

#ಅನ್ತರ್ಭಾವ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
ಪೂರ್ಣಾಙ್ಕ
ssh_gssapi_get_buffer_desc(ಸಂರಚನಾ sshbuf *b, gss_buffer_desc *g)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char *p;
	size_t len;

	ಯದಿ ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	g->ಮೌಲ್ಯ = p;
	g->length = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Check that the OID in a data stream matches that in the context */
ಪೂರ್ಣಾಙ್ಕ
ssh_gssapi_check_oid(Gssctxt *ctx, ಶೂನ್ಯ *data, size_t len)
{
	ಪ್ರತ್ಯಾಗಮ (ctx != ರಿಕ್ತ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
ಶೂನ್ಯ
ssh_gssapi_set_oid_data(Gssctxt *ctx, ಶೂನ್ಯ *data, size_t len)
{
	ಯದಿ (ctx->oid != GSS_C_NO_OID) {
		ಮುಕ್ತ(ctx->oid->elements);
		ಮುಕ್ತ(ctx->oid);
	}
	ctx->oid = xcalloc(1, ಪರಿಮಾಣ(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
ಶೂನ್ಯ
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
ಶೂನ್ಯ
ssh_gssapi_error(Gssctxt *ctxt)
{
	ವರ್ಣ *s;

	s = ssh_gssapi_last_error(ctxt, ರಿಕ್ತ, ರಿಕ್ತ);
	debug("%s", s);
	ಮುಕ್ತ(s);
}

ವರ್ಣ *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc ಸಂದೇಶ = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	ಸಂರಚನಾ sshbuf *b;
	ವರ್ಣ *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯದಿ (major_status != ರಿಕ್ತ)
		*major_status = ctxt->major;
	ಯದಿ (minor_status != ರಿಕ್ತ)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	ಕುರು {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &ಸಂದೇಶ);

		ಯದಿ ((r = sshbuf_put(b, ಸಂದೇಶ.ಮೌಲ್ಯ, ಸಂದೇಶ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &ಸಂದೇಶ);
	} ಯಾವತ್ (ctx != 0);

	/* The mechanism specific error */
	ಕುರು {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &ಸಂದೇಶ);

		ಯದಿ ((r = sshbuf_put(b, ಸಂದೇಶ.ಮೌಲ್ಯ, ಸಂದೇಶ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &ಸಂದೇಶ);
	} ಯಾವತ್ (ctx != 0);

	ಯದಿ ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ಧ್ರುವ ವರ್ಣ *)sshbuf_ptr(b));
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
ಶೂನ್ಯ
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, ಪರಿಮಾಣ (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
ಶೂನ್ಯ
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	ಯದಿ ((*ctx) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	ಯದಿ ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	ಯದಿ ((*ctx)->oid != GSS_C_NO_OID) {
		ಮುಕ್ತ((*ctx)->oid->elements);
		ಮುಕ್ತ((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	ಯದಿ ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	ಯದಿ ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	ಯದಿ ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	ಮುಕ್ತ(*ctx);
	*ctx = ರಿಕ್ತ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, ಪೂರ್ಣಾಙ್ಕ deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	ಪೂರ್ಣಾಙ್ಕ deleg_flag = 0;

	ಯದಿ (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ರಿಕ್ತ, recv_tok, ರಿಕ್ತ, send_tok, flags, ರಿಕ್ತ);

	ಯದಿ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ಪ್ರತ್ಯಾಗಮ (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ಧ್ರುವ ವರ್ಣ *host)
{
	gss_buffer_desc gssbuf;
	ವರ್ಣ *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.ಮೌಲ್ಯ = val;
	gssbuf.length = strlen(gssbuf.ಮೌಲ್ಯ);

	ಯದಿ ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	ಮುಕ್ತ(gssbuf.ಮೌಲ್ಯ);
	ಪ್ರತ್ಯಾಗಮ (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	ಯದಿ ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	ಪ್ರತ್ಯಾಗಮ (ctx->major);
}

ಶೂನ್ಯ
ssh_gssapi_buildmic(ಸಂರಚನಾ sshbuf *b, ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *service,
    ಧ್ರುವ ವರ್ಣ *context, ಧ್ರುವ ಸಂರಚನಾ sshbuf *session_id)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	sshbuf_reset(b);
	ಯದಿ ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

ಪೂರ್ಣಾಙ್ಕ
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ಧ್ರುವ ವರ್ಣ *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (ಶೂನ್ಯ *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	ಯದಿ (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		ಪ್ರತ್ಯಾಗಮ 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	ಯದಿ (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    ರಿಕ್ತ);
		gss_release_buffer(&minor, &token);
		ಯದಿ ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	ಯದಿ (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ಪ್ರತ್ಯಾಗಮ (!GSS_ERROR(major));
}

#endif /* GSSAPI */
