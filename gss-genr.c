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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI

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
ಪೂರ್ಣಾಂಕ
ssh_gssapi_get_ಬಫರ್_desc(ರಚನೆ sshbuf *b, gss_ಬಫರ್_desc *g)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char *p;
	ಗಾತ್ರ_t len;

	ಆದರೆ ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	g->ಮೌಲ್ಯ = p;
	g->ಉದ್ದಳತೆ = len;
	ಹಿಂತಿರುಗಿ 0;
}

/* Check that the OID in a data stream matches that in the context */
ಪೂರ್ಣಾಂಕ
ssh_gssapi_check_oid(Gssctxt *ctx, ಶೂನ್ಯ *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ (ctx != ಖಾಲಿ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->ಉದ್ದಳತೆ == len &&
	    memcmp(ctx->oid->elements, ದತ್ತಾಂಶ, len) == 0);
}

/* Set the contexts OID from a data stream */
ಶೂನ್ಯ
ssh_gssapi_ಗಣ_oid_ದತ್ತಾಂಶ(Gssctxt *ctx, ಶೂನ್ಯ *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	ಆದರೆ (ctx->oid != GSS_C_NO_OID) {
		ಬಿಡುಗಡೆ(ctx->oid->elements);
		ಬಿಡುಗಡೆ(ctx->oid);
	}
	ctx->oid = xcalloc(1, ಗಾತ್ರ(gss_OID_desc));
	ctx->oid->ಉದ್ದಳತೆ = len;
	ctx->oid->elements = xmalloc(len);
	ಸ್ಮರಣೆ_ನಕಲು(ctx->oid->elements, ದತ್ತಾಂಶ, len);
}

/* Set the contexts OID */
ಶೂನ್ಯ
ssh_gssapi_ಗಣ_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_ಗಣ_oid_ದತ್ತಾಂಶ(ctx, oid->elements, oid->ಉದ್ದಳತೆ);
}

/* All this effort to report an error ... */
ಶೂನ್ಯ
ssh_gssapi_error(Gssctxt *ctxt)
{
	ಅಕ್ಷರ *s;

	s = ssh_gssapi_ಕೊನೆಯ_error(ctxt, ಖಾಲಿ, ಖಾಲಿ);
	debug("%s", s);
	ಬಿಡುಗಡೆ(s);
}

ಅಕ್ಷರ *
ssh_gssapi_ಕೊನೆಯ_error(Gssctxt *ctxt, OM_uint32 *major_ಸ್ಥಿತಿ,
    OM_uint32 *minor_ಸ್ಥಿತಿ)
{
	OM_uint32 lmin;
	gss_ಬಫರ್_desc ಸಂದೇಶ = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	OM_uint32 ctx;
	ರಚನೆ sshbuf *b;
	ಅಕ್ಷರ *ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆದರೆ (major_ಸ್ಥಿತಿ != ಖಾಲಿ)
		*major_ಸ್ಥಿತಿ = ctxt->major;
	ಆದರೆ (minor_ಸ್ಥಿತಿ != ಖಾಲಿ)
		*minor_ಸ್ಥಿತಿ = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	ಮಾಡು {
		gss_display_ಸ್ಥಿತಿ(&lmin, ctxt->major,
		    GSS_C_GSS_ಸಂಕೇತ, ctxt->oid, &ctx, &ಸಂದೇಶ);

		ಆದರೆ ((r = sshbuf_put(b, ಸಂದೇಶ.ಮೌಲ್ಯ, ಸಂದೇಶ.ಉದ್ದಳತೆ)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_ಬಫರ್(&lmin, &ಸಂದೇಶ);
	} ಆಗ (ctx != 0);

	/* The mechanism specific error */
	ಮಾಡು {
		gss_display_ಸ್ಥಿತಿ(&lmin, ctxt->minor,
		    GSS_C_MECH_ಸಂಕೇತ, ctxt->oid, &ctx, &ಸಂದೇಶ);

		ಆದರೆ ((r = sshbuf_put(b, ಸಂದೇಶ.ಮೌಲ್ಯ, ಸಂದೇಶ.ಉದ್ದಳತೆ)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_ಬಫರ್(&lmin, &ಸಂದೇಶ);
	} ಆಗ (ctx != 0);

	ಆದರೆ ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(b));
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ (ret);
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
	*ctx = xcalloc(1, ಗಾತ್ರ (Gssctxt));
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

	ಆದರೆ ((*ctx) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_ಬಫರ್);
	ಆದರೆ ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	ಆದರೆ ((*ctx)->oid != GSS_C_NO_OID) {
		ಬಿಡುಗಡೆ((*ctx)->oid->elements);
		ಬಿಡುಗಡೆ((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	ಆದರೆ ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	ಆದರೆ ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	ಆದರೆ ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	ಬಿಡುಗಡೆ(*ctx);
	*ctx = ಖಾಲಿ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, ಪೂರ್ಣಾಂಕ deleg_creds, gss_ಬಫರ್_desc *recv_tok,
    gss_ಬಫರ್_desc* send_tok, OM_uint32 *flags)
{
	ಪೂರ್ಣಾಂಕ deleg_flag = 0;

	ಆದರೆ (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ಖಾಲಿ, recv_tok, ಖಾಲಿ, send_tok, flags, ಖಾಲಿ);

	ಆದರೆ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ಹಿಂತಿರುಗಿ (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host)
{
	gss_ಬಫರ್_desc gssbuf;
	ಅಕ್ಷರ *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.ಮೌಲ್ಯ = val;
	gssbuf.ಉದ್ದಳತೆ = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(gssbuf.ಮೌಲ್ಯ);

	ಆದರೆ ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	ಬಿಡುಗಡೆ(gssbuf.ಮೌಲ್ಯ);
	ಹಿಂತಿರುಗಿ (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_ಬಫರ್_t ಬಫರ್, gss_ಬಫರ್_t hash)
{
	ಆದರೆ ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, ಬಫರ್, hash)))
		ssh_gssapi_error(ctx);

	ಹಿಂತಿರುಗಿ (ctx->major);
}

ಶೂನ್ಯ
ssh_gssapi_buildmic(ರಚನೆ sshbuf *b, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *service,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *context, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *session_id)
{
	ಪೂರ್ಣಾಂಕ r;

	sshbuf_reset(b);
	ಆದರೆ ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

ಪೂರ್ಣಾಂಕ
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host)
{
	gss_ಬಫರ್_desc token = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (ಶೂನ್ಯ *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	ಆದರೆ (oid->ಉದ್ದಳತೆ == spnego_oid.ಉದ್ದಳತೆ &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->ಉದ್ದಳತೆ) == 0))
		ಹಿಂತಿರುಗಿ 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_ಗಣ_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	ಆದರೆ (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_ಬಫರ್, &token,
		    ಖಾಲಿ);
		gss_release_ಬಫರ್(&minor, &token);
		ಆದರೆ ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_ಬಫರ್);
	}

	ಆದರೆ (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ಹಿಂತಿರುಗಿ (!GSS_ERROR(major));
}

#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */
