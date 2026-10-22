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

#અન્તર્ભાવ "includes.h"

#ifdef GSSAPI

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh2.h"

#અન્તર્ભાવ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
પૂર્ણાંક
ssh_gssapi_get_buffer_desc(સંરચના sshbuf *b, gss_buffer_desc *g)
{
	પૂર્ણાંક r;
	u_char *p;
	size_t len;

	જો ((r = sshbuf_get_string(b, &p, &len)) != 0)
		પાછા r;
	g->કિંમત = p;
	g->length = len;
	પાછા 0;
}

/* Check that the OID in a data stream matches that in the context */
પૂર્ણાંક
ssh_gssapi_check_oid(Gssctxt *ctx, શૂન્ય *data, size_t len)
{
	પાછા (ctx != ખાલી && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
શૂન્ય
ssh_gssapi_set_oid_data(Gssctxt *ctx, શૂન્ય *data, size_t len)
{
	જો (ctx->oid != GSS_C_NO_OID) {
		મુક્ત(ctx->oid->elements);
		મુક્ત(ctx->oid);
	}
	ctx->oid = xcalloc(1, કદ(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
શૂન્ય
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
શૂન્ય
ssh_gssapi_error(Gssctxt *ctxt)
{
	અક્ષર *s;

	s = ssh_gssapi_last_error(ctxt, ખાલી, ખાલી);
	debug("%s", s);
	મુક્ત(s);
}

અક્ષર *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc સંદેશ = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	સંરચના sshbuf *b;
	અક્ષર *ret;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જો (major_status != ખાલી)
		*major_status = ctxt->major;
	જો (minor_status != ખાલી)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	કરો {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &સંદેશ);

		જો ((r = sshbuf_put(b, સંદેશ.કિંમત, સંદેશ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &સંદેશ);
	} જ્યારે (ctx != 0);

	/* The mechanism specific error */
	કરો {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &સંદેશ);

		જો ((r = sshbuf_put(b, સંદેશ.કિંમત, સંદેશ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &સંદેશ);
	} જ્યારે (ctx != 0);

	જો ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((અચલ અક્ષર *)sshbuf_ptr(b));
	sshbuf_free(b);
	પાછા (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
શૂન્ય
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, કદ (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
શૂન્ય
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	જો ((*ctx) == ખાલી)
		પાછા;
	જો ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	જો ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	જો ((*ctx)->oid != GSS_C_NO_OID) {
		મુક્ત((*ctx)->oid->elements);
		મુક્ત((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	જો ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	જો ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	જો ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	મુક્ત(*ctx);
	*ctx = ખાલી;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, પૂર્ણાંક deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	પૂર્ણાંક deleg_flag = 0;

	જો (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ખાલી, recv_tok, ખાલી, send_tok, flags, ખાલી);

	જો (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	પાછા (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, અચલ અક્ષર *host)
{
	gss_buffer_desc gssbuf;
	અક્ષર *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.કિંમત = val;
	gssbuf.length = strlen(gssbuf.કિંમત);

	જો ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	મુક્ત(gssbuf.કિંમત);
	પાછા (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	જો ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	પાછા (ctx->major);
}

શૂન્ય
ssh_gssapi_buildmic(સંરચના sshbuf *b, અચલ અક્ષર *user, અચલ અક્ષર *service,
    અચલ અક્ષર *context, અચલ સંરચના sshbuf *session_id)
{
	પૂર્ણાંક r;

	sshbuf_reset(b);
	જો ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

પૂર્ણાંક
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, અચલ અક્ષર *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (શૂન્ય *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	જો (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		પાછા 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	જો (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    ખાલી);
		gss_release_buffer(&minor, &token);
		જો ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	જો (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	પાછા (!GSS_ERROR(major));
}

#endif /* GSSAPI */
