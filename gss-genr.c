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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef GSSAPI

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"

#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_gssapi_get_buffer_desc(ସଂରଚନା sshbuf *b, gss_buffer_desc *g)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char *p;
	size_t len;

	ଯଦି ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ଫେରନ୍ତୁ r;
	g->ମୂଲ୍ୟ = p;
	g->length = len;
	ଫେରନ୍ତୁ 0;
}

/* Check that the OID in a data stream matches that in the context */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_gssapi_check_oid(Gssctxt *ctx, ଶୂନ୍ୟ *data, size_t len)
{
	ଫେରନ୍ତୁ (ctx != ଖାଲି && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
ଶୂନ୍ୟ
ssh_gssapi_set_oid_data(Gssctxt *ctx, ଶୂନ୍ୟ *data, size_t len)
{
	ଯଦି (ctx->oid != GSS_C_NO_OID) {
		ମୁକ୍ତ(ctx->oid->elements);
		ମୁକ୍ତ(ctx->oid);
	}
	ctx->oid = xcalloc(1, ଆକାର(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
ଶୂନ୍ୟ
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
ଶୂନ୍ୟ
ssh_gssapi_error(Gssctxt *ctxt)
{
	ଅକ୍ଷର *s;

	s = ssh_gssapi_last_error(ctxt, ଖାଲି, ଖାଲି);
	debug("%s", s);
	ମୁକ୍ତ(s);
}

ଅକ୍ଷର *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc ସନ୍ଦେଶ = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	ସଂରଚନା sshbuf *b;
	ଅକ୍ଷର *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯଦି (major_status != ଖାଲି)
		*major_status = ctxt->major;
	ଯଦି (minor_status != ଖାଲି)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	କର {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &ସନ୍ଦେଶ);

		ଯଦି ((r = sshbuf_put(b, ସନ୍ଦେଶ.ମୂଲ୍ୟ, ସନ୍ଦେଶ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &ସନ୍ଦେଶ);
	} ଯେତେବେଳେ (ctx != 0);

	/* The mechanism specific error */
	କର {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &ସନ୍ଦେଶ);

		ଯଦି ((r = sshbuf_put(b, ସନ୍ଦେଶ.ମୂଲ୍ୟ, ସନ୍ଦେଶ.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &ସନ୍ଦେଶ);
	} ଯେତେବେଳେ (ctx != 0);

	ଯଦି ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ଅଚଳ ଅକ୍ଷର *)sshbuf_ptr(b));
	sshbuf_free(b);
	ଫେରନ୍ତୁ (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
ଶୂନ୍ୟ
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, ଆକାର (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
ଶୂନ୍ୟ
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	ଯଦି ((*ctx) == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	ଯଦି ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	ଯଦି ((*ctx)->oid != GSS_C_NO_OID) {
		ମୁକ୍ତ((*ctx)->oid->elements);
		ମୁକ୍ତ((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	ଯଦି ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	ଯଦି ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	ଯଦି ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	ମୁକ୍ତ(*ctx);
	*ctx = ଖାଲି;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, ପୂର୍ଣ୍ଣସଂଖ୍ୟା deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା deleg_flag = 0;

	ଯଦି (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ଖାଲି, recv_tok, ଖାଲି, send_tok, flags, ଖାଲି);

	ଯଦି (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ଫେରନ୍ତୁ (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ଅଚଳ ଅକ୍ଷର *host)
{
	gss_buffer_desc gssbuf;
	ଅକ୍ଷର *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.ମୂଲ୍ୟ = val;
	gssbuf.length = strlen(gssbuf.ମୂଲ୍ୟ);

	ଯଦି ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	ମୁକ୍ତ(gssbuf.ମୂଲ୍ୟ);
	ଫେରନ୍ତୁ (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	ଯଦି ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	ଫେରନ୍ତୁ (ctx->major);
}

ଶୂନ୍ୟ
ssh_gssapi_buildmic(ସଂରଚନା sshbuf *b, ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *service,
    ଅଚଳ ଅକ୍ଷର *context, ଅଚଳ ସଂରଚନା sshbuf *session_id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	sshbuf_reset(b);
	ଯଦି ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ଅଚଳ ଅକ୍ଷର *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (ଶୂନ୍ୟ *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	ଯଦି (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		ଫେରନ୍ତୁ 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	ଯଦି (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    ଖାଲି);
		gss_release_buffer(&minor, &token);
		ଯଦି ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	ଯଦି (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ଫେରନ୍ତୁ (!GSS_ERROR(major));
}

#endif /* GSSAPI */
