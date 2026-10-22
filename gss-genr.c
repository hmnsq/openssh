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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే GSSAPI

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh2.h"

#అన్తర్భావ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
పూర్ణాంకం
ssh_gssapi_get_బఫరు_desc(నిర్మాణం sshbuf *b, gss_బఫరు_desc *g)
{
	పూర్ణాంకం r;
	u_char *p;
	కొలత_t len;

	ఒకవేళ ((r = sshbuf_get_string(b, &p, &len)) != 0)
		తిరిగి r;
	g->విలువ = p;
	g->నిడివి = len;
	తిరిగి 0;
}

/* Check that the OID in a data stream matches that in the context */
పూర్ణాంకం
ssh_gssapi_check_oid(Gssctxt *ctx, శూన్య *దత్తాంశం, కొలత_t len)
{
	తిరిగి (ctx != ఖాళీ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->నిడివి == len &&
	    memcmp(ctx->oid->elements, దత్తాంశం, len) == 0);
}

/* Set the contexts OID from a data stream */
శూన్య
ssh_gssapi_సమితి_oid_దత్తాంశం(Gssctxt *ctx, శూన్య *దత్తాంశం, కొలత_t len)
{
	ఒకవేళ (ctx->oid != GSS_C_NO_OID) {
		విడుదల(ctx->oid->elements);
		విడుదల(ctx->oid);
	}
	ctx->oid = xcalloc(1, పరిమాణం(gss_OID_desc));
	ctx->oid->నిడివి = len;
	ctx->oid->elements = xmalloc(len);
	జ్ఞాపకం_నకలు(ctx->oid->elements, దత్తాంశం, len);
}

/* Set the contexts OID */
శూన్య
ssh_gssapi_సమితి_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_సమితి_oid_దత్తాంశం(ctx, oid->elements, oid->నిడివి);
}

/* All this effort to report an error ... */
శూన్య
ssh_gssapi_error(Gssctxt *ctxt)
{
	అక్షరం *s;

	s = ssh_gssapi_చివరి_error(ctxt, ఖాళీ, ఖాళీ);
	debug("%s", s);
	విడుదల(s);
}

అక్షరం *
ssh_gssapi_చివరి_error(Gssctxt *ctxt, OM_uint32 *major_స్థితి,
    OM_uint32 *minor_స్థితి)
{
	OM_uint32 lmin;
	gss_బఫరు_desc సందేశం = GSS_C_ఖాళీలు_బఫరు;
	OM_uint32 ctx;
	నిర్మాణం sshbuf *b;
	అక్షరం *ret;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	ఒకవేళ (major_స్థితి != ఖాళీ)
		*major_స్థితి = ctxt->major;
	ఒకవేళ (minor_స్థితి != ఖాళీ)
		*minor_స్థితి = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	చేయి {
		gss_display_స్థితి(&lmin, ctxt->major,
		    GSS_C_GSS_సంకేతం, ctxt->oid, &ctx, &సందేశం);

		ఒకవేళ ((r = sshbuf_put(b, సందేశం.విలువ, సందేశం.నిడివి)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_బఫరు(&lmin, &సందేశం);
	} అయితే (ctx != 0);

	/* The mechanism specific error */
	చేయి {
		gss_display_స్థితి(&lmin, ctxt->minor,
		    GSS_C_MECH_సంకేతం, ctxt->oid, &ctx, &సందేశం);

		ఒకవేళ ((r = sshbuf_put(b, సందేశం.విలువ, సందేశం.నిడివి)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_బఫరు(&lmin, &సందేశం);
	} అయితే (ctx != 0);

	ఒకవేళ ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((స్థిరరాశి అక్షరం *)sshbuf_ptr(b));
	sshbuf_free(b);
	తిరిగి (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
శూన్య
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, పరిమాణం (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
శూన్య
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	ఒకవేళ ((*ctx) == ఖాళీ)
		తిరిగి;
	ఒకవేళ ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_బఫరు);
	ఒకవేళ ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	ఒకవేళ ((*ctx)->oid != GSS_C_NO_OID) {
		విడుదల((*ctx)->oid->elements);
		విడుదల((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	ఒకవేళ ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	ఒకవేళ ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	ఒకవేళ ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	విడుదల(*ctx);
	*ctx = ఖాళీ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, పూర్ణాంకం deleg_creds, gss_బఫరు_desc *recv_tok,
    gss_బఫరు_desc* send_tok, OM_uint32 *flags)
{
	పూర్ణాంకం deleg_flag = 0;

	ఒకవేళ (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ఖాళీ, recv_tok, ఖాళీ, send_tok, flags, ఖాళీ);

	ఒకవేళ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	తిరిగి (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, స్థిరరాశి అక్షరం *host)
{
	gss_బఫరు_desc gssbuf;
	అక్షరం *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.విలువ = val;
	gssbuf.నిడివి = అక్షరశ్రేణి_పొడవు(gssbuf.విలువ);

	ఒకవేళ ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	విడుదల(gssbuf.విలువ);
	తిరిగి (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_బఫరు_t బఫరు, gss_బఫరు_t hash)
{
	ఒకవేళ ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, బఫరు, hash)))
		ssh_gssapi_error(ctx);

	తిరిగి (ctx->major);
}

శూన్య
ssh_gssapi_buildmic(నిర్మాణం sshbuf *b, స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *service,
    స్థిరరాశి అక్షరం *context, స్థిరరాశి నిర్మాణం sshbuf *session_id)
{
	పూర్ణాంకం r;

	sshbuf_reset(b);
	ఒకవేళ ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

పూర్ణాంకం
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, స్థిరరాశి అక్షరం *host)
{
	gss_బఫరు_desc token = GSS_C_ఖాళీలు_బఫరు;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (శూన్య *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	ఒకవేళ (oid->నిడివి == spnego_oid.నిడివి &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->నిడివి) == 0))
		తిరిగి 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_సమితి_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	ఒకవేళ (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_బఫరు, &token,
		    ఖాళీ);
		gss_release_బఫరు(&minor, &token);
		ఒకవేళ ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_బఫరు);
	}

	ఒకవేళ (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	తిరిగి (!GSS_ERROR(major));
}

#అయితే_ముగింపు /* GSSAPI */
