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

#অন্তর্ভাব "includes.h"

#ifdef GSSAPI

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh2.h"

#অন্তর্ভাব "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
পূর্ণসংখ্যা
ssh_gssapi_get_বাফার_desc(কাঠামো sshbuf *b, gss_বাফার_desc *g)
{
	পূর্ণসংখ্যা r;
	u_char *p;
	আকার_t len;

	যদি ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ফেরত r;
	g->মান = p;
	g->দৈর্ঘ্য = len;
	ফেরত 0;
}

/* Check that the OID in a data stream matches that in the context */
পূর্ণসংখ্যা
ssh_gssapi_check_oid(Gssctxt *ctx, শূন্য *তথ্য, আকার_t len)
{
	ফেরত (ctx != ফাঁকা && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->দৈর্ঘ্য == len &&
	    memcmp(ctx->oid->elements, তথ্য, len) == 0);
}

/* Set the contexts OID from a data stream */
শূন্য
ssh_gssapi_set_oid_তথ্য(Gssctxt *ctx, শূন্য *তথ্য, আকার_t len)
{
	যদি (ctx->oid != GSS_C_NO_OID) {
		মুক্ত(ctx->oid->elements);
		মুক্ত(ctx->oid);
	}
	ctx->oid = xcalloc(1, আকার(gss_OID_desc));
	ctx->oid->দৈর্ঘ্য = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, তথ্য, len);
}

/* Set the contexts OID */
শূন্য
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_তথ্য(ctx, oid->elements, oid->দৈর্ঘ্য);
}

/* All this effort to report an error ... */
শূন্য
ssh_gssapi_error(Gssctxt *ctxt)
{
	অক্ষর *s;

	s = ssh_gssapi_last_error(ctxt, ফাঁকা, ফাঁকা);
	debug("%s", s);
	মুক্ত(s);
}

অক্ষর *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_বাফার_desc বার্তা = GSS_C_EMPTY_বাফার;
	OM_uint32 ctx;
	কাঠামো sshbuf *b;
	অক্ষর *ret;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	যদি (major_status != ফাঁকা)
		*major_status = ctxt->major;
	যদি (minor_status != ফাঁকা)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	করো {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &বার্তা);

		যদি ((r = sshbuf_put(b, বার্তা.মান, বার্তা.দৈর্ঘ্য)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_বাফার(&lmin, &বার্তা);
	} যখন (ctx != 0);

	/* The mechanism specific error */
	করো {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &বার্তা);

		যদি ((r = sshbuf_put(b, বার্তা.মান, বার্তা.দৈর্ঘ্য)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_বাফার(&lmin, &বার্তা);
	} যখন (ctx != 0);

	যদি ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ধ্রুবক অক্ষর *)sshbuf_ptr(b));
	sshbuf_free(b);
	ফেরত (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
শূন্য
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, আকার (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
শূন্য
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	যদি ((*ctx) == ফাঁকা)
		ফেরত;
	যদি ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_বাফার);
	যদি ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	যদি ((*ctx)->oid != GSS_C_NO_OID) {
		মুক্ত((*ctx)->oid->elements);
		মুক্ত((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	যদি ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	যদি ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	যদি ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	মুক্ত(*ctx);
	*ctx = ফাঁকা;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, পূর্ণসংখ্যা deleg_creds, gss_বাফার_desc *recv_tok,
    gss_বাফার_desc* send_tok, OM_uint32 *flags)
{
	পূর্ণসংখ্যা deleg_flag = 0;

	যদি (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ফাঁকা, recv_tok, ফাঁকা, send_tok, flags, ফাঁকা);

	যদি (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ফেরত (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ধ্রুবক অক্ষর *host)
{
	gss_বাফার_desc gssbuf;
	অক্ষর *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.মান = val;
	gssbuf.দৈর্ঘ্য = strlen(gssbuf.মান);

	যদি ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	মুক্ত(gssbuf.মান);
	ফেরত (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_বাফার_t বাফার, gss_বাফার_t hash)
{
	যদি ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, বাফার, hash)))
		ssh_gssapi_error(ctx);

	ফেরত (ctx->major);
}

শূন্য
ssh_gssapi_buildmic(কাঠামো sshbuf *b, ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *service,
    ধ্রুবক অক্ষর *context, ধ্রুবক কাঠামো sshbuf *session_id)
{
	পূর্ণসংখ্যা r;

	sshbuf_reset(b);
	যদি ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

পূর্ণসংখ্যা
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ধ্রুবক অক্ষর *host)
{
	gss_বাফার_desc token = GSS_C_EMPTY_বাফার;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (শূন্য *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	যদি (oid->দৈর্ঘ্য == spnego_oid.দৈর্ঘ্য &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->দৈর্ঘ্য) == 0))
		ফেরত 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	যদি (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_বাফার, &token,
		    ফাঁকা);
		gss_release_বাফার(&minor, &token);
		যদি ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_বাফার);
	}

	যদি (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ফেরত (!GSS_ERROR(major));
}

#endif /* GSSAPI */
