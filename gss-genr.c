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

#অন্তর্ভাৱ "includes.h"

#ifdef GSSAPI

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "ssh2.h"

#অন্তর্ভাৱ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
পূর্ণাঙ্ক
ssh_gssapi_get_buffer_desc(সংরচনা sshbuf *b, gss_buffer_desc *g)
{
	পূর্ণাঙ্ক r;
	u_char *p;
	size_t len;

	যদি ((r = sshbuf_get_string(b, &p, &len)) != 0)
		ঘূৰাই r;
	g->মান = p;
	g->length = len;
	ঘূৰাই 0;
}

/* Check that the OID in a data stream matches that in the context */
পূর্ণাঙ্ক
ssh_gssapi_check_oid(Gssctxt *ctx, শূন্য *data, size_t len)
{
	ঘূৰাই (ctx != রিক্ত && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
শূন্য
ssh_gssapi_set_oid_data(Gssctxt *ctx, শূন্য *data, size_t len)
{
	যদি (ctx->oid != GSS_C_NO_OID) {
		মুক্ত(ctx->oid->elements);
		মুক্ত(ctx->oid);
	}
	ctx->oid = xcalloc(1, পরিমাণ(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
শূন্য
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
শূন্য
ssh_gssapi_error(Gssctxt *ctxt)
{
	ৱর্ণ *s;

	s = ssh_gssapi_last_error(ctxt, রিক্ত, রিক্ত);
	debug("%s", s);
	মুক্ত(s);
}

ৱর্ণ *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc বাৰ্তা = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	সংরচনা sshbuf *b;
	ৱর্ণ *ret;
	পূর্ণাঙ্ক r;

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	যদি (major_status != রিক্ত)
		*major_status = ctxt->major;
	যদি (minor_status != রিক্ত)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	কৰা {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &বাৰ্তা);

		যদি ((r = sshbuf_put(b, বাৰ্তা.মান, বাৰ্তা.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &বাৰ্তা);
	} যেতিয়ালৈ (ctx != 0);

	/* The mechanism specific error */
	কৰা {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &বাৰ্তা);

		যদি ((r = sshbuf_put(b, বাৰ্তা.মান, বাৰ্তা.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &বাৰ্তা);
	} যেতিয়ালৈ (ctx != 0);

	যদি ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ধ্রুৱ ৱর্ণ *)sshbuf_ptr(b));
	sshbuf_free(b);
	ঘূৰাই (ret);
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
	*ctx = xcalloc(1, পরিমাণ (Gssctxt));
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

	যদি ((*ctx) == রিক্ত)
		ঘূৰাই;
	যদি ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
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
	*ctx = রিক্ত;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, পূর্ণাঙ্ক deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	পূর্ণাঙ্ক deleg_flag = 0;

	যদি (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, রিক্ত, recv_tok, রিক্ত, send_tok, flags, রিক্ত);

	যদি (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ঘূৰাই (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ধ্রুৱ ৱর্ণ *host)
{
	gss_buffer_desc gssbuf;
	ৱর্ণ *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.মান = val;
	gssbuf.length = strlen(gssbuf.মান);

	যদি ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	মুক্ত(gssbuf.মান);
	ঘূৰাই (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	যদি ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	ঘূৰাই (ctx->major);
}

শূন্য
ssh_gssapi_buildmic(সংরচনা sshbuf *b, ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *service,
    ধ্রুৱ ৱর্ণ *context, ধ্রুৱ সংরচনা sshbuf *session_id)
{
	পূর্ণাঙ্ক r;

	sshbuf_reset(b);
	যদি ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বাৰ্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

পূর্ণাঙ্ক
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ধ্রুৱ ৱর্ণ *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (শূন্য *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	যদি (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		ঘূৰাই 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	যদি (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    রিক্ত);
		gss_release_buffer(&minor, &token);
		যদি ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	যদি (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	ঘূৰাই (!GSS_ERROR(major));
}

#endif /* GSSAPI */
