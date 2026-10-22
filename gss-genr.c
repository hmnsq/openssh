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

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् GSSAPI

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh2.h"

#अन्तर्भाव "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
पूर्णाङ्क
ssh_gssapi_get_बफर_desc(संरचना sshbuf *b, gss_बफर_desc *g)
{
	पूर्णाङ्क r;
	u_char *p;
	आकार_t len;

	यदि ((r = sshbuf_get_string(b, &p, &len)) != 0)
		प्रत्यागम r;
	g->मानम् = p;
	g->दीर्घता = len;
	प्रत्यागम 0;
}

/* Check that the OID in a data stream matches that in the context */
पूर्णाङ्क
ssh_gssapi_check_oid(Gssctxt *ctx, शून्य *दत्त, आकार_t len)
{
	प्रत्यागम (ctx != रिक्त && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->दीर्घता == len &&
	    memcmp(ctx->oid->elements, दत्त, len) == 0);
}

/* Set the contexts OID from a data stream */
शून्य
ssh_gssapi_समुच्चयः_oid_दत्त(Gssctxt *ctx, शून्य *दत्त, आकार_t len)
{
	यदि (ctx->oid != GSS_C_NO_OID) {
		मुक्त(ctx->oid->elements);
		मुक्त(ctx->oid);
	}
	ctx->oid = xcalloc(1, परिमाण(gss_OID_desc));
	ctx->oid->दीर्घता = len;
	ctx->oid->elements = xmalloc(len);
	स्मृतिं_प्रतिलिख(ctx->oid->elements, दत्त, len);
}

/* Set the contexts OID */
शून्य
ssh_gssapi_समुच्चयः_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_समुच्चयः_oid_दत्त(ctx, oid->elements, oid->दीर्घता);
}

/* All this effort to report an error ... */
शून्य
ssh_gssapi_error(Gssctxt *ctxt)
{
	वर्ण *s;

	s = ssh_gssapi_चरमः_error(ctxt, रिक्त, रिक्त);
	debug("%s", s);
	मुक्त(s);
}

वर्ण *
ssh_gssapi_चरमः_error(Gssctxt *ctxt, OM_uint32 *major_स्थितिः,
    OM_uint32 *minor_स्थितिः)
{
	OM_uint32 lmin;
	gss_बफर_desc सन्देशः = GSS_C_रिक्तानि_बफर;
	OM_uint32 ctx;
	संरचना sshbuf *b;
	वर्ण *ret;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यदि (major_स्थितिः != रिक्त)
		*major_स्थितिः = ctxt->major;
	यदि (minor_स्थितिः != रिक्त)
		*minor_स्थितिः = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	कुरु {
		gss_display_स्थितिः(&lmin, ctxt->major,
		    GSS_C_GSS_संहिता, ctxt->oid, &ctx, &सन्देशः);

		यदि ((r = sshbuf_put(b, सन्देशः.मानम्, सन्देशः.दीर्घता)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_बफर(&lmin, &सन्देशः);
	} यावत् (ctx != 0);

	/* The mechanism specific error */
	कुरु {
		gss_display_स्थितिः(&lmin, ctxt->minor,
		    GSS_C_MECH_संहिता, ctxt->oid, &ctx, &सन्देशः);

		यदि ((r = sshbuf_put(b, सन्देशः.मानम्, सन्देशः.दीर्घता)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_बफर(&lmin, &सन्देशः);
	} यावत् (ctx != 0);

	यदि ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((ध्रुव वर्ण *)sshbuf_ptr(b));
	sshbuf_free(b);
	प्रत्यागम (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
शून्य
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, परिमाण (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
शून्य
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	यदि ((*ctx) == रिक्त)
		प्रत्यागम;
	यदि ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_बफर);
	यदि ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	यदि ((*ctx)->oid != GSS_C_NO_OID) {
		मुक्त((*ctx)->oid->elements);
		मुक्त((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	यदि ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	यदि ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	यदि ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	मुक्त(*ctx);
	*ctx = रिक्त;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, पूर्णाङ्क deleg_creds, gss_बफर_desc *recv_tok,
    gss_बफर_desc* send_tok, OM_uint32 *flags)
{
	पूर्णाङ्क deleg_flag = 0;

	यदि (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, रिक्त, recv_tok, रिक्त, send_tok, flags, रिक्त);

	यदि (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	प्रत्यागम (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, ध्रुव वर्ण *host)
{
	gss_बफर_desc gssbuf;
	वर्ण *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.मानम् = val;
	gssbuf.दीर्घता = वाक्यदैर्घ्यम्(gssbuf.मानम्);

	यदि ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	मुक्त(gssbuf.मानम्);
	प्रत्यागम (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_बफर_t बफर, gss_बफर_t hash)
{
	यदि ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, बफर, hash)))
		ssh_gssapi_error(ctx);

	प्रत्यागम (ctx->major);
}

शून्य
ssh_gssapi_buildmic(संरचना sshbuf *b, ध्रुव वर्ण *user, ध्रुव वर्ण *service,
    ध्रुव वर्ण *context, ध्रुव संरचना sshbuf *session_id)
{
	पूर्णाङ्क r;

	sshbuf_reset(b);
	यदि ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

पूर्णाङ्क
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, ध्रुव वर्ण *host)
{
	gss_बफर_desc token = GSS_C_रिक्तानि_बफर;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (शून्य *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	यदि (oid->दीर्घता == spnego_oid.दीर्घता &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->दीर्घता) == 0))
		प्रत्यागम 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_समुच्चयः_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	यदि (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_बफर, &token,
		    रिक्त);
		gss_release_बफर(&minor, &token);
		यदि ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_बफर);
	}

	यदि (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	प्रत्यागम (!GSS_ERROR(major));
}

#यदि_अन्तः /* GSSAPI */
