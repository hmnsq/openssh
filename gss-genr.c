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

#അന്തര്ഭാവ "includes.h"

#ifdef GSSAPI

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh2.h"

#അന്തര്ഭാവ "ssh-gss.h"

/* sshbuf_get for gss_buffer_desc */
പൂർണ്ണസംഖ്യ
ssh_gssapi_get_buffer_desc(ഘടന sshbuf *b, gss_buffer_desc *g)
{
	പൂർണ്ണസംഖ്യ r;
	u_char *p;
	size_t len;

	എങ്കിൽ ((r = sshbuf_get_string(b, &p, &len)) != 0)
		തിരികെ r;
	g->മൂല്യം = p;
	g->length = len;
	തിരികെ 0;
}

/* Check that the OID in a data stream matches that in the context */
പൂർണ്ണസംഖ്യ
ssh_gssapi_check_oid(Gssctxt *ctx, ശൂന്യം *data, size_t len)
{
	തിരികെ (ctx != ശൂന്യ && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
ശൂന്യം
ssh_gssapi_set_oid_data(Gssctxt *ctx, ശൂന്യം *data, size_t len)
{
	എങ്കിൽ (ctx->oid != GSS_C_NO_OID) {
		സ്വതന്ത്രം(ctx->oid->elements);
		സ്വതന്ത്രം(ctx->oid);
	}
	ctx->oid = xcalloc(1, വലുപ്പം(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
ശൂന്യം
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
ശൂന്യം
ssh_gssapi_error(Gssctxt *ctxt)
{
	അക്ഷരം *s;

	s = ssh_gssapi_last_error(ctxt, ശൂന്യ, ശൂന്യ);
	debug("%s", s);
	സ്വതന്ത്രം(s);
}

അക്ഷരം *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc സന്ദേശം = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	ഘടന sshbuf *b;
	അക്ഷരം *ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	എങ്കിൽ (major_status != ശൂന്യ)
		*major_status = ctxt->major;
	എങ്കിൽ (minor_status != ശൂന്യ)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	ചെയ്യുക {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &സന്ദേശം);

		എങ്കിൽ ((r = sshbuf_put(b, സന്ദേശം.മൂല്യം, സന്ദേശം.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble GSS_CODE");

		gss_release_buffer(&lmin, &സന്ദേശം);
	} ആകുമ്പോൾ (ctx != 0);

	/* The mechanism specific error */
	ചെയ്യുക {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &സന്ദേശം);

		എങ്കിൽ ((r = sshbuf_put(b, സന്ദേശം.മൂല്യം, സന്ദേശം.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal_fr(r, "assemble MECH_CODE");

		gss_release_buffer(&lmin, &സന്ദേശം);
	} ആകുമ്പോൾ (ctx != 0);

	എങ്കിൽ ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal_fr(r, "assemble newline");
	ret = xstrdup((സ്ഥിരം അക്ഷരം *)sshbuf_ptr(b));
	sshbuf_free(b);
	തിരികെ (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
ശൂന്യം
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, വലുപ്പം (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
ശൂന്യം
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	എങ്കിൽ ((*ctx) == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	എങ്കിൽ ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	എങ്കിൽ ((*ctx)->oid != GSS_C_NO_OID) {
		സ്വതന്ത്രം((*ctx)->oid->elements);
		സ്വതന്ത്രം((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	എങ്കിൽ ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	എങ്കിൽ ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	എങ്കിൽ ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	സ്വതന്ത്രം(*ctx);
	*ctx = ശൂന്യ;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, പൂർണ്ണസംഖ്യ deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	പൂർണ്ണസംഖ്യ deleg_flag = 0;

	എങ്കിൽ (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, ശൂന്യ, recv_tok, ശൂന്യ, send_tok, flags, ശൂന്യ);

	എങ്കിൽ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	തിരികെ (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, സ്ഥിരം അക്ഷരം *host)
{
	gss_buffer_desc gssbuf;
	അക്ഷരം *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.മൂല്യം = val;
	gssbuf.length = strlen(gssbuf.മൂല്യം);

	എങ്കിൽ ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	സ്വതന്ത്രം(gssbuf.മൂല്യം);
	തിരികെ (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	എങ്കിൽ ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	തിരികെ (ctx->major);
}

ശൂന്യം
ssh_gssapi_buildmic(ഘടന sshbuf *b, സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *service,
    സ്ഥിരം അക്ഷരം *context, സ്ഥിരം ഘടന sshbuf *session_id)
{
	പൂർണ്ണസംഖ്യ r;

	sshbuf_reset(b);
	എങ്കിൽ ((r = sshbuf_put_stringb(b, session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal_fr(r, "assemble buildmic");
}

പൂർണ്ണസംഖ്യ
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, സ്ഥിരം അക്ഷരം *host)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (ശൂന്യം *)"\x2B\x06\x01\x05\x05\x02"};

	/* RFC 4462 says we MUST NOT do SPNEGO */
	എങ്കിൽ (oid->length == spnego_oid.length &&
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		തിരികെ 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);
	എങ്കിൽ (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token,
		    ശൂന്യ);
		gss_release_buffer(&minor, &token);
		എങ്കിൽ ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	എങ്കിൽ (GSS_ERROR(major))
		ssh_gssapi_delete_ctx(ctx);

	തിരികെ (!GSS_ERROR(major));
}

#endif /* GSSAPI */
