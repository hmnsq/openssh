/* $OpenBSD: gss-serv.c,v 1.40 2026/10/07 09:00:11 robert Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
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
#അന്തര്ഭാവ <sys/param.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "session.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"

#അന്തര്ഭാവ "ssh-gss.h"

ബാഹ്യ ServerOptions options;

സ്ഥിതം ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER,
    GSS_C_NO_CREDENTIAL, ശൂന്യ, {ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ശൂന്യ, ശൂന്യ, {0, ശൂന്യ}, ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ};

#ifdef KRB5
ബാഹ്യ ssh_gssapi_mech gssapi_kerberos_mech;
#endif

ssh_gssapi_mech* supported_mechs[]= {
#ifdef KRB5
	&gssapi_kerberos_mech,
#endif
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
സ്ഥിതം gss_OID_set supported_oids;

ശൂന്യം
ssh_gssapi_prepare_supported_oids(ശൂന്യം)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, പൂർണ്ണസംഖ്യ *present)
{
	എങ്കിൽ (supported_oids == ശൂന്യ)
		ssh_gssapi_prepare_supported_oids();
	തിരികെ gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
സ്ഥിതം OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	അക്ഷരം lname[NI_MAXHOST];
	gss_OID_set oidset;

	എങ്കിൽ (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		എങ്കിൽ (gethostname(lname, വലുപ്പം(lname))) {
			gss_release_oid_set(&status, &oidset);
			തിരികെ (-1);
		}

		എങ്കിൽ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			തിരികെ (ctx->major);
		}

		എങ്കിൽ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ശൂന്യ, ശൂന്യ)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		തിരികെ (ctx->major);
	} അല്ലെങ്കിൽ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	തിരികെ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	എങ്കിൽ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	തിരികെ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
ശൂന്യം
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	പൂർണ്ണസംഖ്യ i = 0;
	OM_uint32 min_status;
	പൂർണ്ണസംഖ്യ present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	ആകുമ്പോൾ (supported_mechs[i]->name != ശൂന്യ) {
		എങ്കിൽ (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		എങ്കിൽ (present)
			gss_add_oid_set_member(&min_status,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_set(&min_status, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *recv_tok,
    gss_buffer_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 status;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, ശൂന്യ, &ctx->client_creds);

	എങ്കിൽ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	എങ്കിൽ (ctx->client_creds)
		debug("Received some client credentials");
	അല്ലെങ്കിൽ
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	എങ്കിൽ (((flags == ശൂന്യ) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		എങ്കിൽ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	തിരികെ (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
സ്ഥിതം OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_buffer_t ename, gss_buffer_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->മൂല്യം;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	എങ്കിൽ (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		തിരികെ GSS_S_FAILURE;

	/*
	 * Extract the OID, and check it. Here GSSAPI breaks with tradition
	 * and does use the OID type and length bytes. To confuse things
	 * there are two lengths - the first including these, and the
	 * second without.
	 */

	oidl = get_u16(tok+2); /* length including next two bytes */
	oidl = oidl-2; /* turn it into the _real_ length of the variable OID */

	/*
	 * Check the BER encoding for correct type and length, that the
	 * string is long enough and that the OID matches that in our context
	 */
	എങ്കിൽ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		തിരികെ GSS_S_FAILURE;

	offset = oidl+6;

	എങ്കിൽ (ename->length < offset+4)
		തിരികെ GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	എങ്കിൽ (UINT_MAX - offset < name->length)
		തിരികെ GSS_S_FAILURE;
	എങ്കിൽ (ename->length < offset+name->length)
		തിരികെ GSS_S_FAILURE;

	name->മൂല്യം = xmalloc(name->length+1);
	memcpy(name->മൂല്യം, tok+offset, name->length);
	((അക്ഷരം *)name->മൂല്യം)[name->length] = 0;

	തിരികെ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	പൂർണ്ണസംഖ്യ i = 0;

	gss_buffer_desc ename;

	client->userok = 0;
	client->mech = ശൂന്യ;

	ആകുമ്പോൾ (supported_mechs[i]->name != ശൂന്യ) {
		എങ്കിൽ (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	എങ്കിൽ (client->mech == ശൂന്യ)
		തിരികെ GSS_S_FAILURE;

	എങ്കിൽ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ശൂന്യ))) {
		ssh_gssapi_error(ctx);
		തിരികെ (ctx->major);
	}

	എങ്കിൽ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		തിരികെ (ctx->major);
	}

	എങ്കിൽ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		തിരികെ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	തിരികെ (ctx->major);
}

/* As user - called on fatal/exit */
ശൂന്യം
ssh_gssapi_cleanup_creds(ശൂന്യം)
{
	എങ്കിൽ (gssapi_client.store.filename != ശൂന്യ) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
ശൂന്യം
ssh_gssapi_storecreds(ശൂന്യം)
{
	എങ്കിൽ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		തിരികെ;
	}

	എങ്കിൽ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		തിരികെ;
	}

	എങ്കിൽ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} അല്ലെങ്കിൽ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
ശൂന്യം
ssh_gssapi_do_child(അക്ഷരം ***envp, u_int *envsizep)
{

	എങ്കിൽ (gssapi_client.store.envvar != ശൂന്യ &&
	    gssapi_client.store.envval != ശൂന്യ) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

ശൂന്യം
ssh_gssapi_cleanup_global_client(ശൂന്യം)
{
	OM_uint32 lmin;

	gss_release_buffer(&lmin, &gssapi_client.displayname);
	gss_release_buffer(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, വലുപ്പം(ssh_gssapi_client));
}

/* Privileged */
പൂർണ്ണസംഖ്യ
ssh_gssapi_userok(അക്ഷരം *user)
{
	എങ്കിൽ (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.മൂല്യം == ശൂന്യ) {
		debug("No suitable client data");
		തിരികെ 0;
	}
	എങ്കിൽ (gssapi_client.mech && gssapi_client.mech->userok)
		എങ്കിൽ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			തിരികെ 1;
		} അല്ലെങ്കിൽ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			തിരികെ 0;
		}
	അല്ലെങ്കിൽ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	തിരികെ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ശൂന്യ);

	തിരികെ (ctx->major);
}

/* Privileged */
സ്ഥിരം അക്ഷരം *ssh_gssapi_displayname(ശൂന്യം)
{
	എങ്കിൽ (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.മൂല്യം == ശൂന്യ)
		തിരികെ ശൂന്യ;
	തിരികെ (അക്ഷരം *)gssapi_client.displayname.മൂല്യം;
}

#endif
