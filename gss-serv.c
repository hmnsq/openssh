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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef GSSAPI

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/param.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"

#ಅನ್ತರ್ಭಾವ "ssh-gss.h"

ಬಾಹ್ಯ ServerOptions options;

ಸ್ಥಿರ ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER,
    GSS_C_NO_CREDENTIAL, ರಿಕ್ತ, {ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ರಿಕ್ತ, ರಿಕ್ತ, {0, ರಿಕ್ತ}, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ};

#ifdef KRB5
ಬಾಹ್ಯ ssh_gssapi_mech gssapi_kerberos_mech;
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
ಸ್ಥಿರ gss_OID_set supported_oids;

ಶೂನ್ಯ
ssh_gssapi_prepare_supported_oids(ಶೂನ್ಯ)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, ಪೂರ್ಣಾಙ್ಕ *present)
{
	ಯದಿ (supported_oids == ರಿಕ್ತ)
		ssh_gssapi_prepare_supported_oids();
	ಪ್ರತ್ಯಾಗಮ gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
ಸ್ಥಿರ OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	ವರ್ಣ lname[NI_MAXHOST];
	gss_OID_set oidset;

	ಯದಿ (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		ಯದಿ (gethostname(lname, ಪರಿಮಾಣ(lname))) {
			gss_release_oid_set(&status, &oidset);
			ಪ್ರತ್ಯಾಗಮ (-1);
		}

		ಯದಿ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			ಪ್ರತ್ಯಾಗಮ (ctx->major);
		}

		ಯದಿ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ರಿಕ್ತ, ರಿಕ್ತ)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		ಪ್ರತ್ಯಾಗಮ (ctx->major);
	} ಅನ್ಯಥಾ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ಪ್ರತ್ಯಾಗಮ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ಯದಿ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	ಪ್ರತ್ಯಾಗಮ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
ಶೂನ್ಯ
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	ಪೂರ್ಣಾಙ್ಕ i = 0;
	OM_uint32 min_status;
	ಪೂರ್ಣಾಙ್ಕ present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	ಯಾವತ್ (supported_mechs[i]->name != ರಿಕ್ತ) {
		ಯದಿ (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ಯದಿ (present)
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
	    send_tok, flags, ರಿಕ್ತ, &ctx->client_creds);

	ಯದಿ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ಯದಿ (ctx->client_creds)
		debug("Received some client credentials");
	ಅನ್ಯಥಾ
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ಯದಿ (((flags == ರಿಕ್ತ) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ಯದಿ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ಪ್ರತ್ಯಾಗಮ (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
ಸ್ಥಿರ OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_buffer_t ename, gss_buffer_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->ಮೌಲ್ಯ;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	ಯದಿ (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;

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
	ಯದಿ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;

	offset = oidl+6;

	ಯದಿ (ename->length < offset+4)
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	ಯದಿ (UINT_MAX - offset < name->length)
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;
	ಯದಿ (ename->length < offset+name->length)
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;

	name->ಮೌಲ್ಯ = xmalloc(name->length+1);
	memcpy(name->ಮೌಲ್ಯ, tok+offset, name->length);
	((ವರ್ಣ *)name->ಮೌಲ್ಯ)[name->length] = 0;

	ಪ್ರತ್ಯಾಗಮ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	ಪೂರ್ಣಾಙ್ಕ i = 0;

	gss_buffer_desc ename;

	client->userok = 0;
	client->mech = ರಿಕ್ತ;

	ಯಾವತ್ (supported_mechs[i]->name != ರಿಕ್ತ) {
		ಯದಿ (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ಯದಿ (client->mech == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ GSS_S_FAILURE;

	ಯದಿ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ರಿಕ್ತ))) {
		ssh_gssapi_error(ctx);
		ಪ್ರತ್ಯಾಗಮ (ctx->major);
	}

	ಯದಿ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ಪ್ರತ್ಯಾಗಮ (ctx->major);
	}

	ಯದಿ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ಪ್ರತ್ಯಾಗಮ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ಪ್ರತ್ಯಾಗಮ (ctx->major);
}

/* As user - called on fatal/exit */
ಶೂನ್ಯ
ssh_gssapi_cleanup_creds(ಶೂನ್ಯ)
{
	ಯದಿ (gssapi_client.store.filename != ರಿಕ್ತ) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
ಶೂನ್ಯ
ssh_gssapi_storecreds(ಶೂನ್ಯ)
{
	ಯದಿ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ಅನ್ಯಥಾ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
ಶೂನ್ಯ
ssh_gssapi_do_child(ವರ್ಣ ***envp, u_int *envsizep)
{

	ಯದಿ (gssapi_client.store.envvar != ರಿಕ್ತ &&
	    gssapi_client.store.envval != ರಿಕ್ತ) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

ಶೂನ್ಯ
ssh_gssapi_cleanup_global_client(ಶೂನ್ಯ)
{
	OM_uint32 lmin;

	gss_release_buffer(&lmin, &gssapi_client.displayname);
	gss_release_buffer(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, ಪರಿಮಾಣ(ssh_gssapi_client));
}

/* Privileged */
ಪೂರ್ಣಾಙ್ಕ
ssh_gssapi_userok(ವರ್ಣ *user)
{
	ಯದಿ (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.ಮೌಲ್ಯ == ರಿಕ್ತ) {
		debug("No suitable client data");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (gssapi_client.mech && gssapi_client.mech->userok)
		ಯದಿ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ಪ್ರತ್ಯಾಗಮ 1;
		} ಅನ್ಯಥಾ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	ಅನ್ಯಥಾ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ಪ್ರತ್ಯಾಗಮ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ರಿಕ್ತ);

	ಪ್ರತ್ಯಾಗಮ (ctx->major);
}

/* Privileged */
ಧ್ರುವ ವರ್ಣ *ssh_gssapi_displayname(ಶೂನ್ಯ)
{
	ಯದಿ (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.ಮೌಲ್ಯ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ (ವರ್ಣ *)gssapi_client.displayname.ಮೌಲ್ಯ;
}

#endif
