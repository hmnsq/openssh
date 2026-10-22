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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI

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
    { GSS_C_ಖಾಲಿಗಳು_ಬಫರ್, GSS_C_ಖಾಲಿಗಳು_ಬಫರ್,
    GSS_C_NO_CREDENTIAL, ಖಾಲಿ, {ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ಖಾಲಿ, ಖಾಲಿ, {0, ಖಾಲಿ}, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ};

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
ಬಾಹ್ಯ ssh_gssapi_mech gssapi_kerberos_mech;
#ಆದರೆ_ಅಂತ್ಯ

ssh_gssapi_mech* supported_mechs[]= {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	&gssapi_kerberos_mech,
#ಆದರೆ_ಅಂತ್ಯ
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
ಸ್ಥಿರ gss_OID_ಗಣ supported_oids;

ಶೂನ್ಯ
ssh_gssapi_prepare_supported_oids(ಶೂನ್ಯ)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, ಪೂರ್ಣಾಂಕ *present)
{
	ಆದರೆ (supported_oids == ಖಾಲಿ)
		ssh_gssapi_prepare_supported_oids();
	ಹಿಂತಿರುಗಿ gss_test_oid_ಗಣ_member(ms, member, supported_oids, present);
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
	OM_uint32 ಸ್ಥಿತಿ_2;
	ಅಕ್ಷರ lname[NI_MAXHOST];
	gss_OID_ಗಣ oidset;

	ಆದರೆ (options.gss_strict_acceptor) {
		gss_create_ಖಾಲಿಗಳು_oid_ಗಣ(&ಸ್ಥಿತಿ_2, &oidset);
		gss_ಕೂಡಿಸು_oid_ಗಣ_member(&ಸ್ಥಿತಿ_2, ctx->oid, &oidset);

		ಆದರೆ (gethostname(lname, ಗಾತ್ರ(lname))) {
			gss_release_oid_ಗಣ(&ಸ್ಥಿತಿ_2, &oidset);
			ಹಿಂತಿರುಗಿ (-1);
		}

		ಆದರೆ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_ಗಣ(&ಸ್ಥಿತಿ_2, &oidset);
			ಹಿಂತಿರುಗಿ (ctx->major);
		}

		ಆದರೆ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ಖಾಲಿ, ಖಾಲಿ)))
			ssh_gssapi_error(ctx);

		gss_release_oid_ಗಣ(&ಸ್ಥಿತಿ_2, &oidset);
		ಹಿಂತಿರುಗಿ (ctx->major);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ಹಿಂತಿರುಗಿ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ಆದರೆ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_ಗಣ_oid(*ctx, oid);
	ಹಿಂತಿರುಗಿ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
ಶೂನ್ಯ
ssh_gssapi_supported_oids(gss_OID_ಗಣ *oidset)
{
	ಪೂರ್ಣಾಂಕ i = 0;
	OM_uint32 min_ಸ್ಥಿತಿ;
	ಪೂರ್ಣಾಂಕ present;
	gss_OID_ಗಣ supported;

	gss_create_ಖಾಲಿಗಳು_oid_ಗಣ(&min_ಸ್ಥಿತಿ, oidset);
	gss_indicate_mechs(&min_ಸ್ಥಿತಿ, &supported);

	ಆಗ (supported_mechs[i]->name != ಖಾಲಿ) {
		ಆದರೆ (GSS_ERROR(gss_test_oid_ಗಣ_member(&min_ಸ್ಥಿತಿ,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ಆದರೆ (present)
			gss_ಕೂಡಿಸು_oid_ಗಣ_member(&min_ಸ್ಥಿತಿ,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_ಗಣ(&min_ಸ್ಥಿತಿ, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_ಬಫರ್_desc *recv_tok,
    gss_ಬಫರ್_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 ಸ್ಥಿತಿ_2;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, ಖಾಲಿ, &ctx->client_creds);

	ಆದರೆ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ಆದರೆ (ctx->client_creds)
		debug("Received some client credentials");
	ಇಲ್ಲದಿದ್ದರೆ
		debug("Got no client credentials");

	ಸ್ಥಿತಿ_2 = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ಆದರೆ (((flags == ಖಾಲಿ) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ಆದರೆ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ಹಿಂತಿರುಗಿ (ಸ್ಥಿತಿ_2);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
ಸ್ಥಿರ OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_ಬಫರ್_t ename, gss_ಬಫರ್_t name)
{
	u_char *tok;
	OM_uint32 ಸ್ಥಾನಾಂತರ;
	OM_uint32 oidl;

	tok = ename->ಮೌಲ್ಯ;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	ಆದರೆ (ename->ಉದ್ದಳತೆ < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;

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
	ಆದರೆ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->ಉದ್ದಳತೆ < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;

	ಸ್ಥಾನಾಂತರ = oidl+6;

	ಆದರೆ (ename->ಉದ್ದಳತೆ < ಸ್ಥಾನಾಂತರ+4)
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;

	name->ಉದ್ದಳತೆ = get_u32(tok+ಸ್ಥಾನಾಂತರ);
	ಸ್ಥಾನಾಂತರ += 4;

	ಆದರೆ (UINT_MAX - ಸ್ಥಾನಾಂತರ < name->ಉದ್ದಳತೆ)
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;
	ಆದರೆ (ename->ಉದ್ದಳತೆ < ಸ್ಥಾನಾಂತರ+name->ಉದ್ದಳತೆ)
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;

	name->ಮೌಲ್ಯ = xmalloc(name->ಉದ್ದಳತೆ+1);
	ಸ್ಮರಣೆ_ನಕಲು(name->ಮೌಲ್ಯ, tok+ಸ್ಥಾನಾಂತರ, name->ಉದ್ದಳತೆ);
	((ಅಕ್ಷರ *)name->ಮೌಲ್ಯ)[name->ಉದ್ದಳತೆ] = 0;

	ಹಿಂತಿರುಗಿ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	ಪೂರ್ಣಾಂಕ i = 0;

	gss_ಬಫರ್_desc ename;

	client->userok = 0;
	client->mech = ಖಾಲಿ;

	ಆಗ (supported_mechs[i]->name != ಖಾಲಿ) {
		ಆದರೆ (supported_mechs[i]->oid.ಉದ್ದಳತೆ == ctx->oid->ಉದ್ದಳತೆ &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->ಉದ್ದಳತೆ) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ಆದರೆ (client->mech == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ GSS_S_FAILURE;

	ಆದರೆ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ಖಾಲಿ))) {
		ssh_gssapi_error(ctx);
		ಹಿಂತಿರುಗಿ (ctx->major);
	}

	ಆದರೆ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ಹಿಂತಿರುಗಿ (ctx->major);
	}

	ಆದರೆ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ಹಿಂತಿರುಗಿ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ಹಿಂತಿರುಗಿ (ctx->major);
}

/* As user - called on fatal/exit */
ಶೂನ್ಯ
ssh_gssapi_cleanup_creds(ಶೂನ್ಯ)
{
	ಆದರೆ (gssapi_client.store.filename != ಖಾಲಿ) {
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
	ಆದರೆ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ಇಲ್ಲದಿದ್ದರೆ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
ಶೂನ್ಯ
ssh_gssapi_do_ಮಗು(ಅಕ್ಷರ ***envp, u_int *envsizep)
{

	ಆದರೆ (gssapi_client.store.envvar != ಖಾಲಿ &&
	    gssapi_client.store.envval != ಖಾಲಿ) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		ಮಗು_ಗಣ_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

ಶೂನ್ಯ
ssh_gssapi_cleanup_global_client(ಶೂನ್ಯ)
{
	OM_uint32 lmin;

	gss_release_ಬಫರ್(&lmin, &gssapi_client.displayname);
	gss_release_ಬಫರ್(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, ಗಾತ್ರ(ssh_gssapi_client));
}

/* Privileged */
ಪೂರ್ಣಾಂಕ
ssh_gssapi_userok(ಅಕ್ಷರ *user)
{
	ಆದರೆ (gssapi_client.exportedname.ಉದ್ದಳತೆ == 0 ||
	    gssapi_client.exportedname.ಮೌಲ್ಯ == ಖಾಲಿ) {
		debug("No suitable client data");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (gssapi_client.mech && gssapi_client.mech->userok)
		ಆದರೆ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ಹಿಂತಿರುಗಿ 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ಹಿಂತಿರುಗಿ 0;
		}
	ಇಲ್ಲದಿದ್ದರೆ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ಹಿಂತಿರುಗಿ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_ಬಫರ್_t gssbuf, gss_ಬಫರ್_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ಖಾಲಿ);

	ಹಿಂತಿರುಗಿ (ctx->major);
}

/* Privileged */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_gssapi_displayname(ಶೂನ್ಯ)
{
	ಆದರೆ (gssapi_client.displayname.ಉದ್ದಳತೆ == 0 ||
	    gssapi_client.displayname.ಮೌಲ್ಯ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ (ಅಕ್ಷರ *)gssapi_client.displayname.ಮೌಲ್ಯ;
}

#ಆದರೆ_ಅಂತ್ಯ
