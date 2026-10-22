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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/param.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"

ਬਾਹਰੀ ServerOptions options;

ਸਥਿਰ ssh_gssapi_client gssapi_client =
    { GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ, GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ,
    GSS_C_NO_CREDENTIAL, ਨਿਰਾ, {ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ਨਿਰਾ, ਨਿਰਾ, {0, ਨਿਰਾ}, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ};

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
ਬਾਹਰੀ ssh_gssapi_mech gssapi_kerberos_mech;
#ਜੇ_ਅੰਤ

ssh_gssapi_mech* supported_mechs[]= {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	&gssapi_kerberos_mech,
#ਜੇ_ਅੰਤ
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
ਸਥਿਰ gss_OID_ਸੈੱਟ supported_oids;

ਖਾਲੀ
ssh_gssapi_prepare_supported_oids(ਖਾਲੀ)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, ਪੂਰਨ *present)
{
	ਜੇ (supported_oids == ਨਿਰਾ)
		ssh_gssapi_prepare_supported_oids();
	ਵਾਪਸ gss_test_oid_ਸੈੱਟ_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
ਸਥਿਰ OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 ਸਥਿਤੀ;
	ਅੱਖਰ lname[NI_MAXHOST];
	gss_OID_ਸੈੱਟ oidset;

	ਜੇ (options.gss_strict_acceptor) {
		gss_create_ਖਾਲੀ_ਥਾਵਾਂ_oid_ਸੈੱਟ(&ਸਥਿਤੀ, &oidset);
		gss_ਜੋੜੋ_oid_ਸੈੱਟ_member(&ਸਥਿਤੀ, ctx->oid, &oidset);

		ਜੇ (gethostname(lname, ਆਕਾਰ(lname))) {
			gss_release_oid_ਸੈੱਟ(&ਸਥਿਤੀ, &oidset);
			ਵਾਪਸ (-1);
		}

		ਜੇ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_ਸੈੱਟ(&ਸਥਿਤੀ, &oidset);
			ਵਾਪਸ (ctx->major);
		}

		ਜੇ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ਨਿਰਾ, ਨਿਰਾ)))
			ssh_gssapi_error(ctx);

		gss_release_oid_ਸੈੱਟ(&ਸਥਿਤੀ, &oidset);
		ਵਾਪਸ (ctx->major);
	} ਨਹੀਂਤਾਂ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ਵਾਪਸ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ਜੇ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_ਸੈੱਟ_oid(*ctx, oid);
	ਵਾਪਸ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
ਖਾਲੀ
ssh_gssapi_supported_oids(gss_OID_ਸੈੱਟ *oidset)
{
	ਪੂਰਨ i = 0;
	OM_uint32 min_ਸਥਿਤੀ;
	ਪੂਰਨ present;
	gss_OID_ਸੈੱਟ supported;

	gss_create_ਖਾਲੀ_ਥਾਵਾਂ_oid_ਸੈੱਟ(&min_ਸਥਿਤੀ, oidset);
	gss_indicate_mechs(&min_ਸਥਿਤੀ, &supported);

	ਜਦੋਂ (supported_mechs[i]->name != ਨਿਰਾ) {
		ਜੇ (GSS_ERROR(gss_test_oid_ਸੈੱਟ_member(&min_ਸਥਿਤੀ,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ਜੇ (present)
			gss_ਜੋੜੋ_oid_ਸੈੱਟ_member(&min_ਸਥਿਤੀ,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_ਸੈੱਟ(&min_ਸਥਿਤੀ, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_ਬਫਰ_desc *recv_tok,
    gss_ਬਫਰ_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 ਸਥਿਤੀ;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, ਨਿਰਾ, &ctx->client_creds);

	ਜੇ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ਜੇ (ctx->client_creds)
		debug("Received some client credentials");
	ਨਹੀਂਤਾਂ
		debug("Got no client credentials");

	ਸਥਿਤੀ = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ਜੇ (((flags == ਨਿਰਾ) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ਜੇ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ਵਾਪਸ (ਸਥਿਤੀ);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
ਸਥਿਰ OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_ਬਫਰ_t ename, gss_ਬਫਰ_t name)
{
	u_char *tok;
	OM_uint32 ਵਿੱਥ;
	OM_uint32 oidl;

	tok = ename->ਮੁੱਲ;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	ਜੇ (ename->ਲੰਮਾਈ < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ਵਾਪਸ GSS_S_FAILURE;

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
	ਜੇ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->ਲੰਮਾਈ < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ਵਾਪਸ GSS_S_FAILURE;

	ਵਿੱਥ = oidl+6;

	ਜੇ (ename->ਲੰਮਾਈ < ਵਿੱਥ+4)
		ਵਾਪਸ GSS_S_FAILURE;

	name->ਲੰਮਾਈ = get_u32(tok+ਵਿੱਥ);
	ਵਿੱਥ += 4;

	ਜੇ (UINT_MAX - ਵਿੱਥ < name->ਲੰਮਾਈ)
		ਵਾਪਸ GSS_S_FAILURE;
	ਜੇ (ename->ਲੰਮਾਈ < ਵਿੱਥ+name->ਲੰਮਾਈ)
		ਵਾਪਸ GSS_S_FAILURE;

	name->ਮੁੱਲ = xmalloc(name->ਲੰਮਾਈ+1);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(name->ਮੁੱਲ, tok+ਵਿੱਥ, name->ਲੰਮਾਈ);
	((ਅੱਖਰ *)name->ਮੁੱਲ)[name->ਲੰਮਾਈ] = 0;

	ਵਾਪਸ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	ਪੂਰਨ i = 0;

	gss_ਬਫਰ_desc ename;

	client->userok = 0;
	client->mech = ਨਿਰਾ;

	ਜਦੋਂ (supported_mechs[i]->name != ਨਿਰਾ) {
		ਜੇ (supported_mechs[i]->oid.ਲੰਮਾਈ == ctx->oid->ਲੰਮਾਈ &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->ਲੰਮਾਈ) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ਜੇ (client->mech == ਨਿਰਾ)
		ਵਾਪਸ GSS_S_FAILURE;

	ਜੇ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ਨਿਰਾ))) {
		ssh_gssapi_error(ctx);
		ਵਾਪਸ (ctx->major);
	}

	ਜੇ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ਵਾਪਸ (ctx->major);
	}

	ਜੇ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ਵਾਪਸ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ਵਾਪਸ (ctx->major);
}

/* As user - called on fatal/exit */
ਖਾਲੀ
ssh_gssapi_cleanup_creds(ਖਾਲੀ)
{
	ਜੇ (gssapi_client.store.filename != ਨਿਰਾ) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
ਖਾਲੀ
ssh_gssapi_storecreds(ਖਾਲੀ)
{
	ਜੇ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ਵਾਪਸ;
	}

	ਜੇ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ਵਾਪਸ;
	}

	ਜੇ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ਨਹੀਂਤਾਂ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
ਖਾਲੀ
ssh_gssapi_do_ਬੱਚਾ(ਅੱਖਰ ***envp, u_int *envsizep)
{

	ਜੇ (gssapi_client.store.envvar != ਨਿਰਾ &&
	    gssapi_client.store.envval != ਨਿਰਾ) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		ਬੱਚਾ_ਸੈੱਟ_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

ਖਾਲੀ
ssh_gssapi_cleanup_global_client(ਖਾਲੀ)
{
	OM_uint32 lmin;

	gss_release_ਬਫਰ(&lmin, &gssapi_client.displayname);
	gss_release_ਬਫਰ(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, ਆਕਾਰ(ssh_gssapi_client));
}

/* Privileged */
ਪੂਰਨ
ssh_gssapi_userok(ਅੱਖਰ *user)
{
	ਜੇ (gssapi_client.exportedname.ਲੰਮਾਈ == 0 ||
	    gssapi_client.exportedname.ਮੁੱਲ == ਨਿਰਾ) {
		debug("No suitable client data");
		ਵਾਪਸ 0;
	}
	ਜੇ (gssapi_client.mech && gssapi_client.mech->userok)
		ਜੇ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ਵਾਪਸ 1;
		} ਨਹੀਂਤਾਂ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ਵਾਪਸ 0;
		}
	ਨਹੀਂਤਾਂ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ਵਾਪਸ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_ਬਫਰ_t gssbuf, gss_ਬਫਰ_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ਨਿਰਾ);

	ਵਾਪਸ (ctx->major);
}

/* Privileged */
ਅਚਲ ਅੱਖਰ *ssh_gssapi_displayname(ਖਾਲੀ)
{
	ਜੇ (gssapi_client.displayname.ਲੰਮਾਈ == 0 ||
	    gssapi_client.displayname.ਮੁੱਲ == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ (ਅੱਖਰ *)gssapi_client.displayname.ਮੁੱਲ;
}

#ਜੇ_ਅੰਤ
