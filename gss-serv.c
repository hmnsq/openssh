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

#ضمن "includes.h"

#ifdef GSSAPI

#ضمن <sys/types.h>
#ضمن <sys/param.h>
#ضمن <sys/queue.h>

#ضمن <netdb.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "log.h"
#ضمن "channels.h"
#ضمن "session.h"
#ضمن "misc.h"
#ضمن "servconf.h"

#ضمن "ssh-gss.h"

خارجي ServerOptions options;

ساكن ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER,
    GSS_C_NO_CREDENTIAL, عدم, {عدم, عدم, عدم, عدم}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { عدم, عدم, {0, عدم}, عدم, عدم, عدم, عدم};

#ifdef KRB5
خارجي ssh_gssapi_mech gssapi_kerberos_mech;
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
ساكن gss_OID_set supported_oids;

فراغ
ssh_gssapi_prepare_supported_oids(فراغ)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, صحيح *present)
{
	ܐܢ (supported_oids == عدم)
		ssh_gssapi_prepare_supported_oids();
	ܦܢܐ gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
ساكن OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	حرف lname[NI_MAXHOST];
	gss_OID_set oidset;

	ܐܢ (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		ܐܢ (gethostname(lname, حجم(lname))) {
			gss_release_oid_set(&status, &oidset);
			ܦܢܐ (-1);
		}

		ܐܢ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			ܦܢܐ (ctx->major);
		}

		ܐܢ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    عدم, عدم)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		ܦܢܐ (ctx->major);
	} ܐܚܪܢܐ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ܦܢܐ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ܐܢ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	ܦܢܐ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
فراغ
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	صحيح i = 0;
	OM_uint32 min_status;
	صحيح present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	ܟܡܐ (supported_mechs[i]->name != عدم) {
		ܐܢ (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ܐܢ (present)
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
	    send_tok, flags, عدم, &ctx->client_creds);

	ܐܢ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ܐܢ (ctx->client_creds)
		debug("Received some client credentials");
	ܐܚܪܢܐ
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ܐܢ (((flags == عدم) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ܐܢ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ܦܢܐ (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
ساكن OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_buffer_t ename, gss_buffer_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->value;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	ܐܢ (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ܦܢܐ GSS_S_FAILURE;

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
	ܐܢ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ܦܢܐ GSS_S_FAILURE;

	offset = oidl+6;

	ܐܢ (ename->length < offset+4)
		ܦܢܐ GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	ܐܢ (UINT_MAX - offset < name->length)
		ܦܢܐ GSS_S_FAILURE;
	ܐܢ (ename->length < offset+name->length)
		ܦܢܐ GSS_S_FAILURE;

	name->value = xmalloc(name->length+1);
	memcpy(name->value, tok+offset, name->length);
	((حرف *)name->value)[name->length] = 0;

	ܦܢܐ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	صحيح i = 0;

	gss_buffer_desc ename;

	client->userok = 0;
	client->mech = عدم;

	ܟܡܐ (supported_mechs[i]->name != عدم) {
		ܐܢ (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ܐܢ (client->mech == عدم)
		ܦܢܐ GSS_S_FAILURE;

	ܐܢ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, عدم))) {
		ssh_gssapi_error(ctx);
		ܦܢܐ (ctx->major);
	}

	ܐܢ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ܦܢܐ (ctx->major);
	}

	ܐܢ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ܦܢܐ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ܦܢܐ (ctx->major);
}

/* As user - called on fatal/exit */
فراغ
ssh_gssapi_cleanup_creds(فراغ)
{
	ܐܢ (gssapi_client.store.filename != عدم) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
فراغ
ssh_gssapi_storecreds(فراغ)
{
	ܐܢ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ܦܢܐ;
	}

	ܐܢ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ܦܢܐ;
	}

	ܐܢ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ܐܚܪܢܐ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
فراغ
ssh_gssapi_do_child(حرف ***envp, u_int *envsizep)
{

	ܐܢ (gssapi_client.store.envvar != عدم &&
	    gssapi_client.store.envval != عدم) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

فراغ
ssh_gssapi_cleanup_global_client(فراغ)
{
	OM_uint32 lmin;

	gss_release_buffer(&lmin, &gssapi_client.displayname);
	gss_release_buffer(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, حجم(ssh_gssapi_client));
}

/* Privileged */
صحيح
ssh_gssapi_userok(حرف *user)
{
	ܐܢ (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.value == عدم) {
		debug("No suitable client data");
		ܦܢܐ 0;
	}
	ܐܢ (gssapi_client.mech && gssapi_client.mech->userok)
		ܐܢ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ܦܢܐ 1;
		} ܐܚܪܢܐ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ܦܢܐ 0;
		}
	ܐܚܪܢܐ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ܦܢܐ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, عدم);

	ܦܢܐ (ctx->major);
}

/* Privileged */
ثابت حرف *ssh_gssapi_displayname(فراغ)
{
	ܐܢ (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.value == عدم)
		ܦܢܐ عدم;
	ܦܢܐ (حرف *)gssapi_client.displayname.value;
}

#endif
