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

#شامل "includes.h"

#اگر_تعریف_شدہ GSSAPI

#شامل <sys/types.h>
#شامل <sys/param.h>
#شامل <sys/queue.h>

#شامل <netdb.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "log.h"
#شامل "channels.h"
#شامل "session.h"
#شامل "misc.h"
#شامل "servconf.h"

#شامل "ssh-gss.h"

خارجی ServerOptions options;

ساکن ssh_gssapi_client gssapi_client =
    { GSS_C_خالی_خانے_بفر, GSS_C_خالی_خانے_بفر,
    GSS_C_NO_CREDENTIAL, تہی, {تہی, تہی, تہی, تہی}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { تہی, تہی, {0, تہی}, تہی, تہی, تہی, تہی};

#اگر_تعریف_شدہ KRB5
خارجی ssh_gssapi_mech gssapi_kerberos_mech;
#اگر_ختم

ssh_gssapi_mech* supported_mechs[]= {
#اگر_تعریف_شدہ KRB5
	&gssapi_kerberos_mech,
#اگر_ختم
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
ساکن gss_OID_سیٹ supported_oids;

خالی
ssh_gssapi_prepare_supported_oids(خالی)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, صحیح *present)
{
	اگر (supported_oids == تہی)
		ssh_gssapi_prepare_supported_oids();
	واپس gss_test_oid_سیٹ_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
ساکن OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 حالت_2;
	حرف lname[NI_MAXHOST];
	gss_OID_سیٹ oidset;

	اگر (options.gss_strict_acceptor) {
		gss_create_خالی_خانے_oid_سیٹ(&حالت_2, &oidset);
		gss_جوڑو_oid_سیٹ_member(&حالت_2, ctx->oid, &oidset);

		اگر (gethostname(lname, حجم(lname))) {
			gss_release_oid_سیٹ(&حالت_2, &oidset);
			واپس (-1);
		}

		اگر (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_سیٹ(&حالت_2, &oidset);
			واپس (ctx->major);
		}

		اگر ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    تہی, تہی)))
			ssh_gssapi_error(ctx);

		gss_release_oid_سیٹ(&حالت_2, &oidset);
		واپس (ctx->major);
	} ورنہ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	واپس GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	اگر (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_سیٹ_oid(*ctx, oid);
	واپس (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
خالی
ssh_gssapi_supported_oids(gss_OID_سیٹ *oidset)
{
	صحیح i = 0;
	OM_uint32 min_حالت;
	صحیح present;
	gss_OID_سیٹ supported;

	gss_create_خالی_خانے_oid_سیٹ(&min_حالت, oidset);
	gss_indicate_mechs(&min_حالت, &supported);

	جب (supported_mechs[i]->name != تہی) {
		اگر (GSS_ERROR(gss_test_oid_سیٹ_member(&min_حالت,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		اگر (present)
			gss_جوڑو_oid_سیٹ_member(&min_حالت,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_سیٹ(&min_حالت, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_بفر_desc *recv_tok,
    gss_بفر_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 حالت_2;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, تہی, &ctx->client_creds);

	اگر (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	اگر (ctx->client_creds)
		debug("Received some client credentials");
	ورنہ
		debug("Got no client credentials");

	حالت_2 = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	اگر (((flags == تہی) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		اگر (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	واپس (حالت_2);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
ساکن OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_بفر_t ename, gss_بفر_t name)
{
	u_char *tok;
	OM_uint32 انحراف;
	OM_uint32 oidl;

	tok = ename->قدر;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	اگر (ename->لمبائی < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		واپس GSS_S_FAILURE;

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
	اگر (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->لمبائی < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		واپس GSS_S_FAILURE;

	انحراف = oidl+6;

	اگر (ename->لمبائی < انحراف+4)
		واپس GSS_S_FAILURE;

	name->لمبائی = get_u32(tok+انحراف);
	انحراف += 4;

	اگر (UINT_MAX - انحراف < name->لمبائی)
		واپس GSS_S_FAILURE;
	اگر (ename->لمبائی < انحراف+name->لمبائی)
		واپس GSS_S_FAILURE;

	name->قدر = xmalloc(name->لمبائی+1);
	حافظہ_نقل(name->قدر, tok+انحراف, name->لمبائی);
	((حرف *)name->قدر)[name->لمبائی] = 0;

	واپس GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	صحیح i = 0;

	gss_بفر_desc ename;

	client->userok = 0;
	client->mech = تہی;

	جب (supported_mechs[i]->name != تہی) {
		اگر (supported_mechs[i]->oid.لمبائی == ctx->oid->لمبائی &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->لمبائی) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	اگر (client->mech == تہی)
		واپس GSS_S_FAILURE;

	اگر ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, تہی))) {
		ssh_gssapi_error(ctx);
		واپس (ctx->major);
	}

	اگر ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		واپس (ctx->major);
	}

	اگر ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		واپس (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	واپس (ctx->major);
}

/* As user - called on fatal/exit */
خالی
ssh_gssapi_cleanup_creds(خالی)
{
	اگر (gssapi_client.store.filename != تہی) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
خالی
ssh_gssapi_storecreds(خالی)
{
	اگر (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		واپس;
	}

	اگر (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		واپس;
	}

	اگر (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ورنہ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
خالی
ssh_gssapi_do_بچہ(حرف ***envp, u_int *envsizep)
{

	اگر (gssapi_client.store.envvar != تہی &&
	    gssapi_client.store.envval != تہی) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		بچہ_سیٹ_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

خالی
ssh_gssapi_cleanup_global_client(خالی)
{
	OM_uint32 lmin;

	gss_release_بفر(&lmin, &gssapi_client.displayname);
	gss_release_بفر(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, حجم(ssh_gssapi_client));
}

/* Privileged */
صحیح
ssh_gssapi_userok(حرف *user)
{
	اگر (gssapi_client.exportedname.لمبائی == 0 ||
	    gssapi_client.exportedname.قدر == تہی) {
		debug("No suitable client data");
		واپس 0;
	}
	اگر (gssapi_client.mech && gssapi_client.mech->userok)
		اگر ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			واپس 1;
		} ورنہ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			واپس 0;
		}
	ورنہ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	واپس (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_بفر_t gssbuf, gss_بفر_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, تہی);

	واپس (ctx->major);
}

/* Privileged */
ثابت حرف *ssh_gssapi_displayname(خالی)
{
	اگر (gssapi_client.displayname.لمبائی == 0 ||
	    gssapi_client.displayname.قدر == تہی)
		واپس تہی;
	واپس (حرف *)gssapi_client.displayname.قدر;
}

#اگر_ختم
