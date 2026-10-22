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

#অন্তর্ভাৱ "includes.h"

#ifdef GSSAPI

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/param.h>
#অন্তর্ভাৱ <sys/queue.h>

#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "channels.h"
#অন্তর্ভাৱ "session.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"

#অন্তর্ভাৱ "ssh-gss.h"

বাহ্য ServerOptions options;

স্থির ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER,
    GSS_C_NO_CREDENTIAL, রিক্ত, {রিক্ত, রিক্ত, রিক্ত, রিক্ত}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { রিক্ত, রিক্ত, {0, রিক্ত}, রিক্ত, রিক্ত, রিক্ত, রিক্ত};

#ifdef KRB5
বাহ্য ssh_gssapi_mech gssapi_kerberos_mech;
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
স্থির gss_OID_set supported_oids;

শূন্য
ssh_gssapi_prepare_supported_oids(শূন্য)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, পূর্ণাঙ্ক *present)
{
	যদি (supported_oids == রিক্ত)
		ssh_gssapi_prepare_supported_oids();
	ঘূৰাই gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
স্থির OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	ৱর্ণ lname[NI_MAXHOST];
	gss_OID_set oidset;

	যদি (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		যদি (gethostname(lname, পরিমাণ(lname))) {
			gss_release_oid_set(&status, &oidset);
			ঘূৰাই (-1);
		}

		যদি (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			ঘূৰাই (ctx->major);
		}

		যদি ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    রিক্ত, রিক্ত)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		ঘূৰাই (ctx->major);
	} অন্যথা {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ঘূৰাই GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	যদি (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	ঘূৰাই (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
শূন্য
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	পূর্ণাঙ্ক i = 0;
	OM_uint32 min_status;
	পূর্ণাঙ্ক present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	যেতিয়ালৈ (supported_mechs[i]->name != রিক্ত) {
		যদি (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		যদি (present)
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
	    send_tok, flags, রিক্ত, &ctx->client_creds);

	যদি (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	যদি (ctx->client_creds)
		debug("Received some client credentials");
	অন্যথা
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	যদি (((flags == রিক্ত) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		যদি (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ঘূৰাই (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
স্থির OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_buffer_t ename, gss_buffer_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->মান;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	যদি (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ঘূৰাই GSS_S_FAILURE;

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
	যদি (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ঘূৰাই GSS_S_FAILURE;

	offset = oidl+6;

	যদি (ename->length < offset+4)
		ঘূৰাই GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	যদি (UINT_MAX - offset < name->length)
		ঘূৰাই GSS_S_FAILURE;
	যদি (ename->length < offset+name->length)
		ঘূৰাই GSS_S_FAILURE;

	name->মান = xmalloc(name->length+1);
	memcpy(name->মান, tok+offset, name->length);
	((ৱর্ণ *)name->মান)[name->length] = 0;

	ঘূৰাই GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	পূর্ণাঙ্ক i = 0;

	gss_buffer_desc ename;

	client->userok = 0;
	client->mech = রিক্ত;

	যেতিয়ালৈ (supported_mechs[i]->name != রিক্ত) {
		যদি (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	যদি (client->mech == রিক্ত)
		ঘূৰাই GSS_S_FAILURE;

	যদি ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, রিক্ত))) {
		ssh_gssapi_error(ctx);
		ঘূৰাই (ctx->major);
	}

	যদি ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ঘূৰাই (ctx->major);
	}

	যদি ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ঘূৰাই (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ঘূৰাই (ctx->major);
}

/* As user - called on fatal/exit */
শূন্য
ssh_gssapi_cleanup_creds(শূন্য)
{
	যদি (gssapi_client.store.filename != রিক্ত) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
শূন্য
ssh_gssapi_storecreds(শূন্য)
{
	যদি (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ঘূৰাই;
	}

	যদি (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ঘূৰাই;
	}

	যদি (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} অন্যথা
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
শূন্য
ssh_gssapi_do_child(ৱর্ণ ***envp, u_int *envsizep)
{

	যদি (gssapi_client.store.envvar != রিক্ত &&
	    gssapi_client.store.envval != রিক্ত) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

শূন্য
ssh_gssapi_cleanup_global_client(শূন্য)
{
	OM_uint32 lmin;

	gss_release_buffer(&lmin, &gssapi_client.displayname);
	gss_release_buffer(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, পরিমাণ(ssh_gssapi_client));
}

/* Privileged */
পূর্ণাঙ্ক
ssh_gssapi_userok(ৱর্ণ *user)
{
	যদি (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.মান == রিক্ত) {
		debug("No suitable client data");
		ঘূৰাই 0;
	}
	যদি (gssapi_client.mech && gssapi_client.mech->userok)
		যদি ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ঘূৰাই 1;
		} অন্যথা {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ঘূৰাই 0;
		}
	অন্যথা
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ঘূৰাই (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, রিক্ত);

	ঘূৰাই (ctx->major);
}

/* Privileged */
ধ্রুৱ ৱর্ণ *ssh_gssapi_displayname(শূন্য)
{
	যদি (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.মান == রিক্ত)
		ঘূৰাই রিক্ত;
	ঘূৰাই (ৱর্ণ *)gssapi_client.displayname.মান;
}

#endif
