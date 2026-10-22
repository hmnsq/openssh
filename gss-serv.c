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

#অন্তর্ভাব "includes.h"

#ifdef GSSAPI

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/param.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "session.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"

#অন্তর্ভাব "ssh-gss.h"

বাহ্যিক ServerOptions options;

স্থির ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_বাফার, GSS_C_EMPTY_বাফার,
    GSS_C_NO_CREDENTIAL, ফাঁকা, {ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ফাঁকা, ফাঁকা, {0, ফাঁকা}, ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা};

#ifdef KRB5
বাহ্যিক ssh_gssapi_mech gssapi_kerberos_mech;
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
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, পূর্ণসংখ্যা *present)
{
	যদি (supported_oids == ফাঁকা)
		ssh_gssapi_prepare_supported_oids();
	ফেরত gss_test_oid_set_member(ms, member, supported_oids, present);
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
	অক্ষর lname[NI_MAXHOST];
	gss_OID_set oidset;

	যদি (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		যদি (gethostname(lname, আকার(lname))) {
			gss_release_oid_set(&status, &oidset);
			ফেরত (-1);
		}

		যদি (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			ফেরত (ctx->major);
		}

		যদি ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ফাঁকা, ফাঁকা)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		ফেরত (ctx->major);
	} অন্যথা {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ফেরত GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	যদি (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	ফেরত (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
শূন্য
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	পূর্ণসংখ্যা i = 0;
	OM_uint32 min_status;
	পূর্ণসংখ্যা present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	যখন (supported_mechs[i]->name != ফাঁকা) {
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
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_বাফার_desc *recv_tok,
    gss_বাফার_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 status;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, ফাঁকা, &ctx->client_creds);

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

	যদি (((flags == ফাঁকা) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		যদি (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ফেরত (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
স্থির OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_বাফার_t ename, gss_বাফার_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->মান;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	যদি (ename->দৈর্ঘ্য < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ফেরত GSS_S_FAILURE;

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
	    ename->দৈর্ঘ্য < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ফেরত GSS_S_FAILURE;

	offset = oidl+6;

	যদি (ename->দৈর্ঘ্য < offset+4)
		ফেরত GSS_S_FAILURE;

	name->দৈর্ঘ্য = get_u32(tok+offset);
	offset += 4;

	যদি (UINT_MAX - offset < name->দৈর্ঘ্য)
		ফেরত GSS_S_FAILURE;
	যদি (ename->দৈর্ঘ্য < offset+name->দৈর্ঘ্য)
		ফেরত GSS_S_FAILURE;

	name->মান = xmalloc(name->দৈর্ঘ্য+1);
	memcpy(name->মান, tok+offset, name->দৈর্ঘ্য);
	((অক্ষর *)name->মান)[name->দৈর্ঘ্য] = 0;

	ফেরত GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	পূর্ণসংখ্যা i = 0;

	gss_বাফার_desc ename;

	client->userok = 0;
	client->mech = ফাঁকা;

	যখন (supported_mechs[i]->name != ফাঁকা) {
		যদি (supported_mechs[i]->oid.দৈর্ঘ্য == ctx->oid->দৈর্ঘ্য &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->দৈর্ঘ্য) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	যদি (client->mech == ফাঁকা)
		ফেরত GSS_S_FAILURE;

	যদি ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ফাঁকা))) {
		ssh_gssapi_error(ctx);
		ফেরত (ctx->major);
	}

	যদি ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ফেরত (ctx->major);
	}

	যদি ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ফেরত (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ফেরত (ctx->major);
}

/* As user - called on fatal/exit */
শূন্য
ssh_gssapi_cleanup_creds(শূন্য)
{
	যদি (gssapi_client.store.filename != ফাঁকা) {
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
		ফেরত;
	}

	যদি (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ফেরত;
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
ssh_gssapi_do_child(অক্ষর ***envp, u_int *envsizep)
{

	যদি (gssapi_client.store.envvar != ফাঁকা &&
	    gssapi_client.store.envval != ফাঁকা) {
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

	gss_release_বাফার(&lmin, &gssapi_client.displayname);
	gss_release_বাফার(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, আকার(ssh_gssapi_client));
}

/* Privileged */
পূর্ণসংখ্যা
ssh_gssapi_userok(অক্ষর *user)
{
	যদি (gssapi_client.exportedname.দৈর্ঘ্য == 0 ||
	    gssapi_client.exportedname.মান == ফাঁকা) {
		debug("No suitable client data");
		ফেরত 0;
	}
	যদি (gssapi_client.mech && gssapi_client.mech->userok)
		যদি ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ফেরত 1;
		} অন্যথা {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ফেরত 0;
		}
	অন্যথা
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ফেরত (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_বাফার_t gssbuf, gss_বাফার_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ফাঁকা);

	ফেরত (ctx->major);
}

/* Privileged */
ধ্রুবক অক্ষর *ssh_gssapi_displayname(শূন্য)
{
	যদি (gssapi_client.displayname.দৈর্ঘ্য == 0 ||
	    gssapi_client.displayname.মান == ফাঁকা)
		ফেরত ফাঁকা;
	ফেরত (অক্ষর *)gssapi_client.displayname.মান;
}

#endif
