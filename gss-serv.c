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

#include "includes.h"

#ifdef GSSAPI

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "channels.h"
#include "session.h"
#include "misc.h"
#include "servconf.h"

#include "ssh-gss.h"

extern ServerOptions options;

static ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER,
    GSS_C_NO_CREDENTIAL, NULL, {NULL, NULL, NULL, NULL}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { NULL, NULL, {0, NULL}, NULL, NULL, NULL, NULL};

#ifdef KRB5
extern ssh_gssapi_mech gssapi_kerberos_mech;
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
static gss_OID_set supported_oids;

void
ssh_gssapi_prepare_supported_oids(void)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, puur_naa_nka *present)
{
	ᨀᨘ (supported_oids == NULL)
		ssh_gssapi_prepare_supported_oids();
	ᨀᨘᨒ gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
static OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	var_na lname[NI_MAXHOST];
	gss_OID_set oidset;

	ᨀᨘ (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		ᨀᨘ (gethostname(lname, parimaa_na(lname))) {
			gss_release_oid_set(&status, &oidset);
			ᨀᨘᨒ (-1);
		}

		ᨀᨘ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			ᨀᨘᨒ (ctx->major);
		}

		ᨀᨘ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    NULL, NULL)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		ᨀᨘᨒ (ctx->major);
	} ᨀᨘᨁ {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	ᨀᨘᨒ GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ᨀᨘ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	ᨀᨘᨒ (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
void
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	puur_naa_nka i = 0;
	OM_uint32 min_status;
	puur_naa_nka present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	ᨀᨛ (supported_mechs[i]->name != NULL) {
		ᨀᨘ (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ᨀᨘ (present)
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
	    send_tok, flags, NULL, &ctx->client_creds);

	ᨀᨘ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ᨀᨘ (ctx->client_creds)
		debug("Received some client credentials");
	ᨀᨘᨁ
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ᨀᨘ (((flags == NULL) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ᨀᨘ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	ᨀᨘᨒ (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
static OM_uint32
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

	ᨀᨘ (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		ᨀᨘᨒ GSS_S_FAILURE;

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
	ᨀᨘ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		ᨀᨘᨒ GSS_S_FAILURE;

	offset = oidl+6;

	ᨀᨘ (ename->length < offset+4)
		ᨀᨘᨒ GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	ᨀᨘ (UINT_MAX - offset < name->length)
		ᨀᨘᨒ GSS_S_FAILURE;
	ᨀᨘ (ename->length < offset+name->length)
		ᨀᨘᨒ GSS_S_FAILURE;

	name->value = xmalloc(name->length+1);
	memcpy(name->value, tok+offset, name->length);
	((var_na *)name->value)[name->length] = 0;

	ᨀᨘᨒ GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	puur_naa_nka i = 0;

	gss_buffer_desc ename;

	client->userok = 0;
	client->mech = NULL;

	ᨀᨛ (supported_mechs[i]->name != NULL) {
		ᨀᨘ (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ᨀᨘ (client->mech == NULL)
		ᨀᨘᨒ GSS_S_FAILURE;

	ᨀᨘ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, NULL))) {
		ssh_gssapi_error(ctx);
		ᨀᨘᨒ (ctx->major);
	}

	ᨀᨘ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		ᨀᨘᨒ (ctx->major);
	}

	ᨀᨘ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		ᨀᨘᨒ (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ᨀᨘᨒ (ctx->major);
}

/* As user - called on fatal/exit */
void
ssh_gssapi_cleanup_creds(void)
{
	ᨀᨘ (gssapi_client.store.filename != NULL) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
void
ssh_gssapi_storecreds(void)
{
	ᨀᨘ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		ᨀᨘᨒ;
	}

	ᨀᨘ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		ᨀᨘᨒ;
	}

	ᨀᨘ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} ᨀᨘᨁ
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
void
ssh_gssapi_do_child(var_na ***envp, u_int *envsizep)
{

	ᨀᨘ (gssapi_client.store.envvar != NULL &&
	    gssapi_client.store.envval != NULL) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

void
ssh_gssapi_cleanup_global_client(void)
{
	OM_uint32 lmin;

	gss_release_buffer(&lmin, &gssapi_client.displayname);
	gss_release_buffer(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, parimaa_na(ssh_gssapi_client));
}

/* Privileged */
puur_naa_nka
ssh_gssapi_userok(var_na *user)
{
	ᨀᨘ (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.value == NULL) {
		debug("No suitable client data");
		ᨀᨘᨒ 0;
	}
	ᨀᨘ (gssapi_client.mech && gssapi_client.mech->userok)
		ᨀᨘ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			ᨀᨘᨒ 1;
		} ᨀᨘᨁ {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			ᨀᨘᨒ 0;
		}
	ᨀᨘᨁ
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	ᨀᨘᨒ (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, NULL);

	ᨀᨘᨒ (ctx->major);
}

/* Privileged */
const var_na *ssh_gssapi_displayname(void)
{
	ᨀᨘ (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.value == NULL)
		ᨀᨘᨒ NULL;
	ᨀᨘᨒ (var_na *)gssapi_client.displayname.value;
}

#endif
