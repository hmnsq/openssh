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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే GSSAPI

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/param.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "session.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"

#అన్తర్భావ "ssh-gss.h"

బాహ్య ServerOptions options;

స్థిర ssh_gssapi_client gssapi_client =
    { GSS_C_ఖాళీలు_బఫరు, GSS_C_ఖాళీలు_బఫరు,
    GSS_C_NO_CREDENTIAL, ఖాళీ, {ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { ఖాళీ, ఖాళీ, {0, ఖాళీ}, ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ};

#నిర్వచితమైతే KRB5
బాహ్య ssh_gssapi_mech gssapi_kerberos_mech;
#అయితే_ముగింపు

ssh_gssapi_mech* supported_mechs[]= {
#నిర్వచితమైతే KRB5
	&gssapi_kerberos_mech,
#అయితే_ముగింపు
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
స్థిర gss_OID_సమితి supported_oids;

శూన్య
ssh_gssapi_prepare_supported_oids(శూన్య)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, పూర్ణాంకం *present)
{
	ఒకవేళ (supported_oids == ఖాళీ)
		ssh_gssapi_prepare_supported_oids();
	తిరిగి gss_test_oid_సమితి_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
స్థిర OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 స్థితి_2;
	అక్షరం lname[NI_MAXHOST];
	gss_OID_సమితి oidset;

	ఒకవేళ (options.gss_strict_acceptor) {
		gss_create_ఖాళీలు_oid_సమితి(&స్థితి_2, &oidset);
		gss_కూడు_oid_సమితి_member(&స్థితి_2, ctx->oid, &oidset);

		ఒకవేళ (gethostname(lname, పరిమాణం(lname))) {
			gss_release_oid_సమితి(&స్థితి_2, &oidset);
			తిరిగి (-1);
		}

		ఒకవేళ (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_సమితి(&స్థితి_2, &oidset);
			తిరిగి (ctx->major);
		}

		ఒకవేళ ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    ఖాళీ, ఖాళీ)))
			ssh_gssapi_error(ctx);

		gss_release_oid_సమితి(&స్థితి_2, &oidset);
		తిరిగి (ctx->major);
	} లేకపోతే {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	తిరిగి GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	ఒకవేళ (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_సమితి_oid(*ctx, oid);
	తిరిగి (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
శూన్య
ssh_gssapi_supported_oids(gss_OID_సమితి *oidset)
{
	పూర్ణాంకం i = 0;
	OM_uint32 min_స్థితి;
	పూర్ణాంకం present;
	gss_OID_సమితి supported;

	gss_create_ఖాళీలు_oid_సమితి(&min_స్థితి, oidset);
	gss_indicate_mechs(&min_స్థితి, &supported);

	అయితే (supported_mechs[i]->name != ఖాళీ) {
		ఒకవేళ (GSS_ERROR(gss_test_oid_సమితి_member(&min_స్థితి,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		ఒకవేళ (present)
			gss_కూడు_oid_సమితి_member(&min_స్థితి,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_సమితి(&min_స్థితి, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_బఫరు_desc *recv_tok,
    gss_బఫరు_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 స్థితి_2;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, ఖాళీ, &ctx->client_creds);

	ఒకవేళ (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	ఒకవేళ (ctx->client_creds)
		debug("Received some client credentials");
	లేకపోతే
		debug("Got no client credentials");

	స్థితి_2 = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	ఒకవేళ (((flags == ఖాళీ) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		ఒకవేళ (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	తిరిగి (స్థితి_2);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
స్థిర OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_బఫరు_t ename, gss_బఫరు_t name)
{
	u_char *tok;
	OM_uint32 స్థానభ్రంశం;
	OM_uint32 oidl;

	tok = ename->విలువ;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	ఒకవేళ (ename->నిడివి < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		తిరిగి GSS_S_FAILURE;

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
	ఒకవేళ (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->నిడివి < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		తిరిగి GSS_S_FAILURE;

	స్థానభ్రంశం = oidl+6;

	ఒకవేళ (ename->నిడివి < స్థానభ్రంశం+4)
		తిరిగి GSS_S_FAILURE;

	name->నిడివి = get_u32(tok+స్థానభ్రంశం);
	స్థానభ్రంశం += 4;

	ఒకవేళ (UINT_MAX - స్థానభ్రంశం < name->నిడివి)
		తిరిగి GSS_S_FAILURE;
	ఒకవేళ (ename->నిడివి < స్థానభ్రంశం+name->నిడివి)
		తిరిగి GSS_S_FAILURE;

	name->విలువ = xmalloc(name->నిడివి+1);
	జ్ఞాపకం_నకలు(name->విలువ, tok+స్థానభ్రంశం, name->నిడివి);
	((అక్షరం *)name->విలువ)[name->నిడివి] = 0;

	తిరిగి GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	పూర్ణాంకం i = 0;

	gss_బఫరు_desc ename;

	client->userok = 0;
	client->mech = ఖాళీ;

	అయితే (supported_mechs[i]->name != ఖాళీ) {
		ఒకవేళ (supported_mechs[i]->oid.నిడివి == ctx->oid->నిడివి &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->నిడివి) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	ఒకవేళ (client->mech == ఖాళీ)
		తిరిగి GSS_S_FAILURE;

	ఒకవేళ ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, ఖాళీ))) {
		ssh_gssapi_error(ctx);
		తిరిగి (ctx->major);
	}

	ఒకవేళ ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		తిరిగి (ctx->major);
	}

	ఒకవేళ ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		తిరిగి (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	తిరిగి (ctx->major);
}

/* As user - called on fatal/exit */
శూన్య
ssh_gssapi_cleanup_creds(శూన్య)
{
	ఒకవేళ (gssapi_client.store.filename != ఖాళీ) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
శూన్య
ssh_gssapi_storecreds(శూన్య)
{
	ఒకవేళ (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		తిరిగి;
	}

	ఒకవేళ (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		తిరిగి;
	}

	ఒకవేళ (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} లేకపోతే
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
శూన్య
ssh_gssapi_do_బిడ్డ(అక్షరం ***envp, u_int *envsizep)
{

	ఒకవేళ (gssapi_client.store.envvar != ఖాళీ &&
	    gssapi_client.store.envval != ఖాళీ) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		బిడ్డ_సమితి_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

శూన్య
ssh_gssapi_cleanup_global_client(శూన్య)
{
	OM_uint32 lmin;

	gss_release_బఫరు(&lmin, &gssapi_client.displayname);
	gss_release_బఫరు(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, పరిమాణం(ssh_gssapi_client));
}

/* Privileged */
పూర్ణాంకం
ssh_gssapi_userok(అక్షరం *user)
{
	ఒకవేళ (gssapi_client.exportedname.నిడివి == 0 ||
	    gssapi_client.exportedname.విలువ == ఖాళీ) {
		debug("No suitable client data");
		తిరిగి 0;
	}
	ఒకవేళ (gssapi_client.mech && gssapi_client.mech->userok)
		ఒకవేళ ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			తిరిగి 1;
		} లేకపోతే {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			తిరిగి 0;
		}
	లేకపోతే
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	తిరిగి (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_బఫరు_t gssbuf, gss_బఫరు_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, ఖాళీ);

	తిరిగి (ctx->major);
}

/* Privileged */
స్థిరరాశి అక్షరం *ssh_gssapi_displayname(శూన్య)
{
	ఒకవేళ (gssapi_client.displayname.నిడివి == 0 ||
	    gssapi_client.displayname.విలువ == ఖాళీ)
		తిరిగి ఖాళీ;
	తిరిగి (అక్షరం *)gssapi_client.displayname.విలువ;
}

#అయితే_ముగింపు
