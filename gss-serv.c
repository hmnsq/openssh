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

#समावेश "includes.h"

#अगर_घोषित GSSAPI

#समावेश <sys/types.h>
#समावेश <sys/param.h>
#समावेश <sys/queue.h>

#समावेश <netdb.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "log.h"
#समावेश "channels.h"
#समावेश "session.h"
#समावेश "misc.h"
#समावेश "servconf.h"

#समावेश "ssh-gss.h"

बाह्य ServerOptions options;

अटल ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_बफर, GSS_C_EMPTY_बफर,
    GSS_C_NO_CREDENTIAL, शून्य, {शून्य, शून्य, शून्य, शून्य}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { शून्य, शून्य, {0, शून्य}, शून्य, शून्य, शून्य, शून्य};

#अगर_घोषित KRB5
बाह्य ssh_gssapi_mech gssapi_kerberos_mech;
#पूर्ण_अगर

ssh_gssapi_mech* supported_mechs[]= {
#अगर_घोषित KRB5
	&gssapi_kerberos_mech,
#पूर्ण_अगर
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
अटल gss_OID_set supported_oids;

व्योम
ssh_gssapi_prepare_supported_oids(व्योम)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, पूर्णांक *present)
{
	अगर (supported_oids == शून्य)
		ssh_gssapi_prepare_supported_oids();
	वापस gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
अटल OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	अक्षर lname[NI_MAXHOST];
	gss_OID_set oidset;

	अगर (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		अगर (gethostname(lname, माप(lname))) {
			gss_release_oid_set(&status, &oidset);
			वापस (-1);
		}

		अगर (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			वापस (ctx->major);
		}

		अगर ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    शून्य, शून्य)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		वापस (ctx->major);
	} अन्यथा {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	वापस GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	अगर (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	वापस (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
व्योम
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	पूर्णांक i = 0;
	OM_uint32 min_status;
	पूर्णांक present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);
	gss_indicate_mechs(&min_status, &supported);

	जबतक (supported_mechs[i]->name != शून्य) {
		अगर (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		अगर (present)
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
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_बफर_desc *recv_tok,
    gss_बफर_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 status;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, शून्य, &ctx->client_creds);

	अगर (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	अगर (ctx->client_creds)
		debug("Received some client credentials");
	अन्यथा
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	अगर (((flags == शून्य) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		अगर (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	वापस (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
अटल OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_बफर_t ename, gss_बफर_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->मूल्य;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	अगर (ename->लंबाई < 6 || स_भेद(tok, "\x04\x01", 2) != 0)
		वापस GSS_S_FAILURE;

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
	अगर (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->लंबाई < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		वापस GSS_S_FAILURE;

	offset = oidl+6;

	अगर (ename->लंबाई < offset+4)
		वापस GSS_S_FAILURE;

	name->लंबाई = get_u32(tok+offset);
	offset += 4;

	अगर (अच_पूर्णांक_उच्च - offset < name->लंबाई)
		वापस GSS_S_FAILURE;
	अगर (ename->लंबाई < offset+name->लंबाई)
		वापस GSS_S_FAILURE;

	name->मूल्य = xmalloc(name->लंबाई+1);
	स_नकल(name->मूल्य, tok+offset, name->लंबाई);
	((अक्षर *)name->मूल्य)[name->लंबाई] = 0;

	वापस GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	पूर्णांक i = 0;

	gss_बफर_desc ename;

	client->userok = 0;
	client->mech = शून्य;

	जबतक (supported_mechs[i]->name != शून्य) {
		अगर (supported_mechs[i]->oid.लंबाई == ctx->oid->लंबाई &&
		    (स_भेद(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->लंबाई) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	अगर (client->mech == शून्य)
		वापस GSS_S_FAILURE;

	अगर ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, शून्य))) {
		ssh_gssapi_error(ctx);
		वापस (ctx->major);
	}

	अगर ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		वापस (ctx->major);
	}

	अगर ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		वापस (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	वापस (ctx->major);
}

/* As user - called on fatal/exit */
व्योम
ssh_gssapi_cleanup_creds(व्योम)
{
	अगर (gssapi_client.store.filename != शून्य) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
व्योम
ssh_gssapi_storecreds(व्योम)
{
	अगर (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		वापस;
	}

	अगर (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		वापस;
	}

	अगर (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} अन्यथा
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
व्योम
ssh_gssapi_do_child(अक्षर ***envp, u_int *envsizep)
{

	अगर (gssapi_client.store.envvar != शून्य &&
	    gssapi_client.store.envval != शून्य) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

व्योम
ssh_gssapi_cleanup_global_client(व्योम)
{
	OM_uint32 lmin;

	gss_release_बफर(&lmin, &gssapi_client.displayname);
	gss_release_बफर(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, माप(ssh_gssapi_client));
}

/* Privileged */
पूर्णांक
ssh_gssapi_userok(अक्षर *user)
{
	अगर (gssapi_client.exportedname.लंबाई == 0 ||
	    gssapi_client.exportedname.मूल्य == शून्य) {
		debug("No suitable client data");
		वापस 0;
	}
	अगर (gssapi_client.mech && gssapi_client.mech->userok)
		अगर ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			वापस 1;
		} अन्यथा {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			वापस 0;
		}
	अन्यथा
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	वापस (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_बफर_t gssbuf, gss_बफर_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, शून्य);

	वापस (ctx->major);
}

/* Privileged */
स्थिर अक्षर *ssh_gssapi_displayname(व्योम)
{
	अगर (gssapi_client.displayname.लंबाई == 0 ||
	    gssapi_client.displayname.मूल्य == शून्य)
		वापस शून्य;
	वापस (अक्षर *)gssapi_client.displayname.मूल्य;
}

#पूर्ण_अगर
