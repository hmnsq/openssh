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

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् GSSAPI

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/param.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"

#अन्तर्भाव "ssh-gss.h"

बाह्य ServerOptions options;

स्थिर ssh_gssapi_client gssapi_client =
    { GSS_C_रिक्तानि_बफर, GSS_C_रिक्तानि_बफर,
    GSS_C_NO_CREDENTIAL, रिक्त, {रिक्त, रिक्त, रिक्त, रिक्त}, 0};

ssh_gssapi_mech gssapi_null_mech =
    { रिक्त, रिक्त, {0, रिक्त}, रिक्त, रिक्त, रिक्त, रिक्त};

#यदि_परिभाषितम् KRB5
बाह्य ssh_gssapi_mech gssapi_kerberos_mech;
#यदि_अन्तः

ssh_gssapi_mech* supported_mechs[]= {
#यदि_परिभाषितम् KRB5
	&gssapi_kerberos_mech,
#यदि_अन्तः
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
स्थिर gss_OID_समुच्चयः supported_oids;

शून्य
ssh_gssapi_prepare_supported_oids(शून्य)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, पूर्णाङ्क *present)
{
	यदि (supported_oids == रिक्त)
		ssh_gssapi_prepare_supported_oids();
	प्रत्यागम gss_test_oid_समुच्चयः_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
स्थिर OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 स्थितिः;
	वर्ण lname[NI_MAXHOST];
	gss_OID_समुच्चयः oidset;

	यदि (options.gss_strict_acceptor) {
		gss_create_रिक्तानि_oid_समुच्चयः(&स्थितिः, &oidset);
		gss_सङ्कलय_oid_समुच्चयः_member(&स्थितिः, ctx->oid, &oidset);

		यदि (gethostname(lname, परिमाण(lname))) {
			gss_release_oid_समुच्चयः(&स्थितिः, &oidset);
			प्रत्यागम (-1);
		}

		यदि (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_समुच्चयः(&स्थितिः, &oidset);
			प्रत्यागम (ctx->major);
		}

		यदि ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    रिक्त, रिक्त)))
			ssh_gssapi_error(ctx);

		gss_release_oid_समुच्चयः(&स्थितिः, &oidset);
		प्रत्यागम (ctx->major);
	} अन्यथा {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	प्रत्यागम GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	यदि (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_समुच्चयः_oid(*ctx, oid);
	प्रत्यागम (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
शून्य
ssh_gssapi_supported_oids(gss_OID_समुच्चयः *oidset)
{
	पूर्णाङ्क i = 0;
	OM_uint32 min_स्थितिः;
	पूर्णाङ्क present;
	gss_OID_समुच्चयः supported;

	gss_create_रिक्तानि_oid_समुच्चयः(&min_स्थितिः, oidset);
	gss_indicate_mechs(&min_स्थितिः, &supported);

	यावत् (supported_mechs[i]->name != रिक्त) {
		यदि (GSS_ERROR(gss_test_oid_समुच्चयः_member(&min_स्थितिः,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		यदि (present)
			gss_सङ्कलय_oid_समुच्चयः_member(&min_स्थितिः,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_समुच्चयः(&min_स्थितिः, &supported);
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
	OM_uint32 स्थितिः;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, रिक्त, &ctx->client_creds);

	यदि (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	यदि (ctx->client_creds)
		debug("Received some client credentials");
	अन्यथा
		debug("Got no client credentials");

	स्थितिः = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	यदि (((flags == रिक्त) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		यदि (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	प्रत्यागम (स्थितिः);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
स्थिर OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_बफर_t ename, gss_बफर_t name)
{
	u_char *tok;
	OM_uint32 विस्थापनम्;
	OM_uint32 oidl;

	tok = ename->मानम्;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	यदि (ename->दीर्घता < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		प्रत्यागम GSS_S_FAILURE;

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
	यदि (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->दीर्घता < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		प्रत्यागम GSS_S_FAILURE;

	विस्थापनम् = oidl+6;

	यदि (ename->दीर्घता < विस्थापनम्+4)
		प्रत्यागम GSS_S_FAILURE;

	name->दीर्घता = get_u32(tok+विस्थापनम्);
	विस्थापनम् += 4;

	यदि (UINT_MAX - विस्थापनम् < name->दीर्घता)
		प्रत्यागम GSS_S_FAILURE;
	यदि (ename->दीर्घता < विस्थापनम्+name->दीर्घता)
		प्रत्यागम GSS_S_FAILURE;

	name->मानम् = xmalloc(name->दीर्घता+1);
	स्मृतिं_प्रतिलिख(name->मानम्, tok+विस्थापनम्, name->दीर्घता);
	((वर्ण *)name->मानम्)[name->दीर्घता] = 0;

	प्रत्यागम GSS_S_COMPLETE;
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	पूर्णाङ्क i = 0;

	gss_बफर_desc ename;

	client->userok = 0;
	client->mech = रिक्त;

	यावत् (supported_mechs[i]->name != रिक्त) {
		यदि (supported_mechs[i]->oid.दीर्घता == ctx->oid->दीर्घता &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->दीर्घता) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	यदि (client->mech == रिक्त)
		प्रत्यागम GSS_S_FAILURE;

	यदि ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, रिक्त))) {
		ssh_gssapi_error(ctx);
		प्रत्यागम (ctx->major);
	}

	यदि ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		प्रत्यागम (ctx->major);
	}

	यदि ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		प्रत्यागम (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	प्रत्यागम (ctx->major);
}

/* As user - called on fatal/exit */
शून्य
ssh_gssapi_cleanup_creds(शून्य)
{
	यदि (gssapi_client.store.filename != रिक्त) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",
		    gssapi_client.store.filename);
		unlink(gssapi_client.store.filename);
	}
}

/* As user */
शून्य
ssh_gssapi_storecreds(शून्य)
{
	यदि (!gssapi_client.userok) {
		debug_f("GSSAPI client was not authorized, doing nothing");
		प्रत्यागम;
	}

	यदि (options.gss_deleg_creds == 0) {
		debug_f("delegate credential is disabled, doing nothing");
		प्रत्यागम;
	}

	यदि (gssapi_client.mech && gssapi_client.mech->storecreds) {
		(*gssapi_client.mech->storecreds)(&gssapi_client);
	} अन्यथा
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
शून्य
ssh_gssapi_do_child(वर्ण ***envp, u_int *envsizep)
{

	यदि (gssapi_client.store.envvar != रिक्त &&
	    gssapi_client.store.envval != रिक्त) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_समुच्चयः_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

शून्य
ssh_gssapi_cleanup_global_client(शून्य)
{
	OM_uint32 lmin;

	gss_release_बफर(&lmin, &gssapi_client.displayname);
	gss_release_बफर(&lmin, &gssapi_client.exportedname);
	gss_release_cred(&lmin, &gssapi_client.creds);
	explicit_bzero(&gssapi_client, परिमाण(ssh_gssapi_client));
}

/* Privileged */
पूर्णाङ्क
ssh_gssapi_userok(वर्ण *user)
{
	यदि (gssapi_client.exportedname.दीर्घता == 0 ||
	    gssapi_client.exportedname.मानम् == रिक्त) {
		debug("No suitable client data");
		प्रत्यागम 0;
	}
	यदि (gssapi_client.mech && gssapi_client.mech->userok)
		यदि ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.userok = 1;
			प्रत्यागम 1;
		} अन्यथा {
			/* Destroy delegated credentials if userok fails */
			ssh_gssapi_cleanup_global_client();
			प्रत्यागम 0;
		}
	अन्यथा
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	प्रत्यागम (0);
}

/* Privileged */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_बफर_t gssbuf, gss_बफर_t gssmic)
{
	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, रिक्त);

	प्रत्यागम (ctx->major);
}

/* Privileged */
ध्रुव वर्ण *ssh_gssapi_displayname(शून्य)
{
	यदि (gssapi_client.displayname.दीर्घता == 0 ||
	    gssapi_client.displayname.मानम् == रिक्त)
		प्रत्यागम रिक्त;
	प्रत्यागम (वर्ण *)gssapi_client.displayname.मानम्;
}

#यदि_अन्तः
