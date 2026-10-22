/* $OpenBSD: ssh-gss.h,v 1.19 2026/10/07 09:00:11 robert Exp $ */
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

#यदि_अपरिभाषितम् _SSH_GSS_H
#परिभाषय _SSH_GSS_H

#यदि_परिभाषितम् GSSAPI

#यदि_परिभाषितम् HAVE_GSSAPI_H
#अन्तर्भाव <gssapi.h>
#नोचेद्यदि defined(HAVE_GSSAPI_GSSAPI_H)
#अन्तर्भाव <gssapi/gssapi.h>
#यदि_अन्तः

#यदि_परिभाषितम् KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  यदि !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#यदि_अन्तः /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_RESPONSE		60
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_TOKEN			61
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_ERROR			64
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_ERRTOK			65
#परिभाषय SSH2_सन्देशः_USERAUTH_GSSAPI_MIC			66

#परिभाषय SSH_GSS_OIDTYPE 0x06

प्रकारनिर्देश संरचना {
	वर्ण *filename;
	वर्ण *envvar;
	वर्ण *envval;
	शून्य *दत्त;
} ssh_gssapi_ccache;

प्रकारनिर्देश संरचना {
	gss_बफर_desc displayname;
	gss_बफर_desc exportedname;
	gss_cred_id_t creds;
	संरचना ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	पूर्णाङ्क userok;
} ssh_gssapi_client;

प्रकारनिर्देश संरचना ssh_gssapi_mech_struct {
	वर्ण *enc_name;
	वर्ण *name;
	gss_OID_desc oid;
	पूर्णाङ्क (*dochild) (ssh_gssapi_client *);
	पूर्णाङ्क (*userok) (ssh_gssapi_client *, वर्ण *);
	पूर्णाङ्क (*localname) (ssh_gssapi_client *, वर्ण **);
	शून्य (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

प्रकारनिर्देश संरचना {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

बाह्य ssh_gssapi_mech *supported_mechs[];

पूर्णाङ्क  ssh_gssapi_check_oid(Gssctxt *, शून्य *, आकार_t);
शून्य ssh_gssapi_समुच्चयः_oid_दत्त(Gssctxt *, शून्य *, आकार_t);
शून्य ssh_gssapi_समुच्चयः_oid(Gssctxt *, gss_OID);
शून्य ssh_gssapi_supported_oids(gss_OID_समुच्चयः *);
शून्य ssh_gssapi_prepare_supported_oids(शून्य);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, पूर्णाङ्क *);

संरचना sshbuf;
पूर्णाङ्क ssh_gssapi_get_बफर_desc(संरचना sshbuf *, gss_बफर_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ध्रुव वर्ण *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, पूर्णाङ्क,
    gss_बफर_desc *, gss_बफर_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_बफर_desc *, gss_बफर_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
शून्य ssh_gssapi_error(Gssctxt *);
वर्ण *ssh_gssapi_चरमः_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
शून्य ssh_gssapi_build_ctx(Gssctxt **);
शून्य ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_बफर_t, gss_बफर_t);
शून्य ssh_gssapi_buildmic(संरचना sshbuf *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव संरचना sshbuf *);
पूर्णाङ्क ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ध्रुव वर्ण *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
पूर्णाङ्क ssh_gssapi_userok(वर्ण *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_बफर_t, gss_बफर_t);
शून्य ssh_gssapi_do_child(वर्ण ***, u_int *);
शून्य ssh_gssapi_cleanup_creds(शून्य);
शून्य ssh_gssapi_storecreds(शून्य);
ध्रुव वर्ण *ssh_gssapi_displayname(शून्य);
शून्य ssh_gssapi_cleanup_global_client(शून्य);

#यदि_अन्तः /* GSSAPI */

#यदि_अन्तः /* _SSH_GSS_H */
