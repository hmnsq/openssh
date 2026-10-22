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

#अगर_अघोषित _SSH_GSS_H
#घोषणा _SSH_GSS_H

#अगर_घोषित GSSAPI

#अगर_घोषित HAVE_GSSAPI_H
#समावेश <gssapi.h>
#या_अगर defined(HAVE_GSSAPI_GSSAPI_H)
#समावेश <gssapi/gssapi.h>
#पूर्ण_अगर

#अगर_घोषित KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  अगर !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#पूर्ण_अगर /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_RESPONSE		60
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_TOKEN			61
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_ERROR			64
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK			65
#घोषणा SSH2_संदेश_USERAUTH_GSSAPI_MIC			66

#घोषणा SSH_GSS_OIDTYPE 0x06

प्रकार काष्ठा {
	अक्षर *filename;
	अक्षर *envvar;
	अक्षर *envval;
	व्योम *तथ्य;
} ssh_gssapi_ccache;

प्रकार काष्ठा {
	gss_बफर_desc displayname;
	gss_बफर_desc exportedname;
	gss_cred_id_t creds;
	काष्ठा ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	पूर्णांक userok;
} ssh_gssapi_client;

प्रकार काष्ठा ssh_gssapi_mech_struct {
	अक्षर *enc_name;
	अक्षर *name;
	gss_OID_desc oid;
	पूर्णांक (*dochild) (ssh_gssapi_client *);
	पूर्णांक (*userok) (ssh_gssapi_client *, अक्षर *);
	पूर्णांक (*localname) (ssh_gssapi_client *, अक्षर **);
	व्योम (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

प्रकार काष्ठा {
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

पूर्णांक  ssh_gssapi_check_oid(Gssctxt *, व्योम *, माप_प्रकार);
व्योम ssh_gssapi_set_oid_तथ्य(Gssctxt *, व्योम *, माप_प्रकार);
व्योम ssh_gssapi_set_oid(Gssctxt *, gss_OID);
व्योम ssh_gssapi_supported_oids(gss_OID_set *);
व्योम ssh_gssapi_prepare_supported_oids(व्योम);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, पूर्णांक *);

काष्ठा sshbuf;
पूर्णांक ssh_gssapi_get_बफर_desc(काष्ठा sshbuf *, gss_बफर_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, स्थिर अक्षर *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, पूर्णांक,
    gss_बफर_desc *, gss_बफर_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_बफर_desc *, gss_बफर_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
व्योम ssh_gssapi_error(Gssctxt *);
अक्षर *ssh_gssapi_last_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
व्योम ssh_gssapi_build_ctx(Gssctxt **);
व्योम ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_बफर_t, gss_बफर_t);
व्योम ssh_gssapi_buildmic(काष्ठा sshbuf *, स्थिर अक्षर *,
    स्थिर अक्षर *, स्थिर अक्षर *, स्थिर काष्ठा sshbuf *);
पूर्णांक ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, स्थिर अक्षर *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
पूर्णांक ssh_gssapi_userok(अक्षर *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_बफर_t, gss_बफर_t);
व्योम ssh_gssapi_do_child(अक्षर ***, u_int *);
व्योम ssh_gssapi_cleanup_creds(व्योम);
व्योम ssh_gssapi_storecreds(व्योम);
स्थिर अक्षर *ssh_gssapi_displayname(व्योम);
व्योम ssh_gssapi_cleanup_global_client(व्योम);

#पूर्ण_अगर /* GSSAPI */

#पूर्ण_अगर /* _SSH_GSS_H */
