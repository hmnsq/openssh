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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SSH_GSS_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SSH_GSS_H

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GSSAPI_H
#ಅನ್ತರ್ಭಾವ <gssapi.h>
#ಅಥವಾಆದರೆ defined(HAVE_GSSAPI_GSSAPI_H)
#ಅನ್ತರ್ಭಾವ <gssapi/gssapi.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  ಆದರೆ !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE		60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN			61
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERROR			64
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK			65
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC			66

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_GSS_OIDTYPE 0x06

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	ಅಕ್ಷರ *filename;
	ಅಕ್ಷರ *envvar;
	ಅಕ್ಷರ *envval;
	ಶೂನ್ಯ *ದತ್ತಾಂಶ;
} ssh_gssapi_ccache;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	gss_ಬಫರ್_desc displayname;
	gss_ಬಫರ್_desc exportedname;
	gss_cred_id_t creds;
	ರಚನೆ ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	ಪೂರ್ಣಾಂಕ userok;
} ssh_gssapi_client;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ssh_gssapi_mech_struct {
	ಅಕ್ಷರ *enc_name;
	ಅಕ್ಷರ *name;
	gss_OID_desc oid;
	ಪೂರ್ಣಾಂಕ (*dochild) (ssh_gssapi_client *);
	ಪೂರ್ಣಾಂಕ (*userok) (ssh_gssapi_client *, ಅಕ್ಷರ *);
	ಪೂರ್ಣಾಂಕ (*localname) (ssh_gssapi_client *, ಅಕ್ಷರ **);
	ಶೂನ್ಯ (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

ಬಾಹ್ಯ ssh_gssapi_mech *supported_mechs[];

ಪೂರ್ಣಾಂಕ  ssh_gssapi_check_oid(Gssctxt *, ಶೂನ್ಯ *, ಗಾತ್ರ_t);
ಶೂನ್ಯ ssh_gssapi_ಗಣ_oid_ದತ್ತಾಂಶ(Gssctxt *, ಶೂನ್ಯ *, ಗಾತ್ರ_t);
ಶೂನ್ಯ ssh_gssapi_ಗಣ_oid(Gssctxt *, gss_OID);
ಶೂನ್ಯ ssh_gssapi_supported_oids(gss_OID_ಗಣ *);
ಶೂನ್ಯ ssh_gssapi_prepare_supported_oids(ಶೂನ್ಯ);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, ಪೂರ್ಣಾಂಕ *);

ರಚನೆ sshbuf;
ಪೂರ್ಣಾಂಕ ssh_gssapi_get_ಬಫರ್_desc(ರಚನೆ sshbuf *, gss_ಬಫರ್_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, ಪೂರ್ಣಾಂಕ,
    gss_ಬಫರ್_desc *, gss_ಬಫರ್_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_ಬಫರ್_desc *, gss_ಬಫರ್_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
ಶೂನ್ಯ ssh_gssapi_error(Gssctxt *);
ಅಕ್ಷರ *ssh_gssapi_ಕೊನೆಯ_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
ಶೂನ್ಯ ssh_gssapi_build_ctx(Gssctxt **);
ಶೂನ್ಯ ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_ಬಫರ್_t, gss_ಬಫರ್_t);
ಶೂನ್ಯ ssh_gssapi_buildmic(ರಚನೆ sshbuf *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
ಪೂರ್ಣಾಂಕ ssh_gssapi_userok(ಅಕ್ಷರ *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_ಬಫರ್_t, gss_ಬಫರ್_t);
ಶೂನ್ಯ ssh_gssapi_do_ಮಗು(ಅಕ್ಷರ ***, u_int *);
ಶೂನ್ಯ ssh_gssapi_cleanup_creds(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_gssapi_storecreds(ಶೂನ್ಯ);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_gssapi_displayname(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_gssapi_cleanup_global_client(ಶೂನ್ಯ);

#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

#ಆದರೆ_ಅಂತ್ಯ /* _SSH_GSS_H */
