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

#ifndef _SSH_GSS_H
#define _SSH_GSS_H

#ifdef GSSAPI

#ifdef HAVE_GSSAPI_H
#ಅನ್ತರ್ಭಾವ <gssapi.h>
#ನೋಚೇದ್ಯದಿ defined(HAVE_GSSAPI_GSSAPI_H)
#ಅನ್ತರ್ಭಾವ <gssapi/gssapi.h>
#endif

#ifdef KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  ಯದಿ !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#endif /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE		60
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN			61
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERROR			64
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK			65
#define SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC			66

#define SSH_GSS_OIDTYPE 0x06

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ {
	ವರ್ಣ *filename;
	ವರ್ಣ *envvar;
	ವರ್ಣ *envval;
	ಶೂನ್ಯ *data;
} ssh_gssapi_ccache;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ {
	gss_buffer_desc displayname;
	gss_buffer_desc exportedname;
	gss_cred_id_t creds;
	ಸಂರಚನಾ ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	ಪೂರ್ಣಾಙ್ಕ userok;
} ssh_gssapi_client;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ ssh_gssapi_mech_struct {
	ವರ್ಣ *enc_name;
	ವರ್ಣ *name;
	gss_OID_desc oid;
	ಪೂರ್ಣಾಙ್ಕ (*dochild) (ssh_gssapi_client *);
	ಪೂರ್ಣಾಙ್ಕ (*userok) (ssh_gssapi_client *, ವರ್ಣ *);
	ಪೂರ್ಣಾಙ್ಕ (*localname) (ssh_gssapi_client *, ವರ್ಣ **);
	ಶೂನ್ಯ (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ {
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

ಪೂರ್ಣಾಙ್ಕ  ssh_gssapi_check_oid(Gssctxt *, ಶೂನ್ಯ *, size_t);
ಶೂನ್ಯ ssh_gssapi_set_oid_data(Gssctxt *, ಶೂನ್ಯ *, size_t);
ಶೂನ್ಯ ssh_gssapi_set_oid(Gssctxt *, gss_OID);
ಶೂನ್ಯ ssh_gssapi_supported_oids(gss_OID_set *);
ಶೂನ್ಯ ssh_gssapi_prepare_supported_oids(ಶೂನ್ಯ);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, ಪೂರ್ಣಾಙ್ಕ *);

ಸಂರಚನಾ sshbuf;
ಪೂರ್ಣಾಙ್ಕ ssh_gssapi_get_buffer_desc(ಸಂರಚನಾ sshbuf *, gss_buffer_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ಧ್ರುವ ವರ್ಣ *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, ಪೂರ್ಣಾಙ್ಕ,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
ಶೂನ್ಯ ssh_gssapi_error(Gssctxt *);
ವರ್ಣ *ssh_gssapi_last_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
ಶೂನ್ಯ ssh_gssapi_build_ctx(Gssctxt **);
ಶೂನ್ಯ ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_buffer_t, gss_buffer_t);
ಶೂನ್ಯ ssh_gssapi_buildmic(ಸಂರಚನಾ sshbuf *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ಧ್ರುವ ವರ್ಣ *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
ಪೂರ್ಣಾಙ್ಕ ssh_gssapi_userok(ವರ್ಣ *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
ಶೂನ್ಯ ssh_gssapi_do_child(ವರ್ಣ ***, u_int *);
ಶೂನ್ಯ ssh_gssapi_cleanup_creds(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_gssapi_storecreds(ಶೂನ್ಯ);
ಧ್ರುವ ವರ್ಣ *ssh_gssapi_displayname(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_gssapi_cleanup_global_client(ಶೂನ್ಯ);

#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
