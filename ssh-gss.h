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
#অন্তর্ভাব <gssapi.h>
#নোচেদ্যদি defined(HAVE_GSSAPI_GSSAPI_H)
#অন্তর্ভাব <gssapi/gssapi.h>
#endif

#ifdef KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  যদি !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#endif /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#define SSH2_বার্তা_USERAUTH_GSSAPI_RESPONSE		60
#define SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN			61
#define SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#define SSH2_বার্তা_USERAUTH_GSSAPI_ERROR			64
#define SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK			65
#define SSH2_বার্তা_USERAUTH_GSSAPI_MIC			66

#define SSH_GSS_OIDTYPE 0x06

প্রকারনির্দেশ সংরচনা {
	বর্ণ *filename;
	বর্ণ *envvar;
	বর্ণ *envval;
	শূন্য *data;
} ssh_gssapi_ccache;

প্রকারনির্দেশ সংরচনা {
	gss_buffer_desc displayname;
	gss_buffer_desc exportedname;
	gss_cred_id_t creds;
	সংরচনা ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	পূর্ণাঙ্ক userok;
} ssh_gssapi_client;

প্রকারনির্দেশ সংরচনা ssh_gssapi_mech_struct {
	বর্ণ *enc_name;
	বর্ণ *name;
	gss_OID_desc oid;
	পূর্ণাঙ্ক (*dochild) (ssh_gssapi_client *);
	পূর্ণাঙ্ক (*userok) (ssh_gssapi_client *, বর্ণ *);
	পূর্ণাঙ্ক (*localname) (ssh_gssapi_client *, বর্ণ **);
	শূন্য (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

প্রকারনির্দেশ সংরচনা {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

বাহ্য ssh_gssapi_mech *supported_mechs[];

পূর্ণাঙ্ক  ssh_gssapi_check_oid(Gssctxt *, শূন্য *, size_t);
শূন্য ssh_gssapi_set_oid_data(Gssctxt *, শূন্য *, size_t);
শূন্য ssh_gssapi_set_oid(Gssctxt *, gss_OID);
শূন্য ssh_gssapi_supported_oids(gss_OID_set *);
শূন্য ssh_gssapi_prepare_supported_oids(শূন্য);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, পূর্ণাঙ্ক *);

সংরচনা sshbuf;
পূর্ণাঙ্ক ssh_gssapi_get_buffer_desc(সংরচনা sshbuf *, gss_buffer_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ধ্রুব বর্ণ *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, পূর্ণাঙ্ক,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
শূন্য ssh_gssapi_error(Gssctxt *);
বর্ণ *ssh_gssapi_last_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
শূন্য ssh_gssapi_build_ctx(Gssctxt **);
শূন্য ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_buffer_t, gss_buffer_t);
শূন্য ssh_gssapi_buildmic(সংরচনা sshbuf *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব সংরচনা sshbuf *);
পূর্ণাঙ্ক ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ধ্রুব বর্ণ *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
পূর্ণাঙ্ক ssh_gssapi_userok(বর্ণ *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
শূন্য ssh_gssapi_do_child(বর্ণ ***, u_int *);
শূন্য ssh_gssapi_cleanup_creds(শূন্য);
শূন্য ssh_gssapi_storecreds(শূন্য);
ধ্রুব বর্ণ *ssh_gssapi_displayname(শূন্য);
শূন্য ssh_gssapi_cleanup_global_client(শূন্য);

#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
