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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SSH_GSS_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SSH_GSS_H

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GSSAPI_H
#ਅਨ੍ਤਰ੍ਭਾਵ <gssapi.h>
#ਜਾਂਜੇ defined(HAVE_GSSAPI_GSSAPI_H)
#ਅਨ੍ਤਰ੍ਭਾਵ <gssapi/gssapi.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  ਜੇ !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#ਜੇ_ਅੰਤ /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_RESPONSE		60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN			61
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERROR			64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK			65
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC			66

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_GSS_OIDTYPE 0x06

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	ਅੱਖਰ *filename;
	ਅੱਖਰ *envvar;
	ਅੱਖਰ *envval;
	ਖਾਲੀ *ਅੰਕੜੇ;
} ssh_gssapi_ccache;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	gss_ਬਫਰ_desc displayname;
	gss_ਬਫਰ_desc exportedname;
	gss_cred_id_t creds;
	ਬਣਤਰ ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	ਪੂਰਨ userok;
} ssh_gssapi_client;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ssh_gssapi_mech_struct {
	ਅੱਖਰ *enc_name;
	ਅੱਖਰ *name;
	gss_OID_desc oid;
	ਪੂਰਨ (*dochild) (ssh_gssapi_client *);
	ਪੂਰਨ (*userok) (ssh_gssapi_client *, ਅੱਖਰ *);
	ਪੂਰਨ (*localname) (ssh_gssapi_client *, ਅੱਖਰ **);
	ਖਾਲੀ (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

ਬਾਹਰੀ ssh_gssapi_mech *supported_mechs[];

ਪੂਰਨ  ssh_gssapi_check_oid(Gssctxt *, ਖਾਲੀ *, ਮਾਪ_t);
ਖਾਲੀ ssh_gssapi_ਸੈੱਟ_oid_ਅੰਕੜੇ(Gssctxt *, ਖਾਲੀ *, ਮਾਪ_t);
ਖਾਲੀ ssh_gssapi_ਸੈੱਟ_oid(Gssctxt *, gss_OID);
ਖਾਲੀ ssh_gssapi_supported_oids(gss_OID_ਸੈੱਟ *);
ਖਾਲੀ ssh_gssapi_prepare_supported_oids(ਖਾਲੀ);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, ਪੂਰਨ *);

ਬਣਤਰ sshbuf;
ਪੂਰਨ ssh_gssapi_get_ਬਫਰ_desc(ਬਣਤਰ sshbuf *, gss_ਬਫਰ_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ਅਚਲ ਅੱਖਰ *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, ਪੂਰਨ,
    gss_ਬਫਰ_desc *, gss_ਬਫਰ_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_ਬਫਰ_desc *, gss_ਬਫਰ_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
ਖਾਲੀ ssh_gssapi_error(Gssctxt *);
ਅੱਖਰ *ssh_gssapi_ਆਖਰੀ_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
ਖਾਲੀ ssh_gssapi_build_ctx(Gssctxt **);
ਖਾਲੀ ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_ਬਫਰ_t, gss_ਬਫਰ_t);
ਖਾਲੀ ssh_gssapi_buildmic(ਬਣਤਰ sshbuf *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਬਣਤਰ sshbuf *);
ਪੂਰਨ ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ਅਚਲ ਅੱਖਰ *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
ਪੂਰਨ ssh_gssapi_userok(ਅੱਖਰ *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_ਬਫਰ_t, gss_ਬਫਰ_t);
ਖਾਲੀ ssh_gssapi_do_ਬੱਚਾ(ਅੱਖਰ ***, u_int *);
ਖਾਲੀ ssh_gssapi_cleanup_creds(ਖਾਲੀ);
ਖਾਲੀ ssh_gssapi_storecreds(ਖਾਲੀ);
ਅਚਲ ਅੱਖਰ *ssh_gssapi_displayname(ਖਾਲੀ);
ਖਾਲੀ ssh_gssapi_cleanup_global_client(ਖਾਲੀ);

#ਜੇ_ਅੰਤ /* GSSAPI */

#ਜੇ_ਅੰਤ /* _SSH_GSS_H */
