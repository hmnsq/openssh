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

#اگر_غیر_تعریف_شدہ _SSH_GSS_H
#تعریف_کرو _SSH_GSS_H

#اگر_تعریف_شدہ GSSAPI

#اگر_تعریف_شدہ HAVE_GSSAPI_H
#شامل <gssapi.h>
#وگرنہ_اگر defined(HAVE_GSSAPI_GSSAPI_H)
#شامل <gssapi/gssapi.h>
#اگر_ختم

#اگر_تعریف_شدہ KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  اگر !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#اگر_ختم /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_RESPONSE		60
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_TOKEN			61
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_ERROR			64
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK			65
#تعریف_کرو SSH2_پیغام_USERAUTH_GSSAPI_MIC			66

#تعریف_کرو SSH_GSS_OIDTYPE 0x06

قسمتعریف ساخت {
	حرف *filename;
	حرف *envvar;
	حرف *envval;
	خالی *ڈیٹا;
} ssh_gssapi_ccache;

قسمتعریف ساخت {
	gss_بفر_desc displayname;
	gss_بفر_desc exportedname;
	gss_cred_id_t creds;
	ساخت ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	صحیح userok;
} ssh_gssapi_client;

قسمتعریف ساخت ssh_gssapi_mech_struct {
	حرف *enc_name;
	حرف *name;
	gss_OID_desc oid;
	صحیح (*dochild) (ssh_gssapi_client *);
	صحیح (*userok) (ssh_gssapi_client *, حرف *);
	صحیح (*localname) (ssh_gssapi_client *, حرف **);
	خالی (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

قسمتعریف ساخت {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

خارجی ssh_gssapi_mech *supported_mechs[];

صحیح  ssh_gssapi_check_oid(Gssctxt *, خالی *, سائز_t);
خالی ssh_gssapi_سیٹ_oid_ڈیٹا(Gssctxt *, خالی *, سائز_t);
خالی ssh_gssapi_سیٹ_oid(Gssctxt *, gss_OID);
خالی ssh_gssapi_supported_oids(gss_OID_سیٹ *);
خالی ssh_gssapi_prepare_supported_oids(خالی);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, صحیح *);

ساخت sshbuf;
صحیح ssh_gssapi_get_بفر_desc(ساخت sshbuf *, gss_بفر_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ثابت حرف *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, صحیح,
    gss_بفر_desc *, gss_بفر_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_بفر_desc *, gss_بفر_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
خالی ssh_gssapi_error(Gssctxt *);
حرف *ssh_gssapi_آخری_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
خالی ssh_gssapi_build_ctx(Gssctxt **);
خالی ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_بفر_t, gss_بفر_t);
خالی ssh_gssapi_buildmic(ساخت sshbuf *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, ثابت ساخت sshbuf *);
صحیح ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ثابت حرف *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
صحیح ssh_gssapi_userok(حرف *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_بفر_t, gss_بفر_t);
خالی ssh_gssapi_do_بچہ(حرف ***, u_int *);
خالی ssh_gssapi_cleanup_creds(خالی);
خالی ssh_gssapi_storecreds(خالی);
ثابت حرف *ssh_gssapi_displayname(خالی);
خالی ssh_gssapi_cleanup_global_client(خالی);

#اگر_ختم /* GSSAPI */

#اگر_ختم /* _SSH_GSS_H */
