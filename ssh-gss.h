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

#جيڪڏهن_وصف_نه_ٿيل _SSH_GSS_H
#وصف_ڪريو _SSH_GSS_H

#جيڪڏهن_وصف_ٿيل GSSAPI

#جيڪڏهن_وصف_ٿيل HAVE_GSSAPI_H
#ضمن <gssapi.h>
#وإلاإذا defined(HAVE_GSSAPI_GSSAPI_H)
#ضمن <gssapi/gssapi.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  إذا !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#جيڪڏهن_پورو /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_RESPONSE		60
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_TOKEN			61
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_ERROR			64
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_ERRTOK			65
#وصف_ڪريو SSH2_نياپو_USERAUTH_GSSAPI_MIC			66

#وصف_ڪريو SSH_GSS_OIDTYPE 0x06

تعريفنوع بنية {
	حرف *filename;
	حرف *envvar;
	حرف *envval;
	فراغ *معلومات;
} ssh_gssapi_ccache;

تعريفنوع بنية {
	gss_بفر_desc displayname;
	gss_بفر_desc exportedname;
	gss_cred_id_t creds;
	بنية ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	صحيح userok;
} ssh_gssapi_client;

تعريفنوع بنية ssh_gssapi_mech_struct {
	حرف *enc_name;
	حرف *name;
	gss_OID_desc oid;
	صحيح (*dochild) (ssh_gssapi_client *);
	صحيح (*userok) (ssh_gssapi_client *, حرف *);
	صحيح (*localname) (ssh_gssapi_client *, حرف **);
	فراغ (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

تعريفنوع بنية {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

خارجي ssh_gssapi_mech *supported_mechs[];

صحيح  ssh_gssapi_check_oid(Gssctxt *, فراغ *, سائيز_t);
فراغ ssh_gssapi_سيٽ_oid_معلومات(Gssctxt *, فراغ *, سائيز_t);
فراغ ssh_gssapi_سيٽ_oid(Gssctxt *, gss_OID);
فراغ ssh_gssapi_supported_oids(gss_OID_سيٽ *);
فراغ ssh_gssapi_prepare_supported_oids(فراغ);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, صحيح *);

بنية sshbuf;
صحيح ssh_gssapi_get_بفر_desc(بنية sshbuf *, gss_بفر_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, ثابت حرف *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, صحيح,
    gss_بفر_desc *, gss_بفر_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_بفر_desc *, gss_بفر_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
فراغ ssh_gssapi_error(Gssctxt *);
حرف *ssh_gssapi_آخري_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
فراغ ssh_gssapi_build_ctx(Gssctxt **);
فراغ ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_بفر_t, gss_بفر_t);
فراغ ssh_gssapi_buildmic(بنية sshbuf *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, ثابت بنية sshbuf *);
صحيح ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, ثابت حرف *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
صحيح ssh_gssapi_userok(حرف *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_بفر_t, gss_بفر_t);
فراغ ssh_gssapi_do_ٻار(حرف ***, u_int *);
فراغ ssh_gssapi_cleanup_creds(فراغ);
فراغ ssh_gssapi_storecreds(فراغ);
ثابت حرف *ssh_gssapi_displayname(فراغ);
فراغ ssh_gssapi_cleanup_global_client(فراغ);

#جيڪڏهن_پورو /* GSSAPI */

#جيڪڏهن_پورو /* _SSH_GSS_H */
