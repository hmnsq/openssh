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

#నిర్వచితం_కాకపోతే _SSH_GSS_H
#నిర్వచించు _SSH_GSS_H

#నిర్వచితమైతే GSSAPI

#నిర్వచితమైతే HAVE_GSSAPI_H
#అన్తర్భావ <gssapi.h>
#లేదావేళ defined(HAVE_GSSAPI_GSSAPI_H)
#అన్తర్భావ <gssapi/gssapi.h>
#అయితే_ముగింపు

#నిర్వచితమైతే KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  ఒకవేళ !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#అయితే_ముగింపు /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_RESPONSE		60
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN			61
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_ERROR			64
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK			65
#నిర్వచించు SSH2_సందేశం_USERAUTH_GSSAPI_MIC			66

#నిర్వచించు SSH_GSS_OIDTYPE 0x06

రకనిర్వచనం నిర్మాణం {
	అక్షరం *filename;
	అక్షరం *envvar;
	అక్షరం *envval;
	శూన్య *దత్తాంశం;
} ssh_gssapi_ccache;

రకనిర్వచనం నిర్మాణం {
	gss_బఫరు_desc displayname;
	gss_బఫరు_desc exportedname;
	gss_cred_id_t creds;
	నిర్మాణం ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	పూర్ణాంకం userok;
} ssh_gssapi_client;

రకనిర్వచనం నిర్మాణం ssh_gssapi_mech_struct {
	అక్షరం *enc_name;
	అక్షరం *name;
	gss_OID_desc oid;
	పూర్ణాంకం (*dochild) (ssh_gssapi_client *);
	పూర్ణాంకం (*userok) (ssh_gssapi_client *, అక్షరం *);
	పూర్ణాంకం (*localname) (ssh_gssapi_client *, అక్షరం **);
	శూన్య (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

రకనిర్వచనం నిర్మాణం {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

బాహ్య ssh_gssapi_mech *supported_mechs[];

పూర్ణాంకం  ssh_gssapi_check_oid(Gssctxt *, శూన్య *, కొలత_t);
శూన్య ssh_gssapi_సమితి_oid_దత్తాంశం(Gssctxt *, శూన్య *, కొలత_t);
శూన్య ssh_gssapi_సమితి_oid(Gssctxt *, gss_OID);
శూన్య ssh_gssapi_supported_oids(gss_OID_సమితి *);
శూన్య ssh_gssapi_prepare_supported_oids(శూన్య);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, పూర్ణాంకం *);

నిర్మాణం sshbuf;
పూర్ణాంకం ssh_gssapi_get_బఫరు_desc(నిర్మాణం sshbuf *, gss_బఫరు_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, స్థిరరాశి అక్షరం *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, పూర్ణాంకం,
    gss_బఫరు_desc *, gss_బఫరు_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_బఫరు_desc *, gss_బఫరు_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
శూన్య ssh_gssapi_error(Gssctxt *);
అక్షరం *ssh_gssapi_చివరి_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
శూన్య ssh_gssapi_build_ctx(Gssctxt **);
శూన్య ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_బఫరు_t, gss_బఫరు_t);
శూన్య ssh_gssapi_buildmic(నిర్మాణం sshbuf *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం sshbuf *);
పూర్ణాంకం ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, స్థిరరాశి అక్షరం *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
పూర్ణాంకం ssh_gssapi_userok(అక్షరం *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_బఫరు_t, gss_బఫరు_t);
శూన్య ssh_gssapi_do_బిడ్డ(అక్షరం ***, u_int *);
శూన్య ssh_gssapi_cleanup_creds(శూన్య);
శూన్య ssh_gssapi_storecreds(శూన్య);
స్థిరరాశి అక్షరం *ssh_gssapi_displayname(శూన్య);
శూన్య ssh_gssapi_cleanup_global_client(శూన్య);

#అయితే_ముగింపు /* GSSAPI */

#అయితే_ముగింపు /* _SSH_GSS_H */
