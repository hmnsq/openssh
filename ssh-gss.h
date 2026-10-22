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
#അന്തര്ഭാവ <gssapi.h>
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_GSSAPI_GSSAPI_H)
#അന്തര്ഭാവ <gssapi/gssapi.h>
#endif

#ifdef KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  എങ്കിൽ !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#endif /* KRB5 */

/* draft-ietf-secsh-gsskeyex-06 */
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_RESPONSE		60
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN			61
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERROR			64
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK			65
#define SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC			66

#define SSH_GSS_OIDTYPE 0x06

തരനിർവചനം ഘടന {
	അക്ഷരം *filename;
	അക്ഷരം *envvar;
	അക്ഷരം *envval;
	ശൂന്യം *data;
} ssh_gssapi_ccache;

തരനിർവചനം ഘടന {
	gss_buffer_desc displayname;
	gss_buffer_desc exportedname;
	gss_cred_id_t creds;
	ഘടന ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	പൂർണ്ണസംഖ്യ userok;
} ssh_gssapi_client;

തരനിർവചനം ഘടന ssh_gssapi_mech_struct {
	അക്ഷരം *enc_name;
	അക്ഷരം *name;
	gss_OID_desc oid;
	പൂർണ്ണസംഖ്യ (*dochild) (ssh_gssapi_client *);
	പൂർണ്ണസംഖ്യ (*userok) (ssh_gssapi_client *, അക്ഷരം *);
	പൂർണ്ണസംഖ്യ (*localname) (ssh_gssapi_client *, അക്ഷരം **);
	ശൂന്യം (*storecreds) (ssh_gssapi_client *);
} ssh_gssapi_mech;

തരനിർവചനം ഘടന {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

ബാഹ്യ ssh_gssapi_mech *supported_mechs[];

പൂർണ്ണസംഖ്യ  ssh_gssapi_check_oid(Gssctxt *, ശൂന്യം *, size_t);
ശൂന്യം ssh_gssapi_set_oid_data(Gssctxt *, ശൂന്യം *, size_t);
ശൂന്യം ssh_gssapi_set_oid(Gssctxt *, gss_OID);
ശൂന്യം ssh_gssapi_supported_oids(gss_OID_set *);
ശൂന്യം ssh_gssapi_prepare_supported_oids(ശൂന്യം);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, പൂർണ്ണസംഖ്യ *);

ഘടന sshbuf;
പൂർണ്ണസംഖ്യ ssh_gssapi_get_buffer_desc(ഘടന sshbuf *, gss_buffer_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, സ്ഥിരം അക്ഷരം *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, പൂർണ്ണസംഖ്യ,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
ശൂന്യം ssh_gssapi_error(Gssctxt *);
അക്ഷരം *ssh_gssapi_last_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
ശൂന്യം ssh_gssapi_build_ctx(Gssctxt **);
ശൂന്യം ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_buffer_t, gss_buffer_t);
ശൂന്യം ssh_gssapi_buildmic(ഘടന sshbuf *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, സ്ഥിരം അക്ഷരം *);

/* In the server */
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
പൂർണ്ണസംഖ്യ ssh_gssapi_userok(അക്ഷരം *name);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
ശൂന്യം ssh_gssapi_do_child(അക്ഷരം ***, u_int *);
ശൂന്യം ssh_gssapi_cleanup_creds(ശൂന്യം);
ശൂന്യം ssh_gssapi_storecreds(ശൂന്യം);
സ്ഥിരം അക്ഷരം *ssh_gssapi_displayname(ശൂന്യം);
ശൂന്യം ssh_gssapi_cleanup_global_client(ശൂന്യം);

#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
