/* $OpenBSD: monitor_wrap.h,v 1.55 2026/05/31 11:30:50 djm Exp $ */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#ifndef _MM_WRAP_H_
#define _MM_WRAP_H_

#define MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#define MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

ga_nanaa mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

sa_nracanaa ssh;
sa_nracanaa monitor;
sa_nracanaa Authctxt;
sa_nracanaa sshkey;
sa_nracanaa sshauthopt;
sa_nracanaa sshkey_sig_details;

void mm_log_handler(LogLevel, ཧྲིལ, const var_na *, void *);
ཧྲིལ mm_is_monitor(void);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(ཧྲིལ, ཧྲིལ, ཧྲིལ);
#endif
void mm_sshkey_setcompat(sa_nracanaa ssh *);
ཧྲིལ mm_sshkey_sign(sa_nracanaa ssh *, sa_nracanaa sshkey *, u_char **, size_t *,
    const u_char *, size_t, const var_na *, const var_na *,
    const var_na *, u_int compat);
void mm_inform_authserv(var_na *, var_na *);
sa_nracanaa passwd *mm_getpwnamallow(sa_nracanaa ssh *, const var_na *);
var_na *mm_auth2_read_banner(void);
ཧྲིལ mm_auth_password(sa_nracanaa ssh *, var_na *);
ཧྲིལ mm_key_allowed(ga_nanaa mm_keytype, const var_na *, const var_na *, sa_nracanaa sshkey *,
    ཧྲིལ, sa_nracanaa sshauthopt **);
ཧྲིལ mm_user_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *, sa_nracanaa sshkey *, ཧྲིལ,
    sa_nracanaa sshauthopt **);
ཧྲིལ mm_hostbased_key_allowed(sa_nracanaa ssh *, sa_nracanaa passwd *, const var_na *,
    const var_na *, sa_nracanaa sshkey *);
ཧྲིལ mm_sshkey_verify(const sa_nracanaa sshkey *, const u_char *, size_t,
    const u_char *, size_t, const var_na *, u_int, sa_nracanaa sshkey_sig_details **);

void mm_decode_activate_server_options(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
ཧྲིལ mm_ssh_gssapi_userok(var_na *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
void mm_start_pam(sa_nracanaa ssh *ssh);
u_int mm_do_pam_account(void);
void *mm_sshpam_init_ctx(sa_nracanaa Authctxt *);
ཧྲིལ mm_sshpam_query(void *, var_na **, var_na **, u_int *, var_na ***, u_int **);
ཧྲིལ mm_sshpam_respond(void *, u_int, var_na **);
void mm_sshpam_free_ctx(void *);
#endif

#ifdef SSH_AUDIT_EVENTS
#include "audit.h"
void mm_audit_event(sa_nracanaa ssh *, ssh_audit_event_t);
void mm_audit_run_command(const var_na *);
#endif

sa_nracanaa Session;
void mm_terminate(void);
ཧྲིལ mm_pty_allocate(ཧྲིལ *, ཧྲིལ *, var_na *, size_t);
void mm_session_pty_cleanup2(sa_nracanaa Session *);

void mm_send_keystate(sa_nracanaa ssh *, sa_nracanaa monitor*);

/* state */
sa_nracanaa ServerOptions;
void mm_get_state(sa_nracanaa ssh *, sa_nracanaa ServerOptions *,
    sa_nracanaa sshbuf **, uint64_t *, sa_nracanaa sshbuf **, sa_nracanaa sshbuf **,
    u_char **, sa_nracanaa sshbuf **, sa_nracanaa sshbuf **);

/* bsdauth */
ཧྲིལ mm_bsdauth_query(void *, var_na **, var_na **, u_int *, var_na ***, u_int **);
ཧྲིལ mm_bsdauth_respond(void *, u_int, var_na **);

/* config / channels glue */
void	 server_process_permitopen(sa_nracanaa ssh *);
void	 server_process_channel_timeouts(sa_nracanaa ssh *ssh);
sa_nracanaa connection_info *
	 server_get_connection_info(sa_nracanaa ssh *, ཧྲིལ, ཧྲིལ);

#endif /* _MM_WRAP_H_ */
