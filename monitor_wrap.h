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

ગણના mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

સંરચના ssh;
સંરચના monitor;
સંરચના Authctxt;
સંરચના sshkey;
સંરચના sshauthopt;
સંરચના sshkey_sig_details;

શૂન્ય mm_log_handler(LogLevel, પૂર્ણાંક, અચલ અક્ષર *, શૂન્ય *);
પૂર્ણાંક mm_is_monitor(શૂન્ય);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
#endif
શૂન્ય mm_sshkey_setcompat(સંરચના ssh *);
પૂર્ણાંક mm_sshkey_sign(સંરચના ssh *, સંરચના sshkey *, u_char **, size_t *,
    અચલ u_char *, size_t, અચલ અક્ષર *, અચલ અક્ષર *,
    અચલ અક્ષર *, u_int compat);
શૂન્ય mm_inform_authserv(અક્ષર *, અક્ષર *);
સંરચના passwd *mm_getpwnamallow(સંરચના ssh *, અચલ અક્ષર *);
અક્ષર *mm_auth2_read_banner(શૂન્ય);
પૂર્ણાંક mm_auth_password(સંરચના ssh *, અક્ષર *);
પૂર્ણાંક mm_ચાવી_allowed(ગણના mm_keytype, અચલ અક્ષર *, અચલ અક્ષર *, સંરચના sshkey *,
    પૂર્ણાંક, સંરચના sshauthopt **);
પૂર્ણાંક mm_user_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *, સંરચના sshkey *, પૂર્ણાંક,
    સંરચના sshauthopt **);
પૂર્ણાંક mm_hostbased_ચાવી_allowed(સંરચના ssh *, સંરચના passwd *, અચલ અક્ષર *,
    અચલ અક્ષર *, સંરચના sshkey *);
પૂર્ણાંક mm_sshkey_verify(અચલ સંરચના sshkey *, અચલ u_char *, size_t,
    અચલ u_char *, size_t, અચલ અક્ષર *, u_int, સંરચના sshkey_sig_details **);

શૂન્ય mm_decode_activate_server_options(સંરચના ssh *ssh, સંરચના sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
પૂર્ણાંક mm_ssh_gssapi_userok(અક્ષર *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
શૂન્ય mm_start_pam(સંરચના ssh *ssh);
u_int mm_do_pam_account(શૂન્ય);
શૂન્ય *mm_sshpam_init_ctx(સંરચના Authctxt *);
પૂર્ણાંક mm_sshpam_query(શૂન્ય *, અક્ષર **, અક્ષર **, u_int *, અક્ષર ***, u_int **);
પૂર્ણાંક mm_sshpam_respond(શૂન્ય *, u_int, અક્ષર **);
શૂન્ય mm_sshpam_free_ctx(શૂન્ય *);
#endif

#ifdef SSH_AUDIT_EVENTS
#અન્તર્ભાવ "audit.h"
શૂન્ય mm_audit_event(સંરચના ssh *, ssh_audit_event_t);
શૂન્ય mm_audit_run_command(અચલ અક્ષર *);
#endif

સંરચના Session;
શૂન્ય mm_terminate(શૂન્ય);
પૂર્ણાંક mm_pty_allocate(પૂર્ણાંક *, પૂર્ણાંક *, અક્ષર *, size_t);
શૂન્ય mm_session_pty_cleanup2(સંરચના Session *);

શૂન્ય mm_send_keystate(સંરચના ssh *, સંરચના monitor*);

/* state */
સંરચના ServerOptions;
શૂન્ય mm_get_state(સંરચના ssh *, સંરચના ServerOptions *,
    સંરચના sshbuf **, uint64_t *, સંરચના sshbuf **, સંરચના sshbuf **,
    u_char **, સંરચના sshbuf **, સંરચના sshbuf **);

/* bsdauth */
પૂર્ણાંક mm_bsdauth_query(શૂન્ય *, અક્ષર **, અક્ષર **, u_int *, અક્ષર ***, u_int **);
પૂર્ણાંક mm_bsdauth_respond(શૂન્ય *, u_int, અક્ષર **);

/* config / channels glue */
શૂન્ય	 server_process_permitopen(સંરચના ssh *);
શૂન્ય	 server_process_channel_timeouts(સંરચના ssh *ssh);
સંરચના connection_info *
	 server_get_connection_info(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);

#endif /* _MM_WRAP_H_ */
