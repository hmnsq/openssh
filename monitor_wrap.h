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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _MM_WRAP_H_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _MM_WRAP_H_

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

ਗਿਣਤੀ mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ਬਣਤਰ ssh;
ਬਣਤਰ monitor;
ਬਣਤਰ Authctxt;
ਬਣਤਰ sshkey;
ਬਣਤਰ sshauthopt;
ਬਣਤਰ sshkey_sig_details;

ਖਾਲੀ mm_log_handler(LogLevel, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਖਾਲੀ *);
ਪੂਰਨ mm_is_monitor(ਖਾਲੀ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
DH *mm_ਚੁਣੋ_dh(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
#ਜੇ_ਅੰਤ
ਖਾਲੀ mm_sshkey_setcompat(ਬਣਤਰ ssh *);
ਪੂਰਨ mm_sshkey_sign(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, u_int compat);
ਖਾਲੀ mm_inform_authserv(ਅੱਖਰ *, ਅੱਖਰ *);
ਬਣਤਰ passwd *mm_getpwnamallow(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ *mm_auth2_read_banner(ਖਾਲੀ);
ਪੂਰਨ mm_auth_password(ਬਣਤਰ ssh *, ਅੱਖਰ *);
ਪੂਰਨ mm_ਕੁੰਜੀ_allowed(ਗਿਣਤੀ mm_keytype, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey *,
    ਪੂਰਨ, ਬਣਤਰ sshauthopt **);
ਪੂਰਨ mm_user_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *, ਬਣਤਰ sshkey *, ਪੂਰਨ,
    ਬਣਤਰ sshauthopt **);
ਪੂਰਨ mm_hostbased_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *, ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey *);
ਪੂਰਨ mm_sshkey_verify(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ u_char *, ਮਾਪ_t,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, u_int, ਬਣਤਰ sshkey_sig_details **);

ਖਾਲੀ mm_decode_activate_server_options(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_ਬਫਰ_desc *, gss_ਬਫਰ_desc *, OM_uint32 *);
ਪੂਰਨ mm_ssh_gssapi_userok(ਅੱਖਰ *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_ਬਫਰ_t, gss_ਬਫਰ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਖਾਲੀ mm_ਸ਼ੁਰੂ_pam(ਬਣਤਰ ssh *ssh);
u_int mm_do_pam_account(ਖਾਲੀ);
ਖਾਲੀ *mm_sshpam_init_ctx(ਬਣਤਰ Authctxt *);
ਪੂਰਨ mm_sshpam_query(ਖਾਲੀ *, ਅੱਖਰ **, ਅੱਖਰ **, u_int *, ਅੱਖਰ ***, u_int **);
ਪੂਰਨ mm_sshpam_respond(ਖਾਲੀ *, u_int, ਅੱਖਰ **);
ਖਾਲੀ mm_sshpam_free_ctx(ਖਾਲੀ *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
#ਅਨ੍ਤਰ੍ਭਾਵ "audit.h"
ਖਾਲੀ mm_audit_event(ਬਣਤਰ ssh *, ssh_audit_event_t);
ਖਾਲੀ mm_audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *);
#ਜੇ_ਅੰਤ

ਬਣਤਰ Session;
ਖਾਲੀ mm_terminate(ਖਾਲੀ);
ਪੂਰਨ mm_pty_allocate(ਪੂਰਨ *, ਪੂਰਨ *, ਅੱਖਰ *, ਮਾਪ_t);
ਖਾਲੀ mm_session_pty_cleanup2(ਬਣਤਰ Session *);

ਖਾਲੀ mm_send_keystate(ਬਣਤਰ ssh *, ਬਣਤਰ monitor*);

/* state */
ਬਣਤਰ ServerOptions;
ਖਾਲੀ mm_get_state(ਬਣਤਰ ssh *, ਬਣਤਰ ServerOptions *,
    ਬਣਤਰ sshbuf **, uint64_t *, ਬਣਤਰ sshbuf **, ਬਣਤਰ sshbuf **,
    u_char **, ਬਣਤਰ sshbuf **, ਬਣਤਰ sshbuf **);

/* bsdauth */
ਪੂਰਨ mm_bsdauth_query(ਖਾਲੀ *, ਅੱਖਰ **, ਅੱਖਰ **, u_int *, ਅੱਖਰ ***, u_int **);
ਪੂਰਨ mm_bsdauth_respond(ਖਾਲੀ *, u_int, ਅੱਖਰ **);

/* config / channels glue */
ਖਾਲੀ	 server_process_permitopen(ਬਣਤਰ ssh *);
ਖਾਲੀ	 server_process_channel_timeouts(ਬਣਤਰ ssh *ssh);
ਬਣਤਰ connection_info *
	 server_get_connection_info(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);

#ਜੇ_ਅੰਤ /* _MM_WRAP_H_ */
