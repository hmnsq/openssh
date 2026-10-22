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

#اگر_غیر_تعریف_شدہ _MM_WRAP_H_
#تعریف_کرو _MM_WRAP_H_

#تعریف_کرو MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#تعریف_کرو MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

شمار mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ساخت ssh;
ساخت monitor;
ساخت Authctxt;
ساخت sshkey;
ساخت sshauthopt;
ساخت sshkey_sig_details;

خالی mm_log_handler(LogLevel, صحیح, ثابت حرف *, خالی *);
صحیح mm_is_monitor(خالی);
#اگر_تعریف_شدہ WITH_OPENSSL
DH *mm_انتخاب_dh(صحیح, صحیح, صحیح);
#اگر_ختم
خالی mm_sshkey_setcompat(ساخت ssh *);
صحیح mm_sshkey_sign(ساخت ssh *, ساخت sshkey *, u_char **, سائز_t *,
    ثابت u_char *, سائز_t, ثابت حرف *, ثابت حرف *,
    ثابت حرف *, u_int compat);
خالی mm_inform_authserv(حرف *, حرف *);
ساخت passwd *mm_getpwnamallow(ساخت ssh *, ثابت حرف *);
حرف *mm_auth2_read_banner(خالی);
صحیح mm_auth_password(ساخت ssh *, حرف *);
صحیح mm_کلید_allowed(شمار mm_keytype, ثابت حرف *, ثابت حرف *, ساخت sshkey *,
    صحیح, ساخت sshauthopt **);
صحیح mm_user_کلید_allowed(ساخت ssh *ssh, ساخت passwd *, ساخت sshkey *, صحیح,
    ساخت sshauthopt **);
صحیح mm_hostbased_کلید_allowed(ساخت ssh *, ساخت passwd *, ثابت حرف *,
    ثابت حرف *, ساخت sshkey *);
صحیح mm_sshkey_verify(ثابت ساخت sshkey *, ثابت u_char *, سائز_t,
    ثابت u_char *, سائز_t, ثابت حرف *, u_int, ساخت sshkey_sig_details **);

خالی mm_decode_activate_server_options(ساخت ssh *ssh, ساخت sshbuf *m);

#اگر_تعریف_شدہ GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_بفر_desc *, gss_بفر_desc *, OM_uint32 *);
صحیح mm_ssh_gssapi_userok(حرف *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_بفر_t, gss_بفر_t);
#اگر_ختم

#اگر_تعریف_شدہ USE_PAM
خالی mm_آغاز_pam(ساخت ssh *ssh);
u_int mm_do_pam_account(خالی);
خالی *mm_sshpam_init_ctx(ساخت Authctxt *);
صحیح mm_sshpam_query(خالی *, حرف **, حرف **, u_int *, حرف ***, u_int **);
صحیح mm_sshpam_respond(خالی *, u_int, حرف **);
خالی mm_sshpam_free_ctx(خالی *);
#اگر_ختم

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
#شامل "audit.h"
خالی mm_audit_event(ساخت ssh *, ssh_audit_event_t);
خالی mm_audit_تسلسل_command(ثابت حرف *);
#اگر_ختم

ساخت Session;
خالی mm_terminate(خالی);
صحیح mm_pty_allocate(صحیح *, صحیح *, حرف *, سائز_t);
خالی mm_session_pty_cleanup2(ساخت Session *);

خالی mm_send_keystate(ساخت ssh *, ساخت monitor*);

/* state */
ساخت ServerOptions;
خالی mm_get_state(ساخت ssh *, ساخت ServerOptions *,
    ساخت sshbuf **, uint64_t *, ساخت sshbuf **, ساخت sshbuf **,
    u_char **, ساخت sshbuf **, ساخت sshbuf **);

/* bsdauth */
صحیح mm_bsdauth_query(خالی *, حرف **, حرف **, u_int *, حرف ***, u_int **);
صحیح mm_bsdauth_respond(خالی *, u_int, حرف **);

/* config / channels glue */
خالی	 server_process_permitopen(ساخت ssh *);
خالی	 server_process_channel_timeouts(ساخت ssh *ssh);
ساخت connection_info *
	 server_get_connection_info(ساخت ssh *, صحیح, صحیح);

#اگر_ختم /* _MM_WRAP_H_ */
