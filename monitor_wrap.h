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

شمارش mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ساختار ssh;
ساختار monitor;
ساختار Authctxt;
ساختار sshkey;
ساختار sshauthopt;
ساختار sshkey_sig_details;

تهی mm_log_handler(LogLevel, صحیح, ثابت نویسه *, تهی *);
صحیح mm_is_monitor(تهی);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(صحیح, صحیح, صحیح);
#endif
تهی mm_sshkey_setcompat(ساختار ssh *);
صحیح mm_sshkey_sign(ساختار ssh *, ساختار sshkey *, u_char **, size_t *,
    ثابت u_char *, size_t, ثابت نویسه *, ثابت نویسه *,
    ثابت نویسه *, u_int compat);
تهی mm_inform_authserv(نویسه *, نویسه *);
ساختار passwd *mm_getpwnamallow(ساختار ssh *, ثابت نویسه *);
نویسه *mm_auth2_read_banner(تهی);
صحیح mm_auth_password(ساختار ssh *, نویسه *);
صحیح mm_کلید_allowed(شمارش mm_keytype, ثابت نویسه *, ثابت نویسه *, ساختار sshkey *,
    صحیح, ساختار sshauthopt **);
صحیح mm_user_کلید_allowed(ساختار ssh *ssh, ساختار passwd *, ساختار sshkey *, صحیح,
    ساختار sshauthopt **);
صحیح mm_hostbased_کلید_allowed(ساختار ssh *, ساختار passwd *, ثابت نویسه *,
    ثابت نویسه *, ساختار sshkey *);
صحیح mm_sshkey_verify(ثابت ساختار sshkey *, ثابت u_char *, size_t,
    ثابت u_char *, size_t, ثابت نویسه *, u_int, ساختار sshkey_sig_details **);

تهی mm_decode_activate_server_options(ساختار ssh *ssh, ساختار sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
صحیح mm_ssh_gssapi_userok(نویسه *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
تهی mm_start_pam(ساختار ssh *ssh);
u_int mm_do_pam_account(تهی);
تهی *mm_sshpam_init_ctx(ساختار Authctxt *);
صحیح mm_sshpam_query(تهی *, نویسه **, نویسه **, u_int *, نویسه ***, u_int **);
صحیح mm_sshpam_respond(تهی *, u_int, نویسه **);
تهی mm_sshpam_free_ctx(تهی *);
#endif

#ifdef SSH_AUDIT_EVENTS
#شامل "audit.h"
تهی mm_audit_event(ساختار ssh *, ssh_audit_event_t);
تهی mm_audit_run_command(ثابت نویسه *);
#endif

ساختار Session;
تهی mm_terminate(تهی);
صحیح mm_pty_allocate(صحیح *, صحیح *, نویسه *, size_t);
تهی mm_session_pty_cleanup2(ساختار Session *);

تهی mm_send_keystate(ساختار ssh *, ساختار monitor*);

/* state */
ساختار ServerOptions;
تهی mm_get_state(ساختار ssh *, ساختار ServerOptions *,
    ساختار sshbuf **, uint64_t *, ساختار sshbuf **, ساختار sshbuf **,
    u_char **, ساختار sshbuf **, ساختار sshbuf **);

/* bsdauth */
صحیح mm_bsdauth_query(تهی *, نویسه **, نویسه **, u_int *, نویسه ***, u_int **);
صحیح mm_bsdauth_respond(تهی *, u_int, نویسه **);

/* config / channels glue */
تهی	 server_process_permitopen(ساختار ssh *);
تهی	 server_process_channel_timeouts(ساختار ssh *ssh);
ساختار connection_info *
	 server_get_connection_info(ساختار ssh *, صحیح, صحیح);

#endif /* _MM_WRAP_H_ */
