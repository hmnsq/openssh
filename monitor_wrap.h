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

ಗಣನಾ mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ಸಂರಚನಾ ssh;
ಸಂರಚನಾ monitor;
ಸಂರಚನಾ Authctxt;
ಸಂರಚನಾ sshkey;
ಸಂರಚನಾ sshauthopt;
ಸಂರಚನಾ sshkey_sig_details;

ಶೂನ್ಯ mm_log_handler(LogLevel, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಶೂನ್ಯ *);
ಪೂರ್ಣಾಙ್ಕ mm_is_monitor(ಶೂನ್ಯ);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
#endif
ಶೂನ್ಯ mm_sshkey_setcompat(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ mm_sshkey_sign(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshkey *, u_char **, size_t *,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, u_int compat);
ಶೂನ್ಯ mm_inform_authserv(ವರ್ಣ *, ವರ್ಣ *);
ಸಂರಚನಾ passwd *mm_getpwnamallow(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ *mm_auth2_read_banner(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ mm_auth_password(ಸಂರಚನಾ ssh *, ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ mm_ಕೀಲಿ_allowed(ಗಣನಾ mm_keytype, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey *,
    ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ mm_user_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *, ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ,
    ಸಂರಚನಾ sshauthopt **);
ಪೂರ್ಣಾಙ್ಕ mm_hostbased_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ passwd *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ mm_sshkey_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ u_char *, size_t,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, u_int, ಸಂರಚನಾ sshkey_sig_details **);

ಶೂನ್ಯ mm_decode_activate_server_options(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
ಪೂರ್ಣಾಙ್ಕ mm_ssh_gssapi_userok(ವರ್ಣ *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
ಶೂನ್ಯ mm_start_pam(ಸಂರಚನಾ ssh *ssh);
u_int mm_do_pam_account(ಶೂನ್ಯ);
ಶೂನ್ಯ *mm_sshpam_init_ctx(ಸಂರಚನಾ Authctxt *);
ಪೂರ್ಣಾಙ್ಕ mm_sshpam_query(ಶೂನ್ಯ *, ವರ್ಣ **, ವರ್ಣ **, u_int *, ವರ್ಣ ***, u_int **);
ಪೂರ್ಣಾಙ್ಕ mm_sshpam_respond(ಶೂನ್ಯ *, u_int, ವರ್ಣ **);
ಶೂನ್ಯ mm_sshpam_free_ctx(ಶೂನ್ಯ *);
#endif

#ifdef SSH_AUDIT_EVENTS
#ಅನ್ತರ್ಭಾವ "audit.h"
ಶೂನ್ಯ mm_audit_event(ಸಂರಚನಾ ssh *, ssh_audit_event_t);
ಶೂನ್ಯ mm_audit_run_command(ಧ್ರುವ ವರ್ಣ *);
#endif

ಸಂರಚನಾ Session;
ಶೂನ್ಯ mm_terminate(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ mm_pty_allocate(ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ *, ವರ್ಣ *, size_t);
ಶೂನ್ಯ mm_session_pty_cleanup2(ಸಂರಚನಾ Session *);

ಶೂನ್ಯ mm_send_keystate(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ monitor*);

/* state */
ಸಂರಚನಾ ServerOptions;
ಶೂನ್ಯ mm_get_state(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ ServerOptions *,
    ಸಂರಚನಾ sshbuf **, uint64_t *, ಸಂರಚನಾ sshbuf **, ಸಂರಚನಾ sshbuf **,
    u_char **, ಸಂರಚನಾ sshbuf **, ಸಂರಚನಾ sshbuf **);

/* bsdauth */
ಪೂರ್ಣಾಙ್ಕ mm_bsdauth_query(ಶೂನ್ಯ *, ವರ್ಣ **, ವರ್ಣ **, u_int *, ವರ್ಣ ***, u_int **);
ಪೂರ್ಣಾಙ್ಕ mm_bsdauth_respond(ಶೂನ್ಯ *, u_int, ವರ್ಣ **);

/* config / channels glue */
ಶೂನ್ಯ	 server_process_permitopen(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 server_process_channel_timeouts(ಸಂರಚನಾ ssh *ssh);
ಸಂರಚನಾ connection_info *
	 server_get_connection_info(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

#endif /* _MM_WRAP_H_ */
