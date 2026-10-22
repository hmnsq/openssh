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

গণনা mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

সংরচনা ssh;
সংরচনা monitor;
সংরচনা Authctxt;
সংরচনা sshkey;
সংরচনা sshauthopt;
সংরচনা sshkey_sig_details;

শূন্য mm_log_handler(LogLevel, পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ *, শূন্য *);
পূর্ণাঙ্ক mm_is_monitor(শূন্য);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
#endif
শূন্য mm_sshkey_setcompat(সংরচনা ssh *);
পূর্ণাঙ্ক mm_sshkey_sign(সংরচনা ssh *, সংরচনা sshkey *, u_char **, size_t *,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, u_int compat);
শূন্য mm_inform_authserv(ৱর্ণ *, ৱর্ণ *);
সংরচনা passwd *mm_getpwnamallow(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *);
ৱর্ণ *mm_auth2_read_banner(শূন্য);
পূর্ণাঙ্ক mm_auth_password(সংরচনা ssh *, ৱর্ণ *);
পূর্ণাঙ্ক mm_চাবি_allowed(গণনা mm_keytype, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, সংরচনা sshkey *,
    পূর্ণাঙ্ক, সংরচনা sshauthopt **);
পূর্ণাঙ্ক mm_user_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *, সংরচনা sshkey *, পূর্ণাঙ্ক,
    সংরচনা sshauthopt **);
পূর্ণাঙ্ক mm_hostbased_চাবি_allowed(সংরচনা ssh *, সংরচনা passwd *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, সংরচনা sshkey *);
পূর্ণাঙ্ক mm_sshkey_verify(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ u_char *, size_t,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, u_int, সংরচনা sshkey_sig_details **);

শূন্য mm_decode_activate_server_options(সংরচনা ssh *ssh, সংরচনা sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
পূর্ণাঙ্ক mm_ssh_gssapi_userok(ৱর্ণ *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
শূন্য mm_start_pam(সংরচনা ssh *ssh);
u_int mm_do_pam_account(শূন্য);
শূন্য *mm_sshpam_init_ctx(সংরচনা Authctxt *);
পূর্ণাঙ্ক mm_sshpam_query(শূন্য *, ৱর্ণ **, ৱর্ণ **, u_int *, ৱর্ণ ***, u_int **);
পূর্ণাঙ্ক mm_sshpam_respond(শূন্য *, u_int, ৱর্ণ **);
শূন্য mm_sshpam_free_ctx(শূন্য *);
#endif

#ifdef SSH_AUDIT_EVENTS
#অন্তর্ভাৱ "audit.h"
শূন্য mm_audit_event(সংরচনা ssh *, ssh_audit_event_t);
শূন্য mm_audit_run_command(ধ্রুৱ ৱর্ণ *);
#endif

সংরচনা Session;
শূন্য mm_terminate(শূন্য);
পূর্ণাঙ্ক mm_pty_allocate(পূর্ণাঙ্ক *, পূর্ণাঙ্ক *, ৱর্ণ *, size_t);
শূন্য mm_session_pty_cleanup2(সংরচনা Session *);

শূন্য mm_send_keystate(সংরচনা ssh *, সংরচনা monitor*);

/* state */
সংরচনা ServerOptions;
শূন্য mm_get_state(সংরচনা ssh *, সংরচনা ServerOptions *,
    সংরচনা sshbuf **, uint64_t *, সংরচনা sshbuf **, সংরচনা sshbuf **,
    u_char **, সংরচনা sshbuf **, সংরচনা sshbuf **);

/* bsdauth */
পূর্ণাঙ্ক mm_bsdauth_query(শূন্য *, ৱর্ণ **, ৱর্ণ **, u_int *, ৱর্ণ ***, u_int **);
পূর্ণাঙ্ক mm_bsdauth_respond(শূন্য *, u_int, ৱর্ণ **);

/* config / channels glue */
শূন্য	 server_process_permitopen(সংরচনা ssh *);
শূন্য	 server_process_channel_timeouts(সংরচনা ssh *ssh);
সংরচনা connection_info *
	 server_get_connection_info(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

#endif /* _MM_WRAP_H_ */
