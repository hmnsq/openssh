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

কাঠামো ssh;
কাঠামো monitor;
কাঠামো Authctxt;
কাঠামো sshkey;
কাঠামো sshauthopt;
কাঠামো sshkey_sig_details;

শূন্য mm_log_handler(LogLevel, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *, শূন্য *);
পূর্ণসংখ্যা mm_is_monitor(শূন্য);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
#endif
শূন্য mm_sshkey_setcompat(কাঠামো ssh *);
পূর্ণসংখ্যা mm_sshkey_sign(কাঠামো ssh *, কাঠামো sshkey *, u_char **, আকার_t *,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, u_int compat);
শূন্য mm_inform_authserv(অক্ষর *, অক্ষর *);
কাঠামো passwd *mm_getpwnamallow(কাঠামো ssh *, ধ্রুবক অক্ষর *);
অক্ষর *mm_auth2_read_banner(শূন্য);
পূর্ণসংখ্যা mm_auth_password(কাঠামো ssh *, অক্ষর *);
পূর্ণসংখ্যা mm_চাবি_allowed(গণনা mm_keytype, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো sshkey *,
    পূর্ণসংখ্যা, কাঠামো sshauthopt **);
পূর্ণসংখ্যা mm_user_চাবি_allowed(কাঠামো ssh *ssh, কাঠামো passwd *, কাঠামো sshkey *, পূর্ণসংখ্যা,
    কাঠামো sshauthopt **);
পূর্ণসংখ্যা mm_hostbased_চাবি_allowed(কাঠামো ssh *, কাঠামো passwd *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, কাঠামো sshkey *);
পূর্ণসংখ্যা mm_sshkey_verify(ধ্রুবক কাঠামো sshkey *, ধ্রুবক u_char *, আকার_t,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, u_int, কাঠামো sshkey_sig_details **);

শূন্য mm_decode_activate_server_options(কাঠামো ssh *ssh, কাঠামো sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_বাফার_desc *, gss_বাফার_desc *, OM_uint32 *);
পূর্ণসংখ্যা mm_ssh_gssapi_userok(অক্ষর *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_বাফার_t, gss_বাফার_t);
#endif

#ifdef USE_PAM
শূন্য mm_start_pam(কাঠামো ssh *ssh);
u_int mm_do_pam_account(শূন্য);
শূন্য *mm_sshpam_init_ctx(কাঠামো Authctxt *);
পূর্ণসংখ্যা mm_sshpam_query(শূন্য *, অক্ষর **, অক্ষর **, u_int *, অক্ষর ***, u_int **);
পূর্ণসংখ্যা mm_sshpam_respond(শূন্য *, u_int, অক্ষর **);
শূন্য mm_sshpam_free_ctx(শূন্য *);
#endif

#ifdef SSH_AUDIT_EVENTS
#অন্তর্ভাব "audit.h"
শূন্য mm_audit_event(কাঠামো ssh *, ssh_audit_event_t);
শূন্য mm_audit_run_command(ধ্রুবক অক্ষর *);
#endif

কাঠামো Session;
শূন্য mm_terminate(শূন্য);
পূর্ণসংখ্যা mm_pty_allocate(পূর্ণসংখ্যা *, পূর্ণসংখ্যা *, অক্ষর *, আকার_t);
শূন্য mm_session_pty_cleanup2(কাঠামো Session *);

শূন্য mm_send_keystate(কাঠামো ssh *, কাঠামো monitor*);

/* state */
কাঠামো ServerOptions;
শূন্য mm_get_state(কাঠামো ssh *, কাঠামো ServerOptions *,
    কাঠামো sshbuf **, uint64_t *, কাঠামো sshbuf **, কাঠামো sshbuf **,
    u_char **, কাঠামো sshbuf **, কাঠামো sshbuf **);

/* bsdauth */
পূর্ণসংখ্যা mm_bsdauth_query(শূন্য *, অক্ষর **, অক্ষর **, u_int *, অক্ষর ***, u_int **);
পূর্ণসংখ্যা mm_bsdauth_respond(শূন্য *, u_int, অক্ষর **);

/* config / channels glue */
শূন্য	 server_process_permitopen(কাঠামো ssh *);
শূন্য	 server_process_channel_timeouts(কাঠামো ssh *ssh);
কাঠামো connection_info *
	 server_get_connection_info(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

#endif /* _MM_WRAP_H_ */
