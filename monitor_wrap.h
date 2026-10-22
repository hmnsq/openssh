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

ଗଣନା mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ସଂରଚନା ssh;
ସଂରଚନା monitor;
ସଂରଚନା Authctxt;
ସଂରଚନା sshkey;
ସଂରଚନା sshauthopt;
ସଂରଚନା sshkey_sig_details;

ଶୂନ୍ୟ mm_log_handler(LogLevel, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ଶୂନ୍ୟ *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_is_monitor(ଶୂନ୍ୟ);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif
ଶୂନ୍ୟ mm_sshkey_setcompat(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_sshkey_sign(ସଂରଚନା ssh *, ସଂରଚନା sshkey *, u_char **, size_t *,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, u_int compat);
ଶୂନ୍ୟ mm_inform_authserv(ଅକ୍ଷର *, ଅକ୍ଷର *);
ସଂରଚନା passwd *mm_getpwnamallow(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର *mm_auth2_read_banner(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_auth_password(ସଂରଚନା ssh *, ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_ଚାବି_allowed(ଗଣନା mm_keytype, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_user_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *, ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ସଂରଚନା sshauthopt **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_hostbased_ଚାବି_allowed(ସଂରଚନା ssh *, ସଂରଚନା passwd *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_sshkey_verify(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ u_char *, size_t,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, u_int, ସଂରଚନା sshkey_sig_details **);

ଶୂନ୍ୟ mm_decode_activate_server_options(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_ssh_gssapi_userok(ଅକ୍ଷର *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
ଶୂନ୍ୟ mm_start_pam(ସଂରଚନା ssh *ssh);
u_int mm_do_pam_account(ଶୂନ୍ୟ);
ଶୂନ୍ୟ *mm_sshpam_init_ctx(ସଂରଚନା Authctxt *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_sshpam_query(ଶୂନ୍ୟ *, ଅକ୍ଷର **, ଅକ୍ଷର **, u_int *, ଅକ୍ଷର ***, u_int **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_sshpam_respond(ଶୂନ୍ୟ *, u_int, ଅକ୍ଷର **);
ଶୂନ୍ୟ mm_sshpam_free_ctx(ଶୂନ୍ୟ *);
#endif

#ifdef SSH_AUDIT_EVENTS
#ଅନ୍ତର୍ଭାଵ "audit.h"
ଶୂନ୍ୟ mm_audit_event(ସଂରଚନା ssh *, ssh_audit_event_t);
ଶୂନ୍ୟ mm_audit_run_command(ଅଚଳ ଅକ୍ଷର *);
#endif

ସଂରଚନା Session;
ଶୂନ୍ୟ mm_terminate(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_pty_allocate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର *, size_t);
ଶୂନ୍ୟ mm_session_pty_cleanup2(ସଂରଚନା Session *);

ଶୂନ୍ୟ mm_send_keystate(ସଂରଚନା ssh *, ସଂରଚନା monitor*);

/* state */
ସଂରଚନା ServerOptions;
ଶୂନ୍ୟ mm_get_state(ସଂରଚନା ssh *, ସଂରଚନା ServerOptions *,
    ସଂରଚନା sshbuf **, uint64_t *, ସଂରଚନା sshbuf **, ସଂରଚନା sshbuf **,
    u_char **, ସଂରଚନା sshbuf **, ସଂରଚନା sshbuf **);

/* bsdauth */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_bsdauth_query(ଶୂନ୍ୟ *, ଅକ୍ଷର **, ଅକ୍ଷର **, u_int *, ଅକ୍ଷର ***, u_int **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mm_bsdauth_respond(ଶୂନ୍ୟ *, u_int, ଅକ୍ଷର **);

/* config / channels glue */
ଶୂନ୍ୟ	 server_process_permitopen(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 server_process_channel_timeouts(ସଂରଚନା ssh *ssh);
ସଂରଚନା connection_info *
	 server_get_connection_info(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

#endif /* _MM_WRAP_H_ */
