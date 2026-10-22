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

#నిర్వచితం_కాకపోతే _MM_WRAP_H_
#నిర్వచించు _MM_WRAP_H_

#నిర్వచించు MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#నిర్వచించు MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

గణన mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

నిర్మాణం ssh;
నిర్మాణం monitor;
నిర్మాణం Authctxt;
నిర్మాణం sshkey;
నిర్మాణం sshauthopt;
నిర్మాణం sshkey_sig_details;

శూన్య mm_log_handler(LogLevel, పూర్ణాంకం, స్థిరరాశి అక్షరం *, శూన్య *);
పూర్ణాంకం mm_is_monitor(శూన్య);
#నిర్వచితమైతే WITH_OPENSSL
DH *mm_ఎంచుకో_dh(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
#అయితే_ముగింపు
శూన్య mm_sshkey_setcompat(నిర్మాణం ssh *);
పూర్ణాంకం mm_sshkey_sign(నిర్మాణం ssh *, నిర్మాణం sshkey *, u_char **, కొలత_t *,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, u_int compat);
శూన్య mm_inform_authserv(అక్షరం *, అక్షరం *);
నిర్మాణం passwd *mm_getpwnamallow(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);
అక్షరం *mm_auth2_read_banner(శూన్య);
పూర్ణాంకం mm_auth_password(నిర్మాణం ssh *, అక్షరం *);
పూర్ణాంకం mm_కీలకం_allowed(గణన mm_keytype, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం sshkey *,
    పూర్ణాంకం, నిర్మాణం sshauthopt **);
పూర్ణాంకం mm_user_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *, నిర్మాణం sshkey *, పూర్ణాంకం,
    నిర్మాణం sshauthopt **);
పూర్ణాంకం mm_hostbased_కీలకం_allowed(నిర్మాణం ssh *, నిర్మాణం passwd *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, నిర్మాణం sshkey *);
పూర్ణాంకం mm_sshkey_verify(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి u_char *, కొలత_t,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, u_int, నిర్మాణం sshkey_sig_details **);

శూన్య mm_decode_activate_server_options(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m);

#నిర్వచితమైతే GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_బఫరు_desc *, gss_బఫరు_desc *, OM_uint32 *);
పూర్ణాంకం mm_ssh_gssapi_userok(అక్షరం *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_బఫరు_t, gss_బఫరు_t);
#అయితే_ముగింపు

#నిర్వచితమైతే USE_PAM
శూన్య mm_ప్రారంభం_pam(నిర్మాణం ssh *ssh);
u_int mm_do_pam_account(శూన్య);
శూన్య *mm_sshpam_init_ctx(నిర్మాణం Authctxt *);
పూర్ణాంకం mm_sshpam_query(శూన్య *, అక్షరం **, అక్షరం **, u_int *, అక్షరం ***, u_int **);
పూర్ణాంకం mm_sshpam_respond(శూన్య *, u_int, అక్షరం **);
శూన్య mm_sshpam_free_ctx(శూన్య *);
#అయితే_ముగింపు

#నిర్వచితమైతే SSH_AUDIT_EVENTS
#అన్తర్భావ "audit.h"
శూన్య mm_audit_event(నిర్మాణం ssh *, ssh_audit_event_t);
శూన్య mm_audit_నిరంతరం_command(స్థిరరాశి అక్షరం *);
#అయితే_ముగింపు

నిర్మాణం Session;
శూన్య mm_terminate(శూన్య);
పూర్ణాంకం mm_pty_allocate(పూర్ణాంకం *, పూర్ణాంకం *, అక్షరం *, కొలత_t);
శూన్య mm_session_pty_cleanup2(నిర్మాణం Session *);

శూన్య mm_send_keystate(నిర్మాణం ssh *, నిర్మాణం monitor*);

/* state */
నిర్మాణం ServerOptions;
శూన్య mm_get_state(నిర్మాణం ssh *, నిర్మాణం ServerOptions *,
    నిర్మాణం sshbuf **, uint64_t *, నిర్మాణం sshbuf **, నిర్మాణం sshbuf **,
    u_char **, నిర్మాణం sshbuf **, నిర్మాణం sshbuf **);

/* bsdauth */
పూర్ణాంకం mm_bsdauth_query(శూన్య *, అక్షరం **, అక్షరం **, u_int *, అక్షరం ***, u_int **);
పూర్ణాంకం mm_bsdauth_respond(శూన్య *, u_int, అక్షరం **);

/* config / channels glue */
శూన్య	 server_process_permitopen(నిర్మాణం ssh *);
శూన్య	 server_process_channel_timeouts(నిర్మాణం ssh *ssh);
నిర్మాణం connection_info *
	 server_get_connection_info(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);

#అయితే_ముగింపు /* _MM_WRAP_H_ */
