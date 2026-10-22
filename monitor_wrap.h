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

#अगर_अघोषित _MM_WRAP_H_
#घोषणा _MM_WRAP_H_

#घोषणा MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#घोषणा MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

क्रमागत mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

काष्ठा ssh;
काष्ठा monitor;
काष्ठा Authctxt;
काष्ठा sshkey;
काष्ठा sshauthopt;
काष्ठा sshkey_sig_details;

व्योम mm_log_handler(LogLevel, पूर्णांक, स्थिर अक्षर *, व्योम *);
पूर्णांक mm_is_monitor(व्योम);
#अगर_घोषित WITH_OPENSSL
DH *mm_choose_dh(पूर्णांक, पूर्णांक, पूर्णांक);
#पूर्ण_अगर
व्योम mm_sshkey_setcompat(काष्ठा ssh *);
पूर्णांक mm_sshkey_sign(काष्ठा ssh *, काष्ठा sshkey *, u_char **, माप_प्रकार *,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, स्थिर अक्षर *,
    स्थिर अक्षर *, u_int compat);
व्योम mm_inform_authserv(अक्षर *, अक्षर *);
काष्ठा passwd *mm_getpwnamallow(काष्ठा ssh *, स्थिर अक्षर *);
अक्षर *mm_auth2_read_banner(व्योम);
पूर्णांक mm_auth_password(काष्ठा ssh *, अक्षर *);
पूर्णांक mm_कुंजी_allowed(क्रमागत mm_keytype, स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा sshkey *,
    पूर्णांक, काष्ठा sshauthopt **);
पूर्णांक mm_user_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *, काष्ठा sshkey *, पूर्णांक,
    काष्ठा sshauthopt **);
पूर्णांक mm_hostbased_कुंजी_allowed(काष्ठा ssh *, काष्ठा passwd *, स्थिर अक्षर *,
    स्थिर अक्षर *, काष्ठा sshkey *);
पूर्णांक mm_sshkey_verify(स्थिर काष्ठा sshkey *, स्थिर u_char *, माप_प्रकार,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, u_int, काष्ठा sshkey_sig_details **);

व्योम mm_decode_activate_server_options(काष्ठा ssh *ssh, काष्ठा sshbuf *m);

#अगर_घोषित GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_बफर_desc *, gss_बफर_desc *, OM_uint32 *);
पूर्णांक mm_ssh_gssapi_userok(अक्षर *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_बफर_t, gss_बफर_t);
#पूर्ण_अगर

#अगर_घोषित USE_PAM
व्योम mm_start_pam(काष्ठा ssh *ssh);
u_int mm_do_pam_account(व्योम);
व्योम *mm_sshpam_init_ctx(काष्ठा Authctxt *);
पूर्णांक mm_sshpam_query(व्योम *, अक्षर **, अक्षर **, u_int *, अक्षर ***, u_int **);
पूर्णांक mm_sshpam_respond(व्योम *, u_int, अक्षर **);
व्योम mm_sshpam_free_ctx(व्योम *);
#पूर्ण_अगर

#अगर_घोषित SSH_AUDIT_EVENTS
#समावेश "audit.h"
व्योम mm_audit_event(काष्ठा ssh *, ssh_audit_event_t);
व्योम mm_audit_run_command(स्थिर अक्षर *);
#पूर्ण_अगर

काष्ठा Session;
व्योम mm_terminate(व्योम);
पूर्णांक mm_pty_allocate(पूर्णांक *, पूर्णांक *, अक्षर *, माप_प्रकार);
व्योम mm_session_pty_cleanup2(काष्ठा Session *);

व्योम mm_send_keystate(काष्ठा ssh *, काष्ठा monitor*);

/* state */
काष्ठा ServerOptions;
व्योम mm_get_state(काष्ठा ssh *, काष्ठा ServerOptions *,
    काष्ठा sshbuf **, uint64_t *, काष्ठा sshbuf **, काष्ठा sshbuf **,
    u_char **, काष्ठा sshbuf **, काष्ठा sshbuf **);

/* bsdauth */
पूर्णांक mm_bsdauth_query(व्योम *, अक्षर **, अक्षर **, u_int *, अक्षर ***, u_int **);
पूर्णांक mm_bsdauth_respond(व्योम *, u_int, अक्षर **);

/* config / channels glue */
व्योम	 server_process_permitopen(काष्ठा ssh *);
व्योम	 server_process_channel_timeouts(काष्ठा ssh *ssh);
काष्ठा connection_info *
	 server_get_connection_info(काष्ठा ssh *, पूर्णांक, पूर्णांक);

#पूर्ण_अगर /* _MM_WRAP_H_ */
