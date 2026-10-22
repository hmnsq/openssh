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

गणना mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

संरचना ssh;
संरचना monitor;
संरचना Authctxt;
संरचना sshkey;
संरचना sshauthopt;
संरचना sshkey_sig_details;

शून्य mm_log_handler(LogLevel, पूर्णाङ्क, अचर वर्ण *, शून्य *);
पूर्णाङ्क mm_is_monitor(शून्य);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
#endif
शून्य mm_sshkey_setcompat(संरचना ssh *);
पूर्णाङ्क mm_sshkey_sign(संरचना ssh *, संरचना sshkey *, u_char **, माप_प्रकार *,
    अचर u_char *, माप_प्रकार, अचर वर्ण *, अचर वर्ण *,
    अचर वर्ण *, u_int compat);
शून्य mm_inform_authserv(वर्ण *, वर्ण *);
संरचना passwd *mm_getpwnamallow(संरचना ssh *, अचर वर्ण *);
वर्ण *mm_auth2_read_banner(शून्य);
पूर्णाङ्क mm_auth_password(संरचना ssh *, वर्ण *);
पूर्णाङ्क mm_साँचो_allowed(गणना mm_keytype, अचर वर्ण *, अचर वर्ण *, संरचना sshkey *,
    पूर्णाङ्क, संरचना sshauthopt **);
पूर्णाङ्क mm_user_साँचो_allowed(संरचना ssh *ssh, संरचना passwd *, संरचना sshkey *, पूर्णाङ्क,
    संरचना sshauthopt **);
पूर्णाङ्क mm_hostbased_साँचो_allowed(संरचना ssh *, संरचना passwd *, अचर वर्ण *,
    अचर वर्ण *, संरचना sshkey *);
पूर्णाङ्क mm_sshkey_verify(अचर संरचना sshkey *, अचर u_char *, माप_प्रकार,
    अचर u_char *, माप_प्रकार, अचर वर्ण *, u_int, संरचना sshkey_sig_details **);

शून्य mm_decode_activate_server_options(संरचना ssh *ssh, संरचना sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
पूर्णाङ्क mm_ssh_gssapi_userok(वर्ण *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
शून्य mm_start_pam(संरचना ssh *ssh);
u_int mm_do_pam_account(शून्य);
शून्य *mm_sshpam_init_ctx(संरचना Authctxt *);
पूर्णाङ्क mm_sshpam_query(शून्य *, वर्ण **, वर्ण **, u_int *, वर्ण ***, u_int **);
पूर्णाङ्क mm_sshpam_respond(शून्य *, u_int, वर्ण **);
शून्य mm_sshpam_free_ctx(शून्य *);
#endif

#ifdef SSH_AUDIT_EVENTS
#अन्तर्भाव "audit.h"
शून्य mm_audit_event(संरचना ssh *, ssh_audit_event_t);
शून्य mm_audit_run_command(अचर वर्ण *);
#endif

संरचना Session;
शून्य mm_terminate(शून्य);
पूर्णाङ्क mm_pty_allocate(पूर्णाङ्क *, पूर्णाङ्क *, वर्ण *, माप_प्रकार);
शून्य mm_session_pty_cleanup2(संरचना Session *);

शून्य mm_send_keystate(संरचना ssh *, संरचना monitor*);

/* state */
संरचना ServerOptions;
शून्य mm_get_state(संरचना ssh *, संरचना ServerOptions *,
    संरचना sshbuf **, uint64_t *, संरचना sshbuf **, संरचना sshbuf **,
    u_char **, संरचना sshbuf **, संरचना sshbuf **);

/* bsdauth */
पूर्णाङ्क mm_bsdauth_query(शून्य *, वर्ण **, वर्ण **, u_int *, वर्ण ***, u_int **);
पूर्णाङ्क mm_bsdauth_respond(शून्य *, u_int, वर्ण **);

/* config / channels glue */
शून्य	 server_process_permitopen(संरचना ssh *);
शून्य	 server_process_channel_timeouts(संरचना ssh *ssh);
संरचना connection_info *
	 server_get_connection_info(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);

#endif /* _MM_WRAP_H_ */
