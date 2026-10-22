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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _MM_WRAP_H_
#ವ್ಯಾಖ್ಯಾನಿಸು _MM_WRAP_H_

#ವ್ಯಾಖ್ಯಾನಿಸು MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#ವ್ಯಾಖ್ಯಾನಿಸು MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

ಎಣಿಕೆ mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ರಚನೆ ssh;
ರಚನೆ monitor;
ರಚನೆ Authctxt;
ರಚನೆ sshkey;
ರಚನೆ sshauthopt;
ರಚನೆ sshkey_sig_details;

ಶೂನ್ಯ mm_log_handler(LogLevel, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಶೂನ್ಯ *);
ಪೂರ್ಣಾಂಕ mm_is_monitor(ಶೂನ್ಯ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
DH *mm_ಆರಿಸು_dh(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ
ಶೂನ್ಯ mm_sshkey_setcompat(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ mm_sshkey_sign(ರಚನೆ ssh *, ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int compat);
ಶೂನ್ಯ mm_inform_authserv(ಅಕ್ಷರ *, ಅಕ್ಷರ *);
ರಚನೆ passwd *mm_getpwnamallow(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ *mm_auth2_read_banner(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ mm_auth_password(ರಚನೆ ssh *, ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ mm_ಕೀಲಿ_allowed(ಎಣಿಕೆ mm_keytype, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey *,
    ಪೂರ್ಣಾಂಕ, ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ mm_user_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *, ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ,
    ರಚನೆ sshauthopt **);
ಪೂರ್ಣಾಂಕ mm_hostbased_ಕೀಲಿ_allowed(ರಚನೆ ssh *, ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ mm_sshkey_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int, ರಚನೆ sshkey_sig_details **);

ಶೂನ್ಯ mm_decode_activate_server_options(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_ಬಫರ್_desc *, gss_ಬಫರ್_desc *, OM_uint32 *);
ಪೂರ್ಣಾಂಕ mm_ssh_gssapi_userok(ಅಕ್ಷರ *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_ಬಫರ್_t, gss_ಬಫರ್_t);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಶೂನ್ಯ mm_ಆರಂಭ_pam(ರಚನೆ ssh *ssh);
u_int mm_do_pam_account(ಶೂನ್ಯ);
ಶೂನ್ಯ *mm_sshpam_init_ctx(ರಚನೆ Authctxt *);
ಪೂರ್ಣಾಂಕ mm_sshpam_query(ಶೂನ್ಯ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, u_int *, ಅಕ್ಷರ ***, u_int **);
ಪೂರ್ಣಾಂಕ mm_sshpam_respond(ಶೂನ್ಯ *, u_int, ಅಕ್ಷರ **);
ಶೂನ್ಯ mm_sshpam_free_ctx(ಶೂನ್ಯ *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
#ಅನ್ತರ್ಭಾವ "audit.h"
ಶೂನ್ಯ mm_audit_event(ರಚನೆ ssh *, ssh_audit_event_t);
ಶೂನ್ಯ mm_audit_ಸತತ_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ Session;
ಶೂನ್ಯ mm_terminate(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ mm_pty_allocate(ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಶೂನ್ಯ mm_session_pty_cleanup2(ರಚನೆ Session *);

ಶೂನ್ಯ mm_send_keystate(ರಚನೆ ssh *, ರಚನೆ monitor*);

/* state */
ರಚನೆ ServerOptions;
ಶೂನ್ಯ mm_get_state(ರಚನೆ ssh *, ರಚನೆ ServerOptions *,
    ರಚನೆ sshbuf **, uint64_t *, ರಚನೆ sshbuf **, ರಚನೆ sshbuf **,
    u_char **, ರಚನೆ sshbuf **, ರಚನೆ sshbuf **);

/* bsdauth */
ಪೂರ್ಣಾಂಕ mm_bsdauth_query(ಶೂನ್ಯ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, u_int *, ಅಕ್ಷರ ***, u_int **);
ಪೂರ್ಣಾಂಕ mm_bsdauth_respond(ಶೂನ್ಯ *, u_int, ಅಕ್ಷರ **);

/* config / channels glue */
ಶೂನ್ಯ	 server_process_permitopen(ರಚನೆ ssh *);
ಶೂನ್ಯ	 server_process_channel_timeouts(ರಚನೆ ssh *ssh);
ರಚನೆ connection_info *
	 server_get_connection_info(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ /* _MM_WRAP_H_ */
