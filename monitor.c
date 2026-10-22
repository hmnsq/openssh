/* $OpenBSD: monitor.c,v 1.260 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"
#ಅನ್ತರ್ಭಾವ "sshlogin.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "monitor.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಸ್ಥಿರ Gssctxt *gsscontext = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

/* Imports */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ u_int utmp_len;
ಬಾಹ್ಯ ರಚನೆ sshbuf *cfg;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ರಚನೆ include_list includes;
ಬಾಹ್ಯ ರಚನೆ sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ಸ್ಥಿರ ರಚನೆ sshbuf *ಮಗು_state;

/* Functions on the monitor that answer unprivileged requests */

ಪೂರ್ಣಾಂಕ mm_answer_moduli(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_setcompat(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_sign(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pwnamallow(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_auth2_read_banner(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_authserv(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_authpassword(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_bsdauthquery(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_bsdauthrespond(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_keyallowed(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_keyverify(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pty(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pty_cleanup(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_ಪದ(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_state(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಪೂರ್ಣಾಂಕ mm_answer_pam_ಆರಂಭ(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pam_account(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pam_init_ctx(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pam_query(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pam_respond(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_pam_free_ctx(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಪೂರ್ಣಾಂಕ mm_answer_gss_ಸಿದ್ಧತೆ_ctx(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_gss_accept_ctx(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_gss_userok(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_gss_checkmic(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
ಪೂರ್ಣಾಂಕ mm_answer_audit_event(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ mm_answer_audit_command(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ Authctxt *authctxt;

/* local state for key verify */
ಸ್ಥಿರ u_char *ಕೀಲಿ_blob = ಖಾಲಿ;
ಸ್ಥಿರ ಗಾತ್ರ_t ಕೀಲಿ_bloblen = 0;
ಸ್ಥಿರ u_int ಕೀಲಿ_blobtype = MM_NOKEY;
ಸ್ಥಿರ ರಚನೆ sshauthopt *ಕೀಲಿ_opts = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *hostbased_cuser = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *hostbased_chost = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *auth_ವಿಧಾನ = "unknown";
ಸ್ಥಿರ ಅಕ್ಷರ *auth_submethod = ಖಾಲಿ;
ಸ್ಥಿರ u_int session_id2_len = 0;
ಸ್ಥಿರ u_char *session_id2 = ಖಾಲಿ;
ಸ್ಥಿರ pid_t monitor_ಮಗು_pid;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ auth_attempted = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ invalid_user = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ compat_ಗಣ = 0;

ರಚನೆ mon_ಕೋಷ್ಟಕ {
	ಎಣಿಕೆ monitor_reqtype type;
	ಪೂರ್ಣಾಂಕ flags;
	ಪೂರ್ಣಾಂಕ (*f)(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *);
};

#ವ್ಯಾಖ್ಯಾನಿಸು MON_ISAUTH	0x0004	/* Required for Authentication */
#ವ್ಯಾಖ್ಯಾನಿಸು MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#ವ್ಯಾಖ್ಯಾನಿಸು MON_ONCE	0x0010	/* Disable after calling */
#ವ್ಯಾಖ್ಯಾನಿಸು MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#ವ್ಯಾಖ್ಯಾನಿಸು MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#ವ್ಯಾಖ್ಯಾನಿಸು MON_PERMIT	0x1000	/* Request is permitted */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ monitor_read(ರಚನೆ ssh *, ರಚನೆ monitor *, ರಚನೆ mon_ಕೋಷ್ಟಕ *,
    ರಚನೆ mon_ಕೋಷ್ಟಕ **);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ monitor_read_log(ರಚನೆ monitor *);

ರಚನೆ mon_ಕೋಷ್ಟಕ mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#ಆದರೆ_ಅಂತ್ಯ
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
    {MONITOR_REQ_PAM_ಆರಂಭ, MON_ONCE, mm_answer_pam_ಆರಂಭ},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#ಆದರೆ_ಅಂತ್ಯ
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_ಸಿದ್ಧತೆ_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#ಆದರೆ_ಅಂತ್ಯ
    {0, 0, ಖಾಲಿ}
};

ರಚನೆ mon_ಕೋಷ್ಟಕ mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#ಆದರೆ_ಅಂತ್ಯ
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_ಪದ, 0, mm_answer_ಪದ},
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#ಆದರೆ_ಅಂತ್ಯ
    {0, 0, ಖಾಲಿ}
};

ರಚನೆ mon_ಕೋಷ್ಟಕ *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ಸ್ಥಿರ ಶೂನ್ಯ
monitor_permit(ರಚನೆ mon_ಕೋಷ್ಟಕ *ent, ಎಣಿಕೆ monitor_reqtype type, ಪೂರ್ಣಾಂಕ permit)
{
	ಆಗ (ent->f != ಖಾಲಿ) {
		ಆದರೆ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ಹಿಂತಿರುಗಿ;
		}
		ent++;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_permit_authentications(ಪೂರ್ಣಾಂಕ permit)
{
	ರಚನೆ mon_ಕೋಷ್ಟಕ *ent = mon_dispatch;

	ಆಗ (ent->f != ಖಾಲಿ) {
		ಆದರೆ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

ಶೂನ್ಯ
monitor_ಮಗು_preauth(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor)
{
	ರಚನೆ mon_ಕೋಷ್ಟಕ *ent;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ಆದರೆ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ಆದರೆ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, ಗಾತ್ರ(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ಆಗ (!authenticated) {
		partial = 0;
		auth_ವಿಧಾನ = "unknown";
		auth_submethod = ಖಾಲಿ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ಆದರೆ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ಆದರೆ (options.ಅಂಕೆ_auth_methods != 0) {
			ಆದರೆ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_ವಿಧಾನ, auth_submethod)) {
				debug3_f("method %s: partial", auth_ವಿಧಾನ);
				authenticated = 0;
				partial = 1;
			}
		}

		ಆದರೆ (authenticated) {
			ಆದರೆ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ಆದರೆ (authctxt->pw->pw_uid == 0 &&
			    !auth_ಬೇರು_allowed(ssh, auth_ವಿಧಾನ))
				authenticated = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
			/* PAM needs to perform account checks after auth */
			ಆದರೆ (options.use_pam && authenticated) {
				ರಚನೆ sshbuf *m;

				ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#ಆದರೆ_ಅಂತ್ಯ
		}
		ಆದರೆ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_ವಿಧಾನ, auth_submethod);
			ಆದರೆ (!partial && !authenticated)
				authctxt->failures++;
			ಆದರೆ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_ವಿಧಾನ, auth_submethod);
			}
		}
		ಆದರೆ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ಆದರೆ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ಆದರೆ (strcmp(auth_ವಿಧಾನ, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ಖಾಲಿ;
	ssh_packet_ಗಣ_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ಆಗ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ಆಗ (waitpid(pmonitor->m_pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno == EINTR)
			ಮುಂದುವರಿ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಆದರೆ (WIFEXITED(ಸ್ಥಿತಿ_2)) {
		ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (ದೀರ್ಘ)pmonitor->m_pid, WEXITSTATUS(ಸ್ಥಿತಿ_2));
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WIFSIGNALED(ಸ್ಥಿತಿ_2)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (ದೀರ್ಘ)pmonitor->m_pid, WTERMSIG(ಸ್ಥಿತಿ_2));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (ದೀರ್ಘ)pmonitor->m_pid);

	ಆದರೆ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ಆದರೆ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_ಗಣ_ಮಗು_handler(pid_t pid)
{
	monitor_ಮಗು_pid = pid;
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_ಮಗು_handler(ಪೂರ್ಣಾಂಕ sig)
{
	kill(monitor_ಮಗು_pid, sig);
}

ಶೂನ್ಯ
monitor_ಮಗು_postauth(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_ಗಣ_ಮಗು_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_ಮಗು_handler);
	ssh_signal(SIGTERM, &monitor_ಮಗು_handler);
	ssh_signal(SIGINT, &monitor_ಮಗು_handler);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#ಆದರೆ_ಅಂತ್ಯ

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_ಪದ, 1);

	ಆದರೆ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	ಗಾಗಿ (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ಖಾಲಿ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
monitor_read_log(ರಚನೆ monitor *pmonitor)
{
	ರಚನೆ sshbuf *logmsg;
	u_int len, level, forced;
	ಅಕ್ಷರ *ಸಂದೇಶ;
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((logmsg = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");

	/* Read length */
	ಆದರೆ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ಆದರೆ (atomicio(ಪಠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		ಆದರೆ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ಹಿಂತಿರುಗಿ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ಆದರೆ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ಆದರೆ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ಆದರೆ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ಆದರೆ (atomicio(ಪಠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ಆದರೆ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &ಸಂದೇಶ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ಆದರೆ (log_level_name(level) == ಖಾಲಿ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", ಸಂದೇಶ,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
monitor_read(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor, ರಚನೆ mon_ಕೋಷ್ಟಕ *ent,
    ರಚನೆ mon_ಕೋಷ್ಟಕ **pent)
{
	ರಚನೆ sshbuf *m;
	ಪೂರ್ಣಾಂಕ r, ret;
	u_char type;
	ರಚನೆ pollfd pfd[2];

	ಗಾಗಿ (;;) {
		memset(&pfd, 0, ಗಾತ್ರ(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ಆದರೆ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ಆದರೆ (errno == EINTR || errno == EAGAIN)
				ಮುಂದುವರಿ;
			fatal_f("poll: %s", strerror(errno));
		}
		ಆದರೆ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (pfd[0].revents)
			ನಿಲ್ಲಿಸು;  /* Continues below */
	}

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ಆದರೆ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ಆಗ (ent->f != ಖಾಲಿ) {
		ಆದರೆ (ent->type == type)
			ನಿಲ್ಲಿಸು;
		ent++;
	}

	ಆದರೆ (ent->f != ಖಾಲಿ) {
		ಆದರೆ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ಆದರೆ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ಆದರೆ (pent != ಖಾಲಿ)
			*pent = ent;

		ಹಿಂತಿರುಗಿ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ಹಿಂತಿರುಗಿ (-1);
}

/* allowed key state */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
monitor_allowed_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ಆದರೆ (ಕೀಲಿ_blob == ಖಾಲಿ || ಕೀಲಿ_bloblen != bloblen ||
	    timingsafe_bcmp(ಕೀಲಿ_blob, blob, ಕೀಲಿ_bloblen))
		ಹಿಂತಿರುಗಿ (0);
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_reset_ಕೀಲಿ_state(ಶೂನ್ಯ)
{
	/* reset state */
	ಬಿಡುಗಡೆ(ಕೀಲಿ_blob);
	ಬಿಡುಗಡೆ(hostbased_cuser);
	ಬಿಡುಗಡೆ(hostbased_chost);
	sshauthopt_free(ಕೀಲಿ_opts);
	ಕೀಲಿ_blob = ಖಾಲಿ;
	ಕೀಲಿ_bloblen = 0;
	ಕೀಲಿ_blobtype = MM_NOKEY;
	ಕೀಲಿ_opts = ಖಾಲಿ;
	hostbased_cuser = ಖಾಲಿ;
	hostbased_chost = ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
mm_answer_state(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *ಬಳಸದ)
{
	ರಚನೆ sshbuf *m = ಖಾಲಿ, *config = ಖಾಲಿ, *hostkeys = ಖಾಲಿ;
	ರಚನೆ sshbuf *opts = ಖಾಲಿ, *confdata = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ postauth;
	ಪೂರ್ಣಾಂಕ r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ ||
	    (config = sshbuf_new()) == ಖಾಲಿ ||
	    (opts = sshbuf_new()) == ಖಾಲಿ ||
	    (confdata = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ಆದರೆ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");

	/*
	 * Protocol from monitor to unpriv privsep process:
	 *	string	configuration_blob
	 *	uint64	timing_secret	XXX move delays to monitor and remove
	 *	string	host_keys[] {
	 *		string public_key
	 *		string certificate
	 *	}
	 *	string  server_banner
	 *	string  client_banner
	 *	string	configuration_data (postauth)
	 *	string  keystate (postauth)
	 *	string  authenticated_user (postauth)
	 *	string  session_info (postauth)
	 *	string  authopts (postauth)
	 */
	ಆದರೆ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ಆದರೆ (postauth) {
		/* XXX shouldn't be reachable */
		fatal_f("internal error: called in postauth");
	}

	sshbuf_free(config);
	sshbuf_free(opts);
	sshbuf_free(confdata);
	sshbuf_free(hostkeys);

	mm_request_send(sock, MONITOR_ANS_STATE, m);
	sshbuf_free(m);
	debug3_f("done");

	ಹಿಂತಿರುಗಿ (0);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
mm_answer_moduli(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	DH *dh;
	ಸ್ಥಿರಾಂಕ BIGNUM *dh_p, *dh_g;
	ಪೂರ್ಣಾಂಕ r;
	u_int min, want, max;

	ಆದರೆ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ಆದರೆ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = ಆರಿಸು_dh(min, want, max);
	ಆದರೆ (dh == ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ಖಾಲಿ, &dh_g);
		ಆದರೆ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
mm_answer_setcompat(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_ಗಣ = 1;

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_sign(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ auth_sock;			/* XXX move to state struct? */
	ರಚನೆ sshkey *pubkey, *ಕೀಲಿ;
	ರಚನೆ sshbuf *sigbuf = ಖಾಲಿ;
	u_char *p = ಖಾಲಿ, *signature = ಖಾಲಿ;
	ಅಕ್ಷರ *alg = ಖಾಲಿ;
	ಗಾತ್ರ_t datlen, siglen;
	ಪೂರ್ಣಾಂಕ r, is_proof = 0, keyid;
	u_int compat;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ proof_req[] = "hostkeys-prove-00@openssh.com";
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ nhostkey_proofs_ಮುಗಿದ, *hostkey_proofs_ಮುಗಿದ;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ಆದರೆ (!compat_ಗಣ)
		fatal_f("state error: setcompat never called");

	ಆದರೆ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ ((keyid = get_hostkey_ಸೂಚ್ಯಂಕ(pubkey, 1, ssh)) == -1)
		fatal_f("unknown hostkey");
	debug_f("hostkey %s index %d", sshkey_ssh_name(pubkey), keyid);
	sshkey_free(pubkey);

	/*
	 * Supported KEX types use SHA1 (20 bytes), SHA256 (32 bytes),
	 * SHA384 (48 bytes) and SHA512 (64 bytes).
	 *
	 * Otherwise, verify the signature request is for a hostkey
	 * proof.
	 *
	 * XXX perform similar check for KEX signature requests too?
	 * it's not trivial, since what is signed is the hash, rather
	 * than the full kex structure...
	 */
	ಆದರೆ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ಆದರೆ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ಆದರೆ ((ಕೀಲಿ = get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(keyid, ssh)) == ಖಾಲಿ)
			fatal_f("no hostkey for index %d", keyid);
		ಆದರೆ (keyid >= nhostkey_proofs_ಮುಗಿದ) {
			hostkey_proofs_ಮುಗಿದ = xrecallocarray(
			    hostkey_proofs_ಮುಗಿದ, nhostkey_proofs_ಮುಗಿದ,
			    keyid + 1, ಗಾತ್ರ(*hostkey_proofs_ಮುಗಿದ));
			nhostkey_proofs_ಮುಗಿದ = keyid + 1;
		}
		ಆದರೆ (hostkey_proofs_ಮುಗಿದ[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(ಕೀಲಿ), keyid);
		}
		hostkey_proofs_ಮುಗಿದ[keyid] = 1;
		ಆದರೆ ((sigbuf = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new");
		ಆದರೆ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(ಕೀಲಿ, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ಆದರೆ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ಆದರೆ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		ಸ್ಮರಣೆ_ನಕಲು(session_id2, p, session_id2_len);
	}

	ಆದರೆ ((ಕೀಲಿ = get_hostkey_by_ಸೂಚ್ಯಂಕ(keyid)) != ಖಾಲಿ) {
		ಆದರೆ ((r = sshkey_sign(ಕೀಲಿ, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ಖಾಲಿ, compat)) != 0)
			fatal_fr(r, "sign");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಕೀಲಿ = get_hostkey_ಬಹಿರಂಗ_by_ಸೂಚ್ಯಂಕ(keyid, ssh)) != ಖಾಲಿ &&
	    auth_sock > 0) {
		ಆದರೆ ((r = ssh_agent_sign(auth_sock, ಕೀಲಿ, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ಇಲ್ಲದಿದ್ದರೆ
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	ಬಿಡುಗಡೆ(alg);
	ಬಿಡುಗಡೆ(p);
	ಬಿಡುಗಡೆ(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ಹಿಂತಿರುಗಿ (0);
}

#ವ್ಯಾಖ್ಯಾನಿಸು PUTPW(b, id) \
	ಮಾಡು { \
		ಆದರೆ ((r = sshbuf_put_string(b, \
		    &pwent->id, ಗಾತ್ರ(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ಆಗ (0)

ಶೂನ್ಯ
mm_encode_server_options(ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *config;

	ಆದರೆ ((config = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ಆದರೆ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
ಪೂರ್ಣಾಂಕ
mm_answer_pwnamallow(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ರಚನೆ passwd *pwent;
	ಪೂರ್ಣಾಂಕ r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ಆದರೆ (!compat_ಗಣ)
		fatal_f("state error: setcompat never called");

	ಆದರೆ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ಆದರೆ ((r = sshbuf_get_cstring(m, &authctxt->user, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ಆದರೆ (pwent == ಖಾಲಿ) {
		invalid_user = 1;
		ಆದರೆ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		ಹೋಗು ಹೊರಹೋಗು;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ಆದರೆ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#ಆದರೆ_ಅಂತ್ಯ
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 ಹೊರಹೋಗು:
	ssh_packet_ಗಣ_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	ಆದರೆ (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_ಪೋರ್ಟ್(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	ಆದರೆ (auth2_ಸಿದ್ಧತೆ_methods_lists(authctxt) != 0) {
		/*
		 * The monitor will continue long enough to let the child
		 * run to its packet_disconnect(), but it must not allow any
		 * authentication to succeed.
		 */
		debug_f("no valid authentication method lists");
	}

	debug3_f("sending MONITOR_ANS_PWNAM: %d", allowed);
	mm_request_send(sock, MONITOR_ANS_PWNAM, m);

	/* Allow service/style information on the auth context */
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_AUTH2_READ_BANNER, 1);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ಆರಂಭ, 1);
#ಆದರೆ_ಅಂತ್ಯ

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ mm_answer_auth2_read_banner(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ *banner;
	ಪೂರ್ಣಾಂಕ r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ಆದರೆ ((r = sshbuf_put_cstring(m, banner != ಖಾಲಿ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	ಬಿಡುಗಡೆ(banner);

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_authserv(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	monitor_permit_authentications(1);

	ಆದರೆ ((r = sshbuf_get_cstring(m, &authctxt->service, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(authctxt->style) == 0) {
		ಬಿಡುಗಡೆ(authctxt->style);
		authctxt->style = ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_ತಳ_type_ಹೊಂದಿಕೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *list)
{
	ಅಕ್ಷರ *s, *l, *ol = xstrdup(list);
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	l = ol;
	ಗಾಗಿ ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ಆದರೆ (sshkey_type_from_name(s) == ಕೀಲಿ->type) {
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!ಸಿಕ್ಕಿತು) {
		error("%s key type %s is not in permitted list %s", ವಿಧಾನ,
		    sshkey_ssh_name(ಕೀಲಿ), list);
	}

	ಬಿಡುಗಡೆ(ol);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಪೂರ್ಣಾಂಕ
mm_answer_authpassword(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ call_ಎಣಿಕೆ;
	ಅಕ್ಷರ *passwd;
	ಪೂರ್ಣಾಂಕ r, authenticated;
	ಗಾತ್ರ_t plen;

	ಆದರೆ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ಆದರೆ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#ಆದರೆ_ಅಂತ್ಯ

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_ಎಣಿಕೆ++;
	ಆದರೆ (plen == 0 && call_ಎಣಿಕೆ == 1)
		auth_ವಿಧಾನ = "none";
	ಇಲ್ಲದಿದ್ದರೆ
		auth_ವಿಧಾನ = "password";

	/* Causes monitor loop to terminate if authenticated */
	ಹಿಂತಿರುಗಿ (authenticated);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
ಪೂರ್ಣಾಂಕ
mm_answer_bsdauthquery(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ *name, *infotxt;
	u_int numprompts, *echo_on, success;
	ಅಕ್ಷರ **prompts;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ಆದರೆ (success) {
		ಆದರೆ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ಆದರೆ (success) {
		ಬಿಡುಗಡೆ(name);
		ಬಿಡುಗಡೆ(infotxt);
		ಬಿಡುಗಡೆ(prompts);
		ಬಿಡುಗಡೆ(echo_on);
	}

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_bsdauthrespond(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ *response;
	ಪೂರ್ಣಾಂಕ r, authok;

	ಆದರೆ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ಆದರೆ (authctxt->as == ಖಾಲಿ)
		fatal_f("no bsd auth session");

	ಆದರೆ ((r = sshbuf_get_cstring(m, &response, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ಖಾಲಿ;
	debug3_f("<%s> = <%d>", response, authok);
	ಬಿಡುಗಡೆ(response);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_ವಿಧಾನ = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ಹಿಂತಿರುಗಿ (authok != 0);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಪೂರ್ಣಾಂಕ
mm_answer_pam_ಆರಂಭ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಆದರೆ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	ಆರಂಭ_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ಆದರೆ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pam_account(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	u_int ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ಆದರೆ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ *sshpam_ctxt, *sshpam_authok;
ಬಾಹ್ಯ KbdintDevice sshpam_device;

ಪೂರ್ಣಾಂಕ
mm_answer_pam_init_ctx(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	u_int ok = 0;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ಆದರೆ (sshpam_ctxt != ಖಾಲಿ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ಖಾಲಿ;
	sshbuf_reset(m);
	ಆದರೆ (sshpam_ctxt != ಖಾಲಿ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ಆದರೆ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pam_query(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ *name = ಖಾಲಿ, *info = ಖಾಲಿ, **prompts = ಖಾಲಿ;
	u_int i, ಅಂಕೆ = 0, *echo_on = 0;
	ಪೂರ್ಣಾಂಕ r, ret;

	debug3_f("entering");
	sshpam_authok = ಖಾಲಿ;
	ಆದರೆ (sshpam_ctxt == ಖಾಲಿ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &ಅಂಕೆ, &prompts, &echo_on);
	ಆದರೆ (ret == 0 && ಅಂಕೆ == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ಆದರೆ (ಅಂಕೆ > 1 || name == ಖಾಲಿ || info == ಖಾಲಿ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಬಿಡುಗಡೆ(name);
	ಬಿಡುಗಡೆ(info);
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ; ++i) {
		ಆದರೆ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		ಬಿಡುಗಡೆ(prompts[i]);
	}
	ಬಿಡುಗಡೆ(prompts);
	ಬಿಡುಗಡೆ(echo_on);
	auth_ವಿಧಾನ = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pam_respond(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ **resp;
	u_int i, ಅಂಕೆ;
	ಪೂರ್ಣಾಂಕ r, ret;

	debug3_f("entering");
	ಆದರೆ (sshpam_ctxt == ಖಾಲಿ)
		fatal_f("no context");
	sshpam_authok = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_get_u32(m, &ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (ಅಂಕೆ > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    ಅಂಕೆ, (ಚಿಹ್ನೆರಹಿತ)PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ);
	}
	ಆದರೆ (ಅಂಕೆ > 0) {
		resp = xcalloc(ಅಂಕೆ, ಗಾತ್ರ(ಅಕ್ಷರ *));
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ; ++i) {
			ಆದರೆ ((r = sshbuf_get_cstring(m, &(resp[i]), ಖಾಲಿ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, ಅಂಕೆ, resp);
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ; ++i)
			ಬಿಡುಗಡೆ(resp[i]);
		ಬಿಡುಗಡೆ(resp);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ret = (sshpam_device.respond)(sshpam_ctxt, ಅಂಕೆ, ಖಾಲಿ);
	}
	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_ವಿಧಾನ = "keyboard-interactive";
	auth_submethod = "pam";
	ಆದರೆ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pam_free_ctx(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r = sshpam_authok != ಖಾಲಿ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ಆದರೆ (sshpam_ctxt == ಖಾಲಿ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ಖಾಲಿ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_ವಿಧಾನ = "keyboard-interactive";
	auth_submethod = "pam";
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
mm_answer_keyallowed(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	ಪೂರ್ಣಾಂಕ r, allowed = 0;
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;

	debug3_f("entering");
	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ಖಾಲಿ)) != 0 ||
	    (r = sshkey_froms(m, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ && authctxt->valid) {
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ MM_USERKEY:
			auth_ವಿಧಾನ = "publickey";
			ಆದರೆ (!options.pubkey_authentication)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (auth2_ಕೀಲಿ_already_ಬಳಸಿದ(authctxt, ಕೀಲಿ))
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (!ಕೀಲಿ_ತಳ_type_ಹೊಂದಿಕೆ(auth_ವಿಧಾನ, ಕೀಲಿ,
			    options.pubkey_accepted_algos))
				ನಿಲ್ಲಿಸು;
			allowed = user_ಕೀಲಿ_allowed(ssh, authctxt->pw, ಕೀಲಿ,
			    pubkey_auth_attempt, &opts);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ MM_HOSTKEY:
			auth_ವಿಧಾನ = "hostbased";
			ಆದರೆ (!options.hostbased_authentication)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (auth2_ಕೀಲಿ_already_ಬಳಸಿದ(authctxt, ಕೀಲಿ))
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (!ಕೀಲಿ_ತಳ_type_ಹೊಂದಿಕೆ(auth_ವಿಧಾನ, ಕೀಲಿ,
			    options.hostbased_accepted_algos))
				ನಿಲ್ಲಿಸು;
			allowed = hostbased_ಕೀಲಿ_allowed(ssh, authctxt->pw,
			    cuser, chost, ಕೀಲಿ);
			auth2_ದಾಖಲೆ_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal_f("unknown key type %u", type);
			ನಿಲ್ಲಿಸು;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_ವಿಧಾನ,
	    pubkey_auth_attempt ? "" : " test",
	    (ಕೀಲಿ == ಖಾಲಿ || !authctxt->valid) ? "invalid" : sshkey_type(ಕೀಲಿ),
	    allowed ? "allowed" : "not allowed");

	auth2_ದಾಖಲೆ_ಕೀಲಿ(authctxt, 0, ಕೀಲಿ);

	/* clear temporarily storage (used by verify) */
	monitor_reset_ಕೀಲಿ_state();

	ಆದರೆ (allowed) {
		/* Save temporarily for comparison in verify */
		ಆದರೆ ((r = sshkey_ಗಮ್ಯ_blob(ಕೀಲಿ, &ಕೀಲಿ_blob, &ಕೀಲಿ_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		ಕೀಲಿ_blobtype = type;
		ಕೀಲಿ_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_ವಿಧಾನ, ಖಾಲಿ);
		ಬಿಡುಗಡೆ(cuser);
		ಬಿಡುಗಡೆ(chost);
	}
	sshkey_free(ಕೀಲಿ);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ಆದರೆ (opts != ಖಾಲಿ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ಆದರೆ (!allowed)
		sshauthopt_free(opts);

	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
monitor_valid_userblob(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, u_int datalen)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ sshkey *hostkey = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಅಕ್ಷರ *userstyle, *cp;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ hostbound = 0, r, fail = 0;

	ಆದರೆ ((b = sshbuf_from(ದತ್ತಾಂಶ, datalen)) == ಖಾಲಿ)
		fatal_f("sshbuf_from");

	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ಆದರೆ ((session_id2 == ಖಾಲಿ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ಆದರೆ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ಆದರೆ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ಬಿಡುಗಡೆ(userstyle);
	ಬಿಡುಗಡೆ(cp);
	ಆದರೆ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse method");
	ಆದರೆ (strcmp("publickey", cp) != 0) {
		ಆದರೆ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ಇಲ್ಲದಿದ್ದರೆ
			fail++;
	}
	ಬಿಡುಗಡೆ(cp);
	ಆದರೆ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ಆದರೆ (type == 0)
		fail++;
	ಆದರೆ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ಆದರೆ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ಆದರೆ (hostkey != ಖಾಲಿ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ಆದರೆ (get_hostkey_ಸೂಚ್ಯಂಕ(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ಹಿಂತಿರುಗಿ (fail == 0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
monitor_valid_hostbasedblob(ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, u_int datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cuser, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *chost)
{
	ರಚನೆ sshbuf *b;
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಅಕ್ಷರ *cp, *userstyle;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r, fail = 0;
	u_char type;

	ಆದರೆ ((b = sshbuf_from(ದತ್ತಾಂಶ, datalen)) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ಆದರೆ ((session_id2 == ಖಾಲಿ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ಆದರೆ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ಆದರೆ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ಬಿಡುಗಡೆ(userstyle);
	ಬಿಡುಗಡೆ(cp);
	ಆದರೆ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse method");
	ಆದರೆ (strcmp(cp, "hostbased") != 0)
		fail++;
	ಬಿಡುಗಡೆ(cp);
	ಆದರೆ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse host");
	ಆದರೆ (((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ಆದರೆ (strcmp(cp, chost) != 0)
		fail++;
	ಬಿಡುಗಡೆ(cp);

	/* verify client user */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &cp, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse ruser");
	ಆದರೆ (strcmp(cp, cuser) != 0)
		fail++;
	ಬಿಡುಗಡೆ(cp);

	ಆದರೆ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ (fail == 0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_keyverify(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ರಚನೆ sshkey *ಕೀಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *signature, *ದತ್ತಾಂಶ, *blob;
	ಅಕ್ಷರ *sigalg = ಖಾಲಿ, *fp = ಖಾಲಿ;
	ಗಾತ್ರ_t signaturelen, datalen, bloblen;
	ಪೂರ್ಣಾಂಕ r, ret, req_presence = 0, req_verify = 0, valid_ದತ್ತಾಂಶ = 0;
	ಪೂರ್ಣಾಂಕ encoded_ret;
	ರಚನೆ sshkey_sig_details *sig_details = ಖಾಲಿ;

	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(m, &ದತ್ತಾಂಶ, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (hostbased_cuser == ಖಾಲಿ || hostbased_chost == ಖಾಲಿ ||
	  !monitor_allowed_ಕೀಲಿ(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ಆದರೆ (*sigalg == '\0') {
		ಬಿಡುಗಡೆ(sigalg);
		sigalg = ಖಾಲಿ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ಆದರೆ ((r = sshkey_from_blob(blob, bloblen, &ಕೀಲಿ)) != 0)
		fatal_fr(r, "parse key");

	ಆಯ್ಕೆ (ಕೀಲಿ_blobtype) {
	ಸ್ಥಿತಿ MM_USERKEY:
		valid_ದತ್ತಾಂಶ = monitor_valid_userblob(ssh, ದತ್ತಾಂಶ, datalen);
		auth_ವಿಧಾನ = "publickey";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MM_HOSTKEY:
		valid_ದತ್ತಾಂಶ = monitor_valid_hostbasedblob(ದತ್ತಾಂಶ, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_ವಿಧಾನ = "hostbased";
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		valid_ದತ್ತಾಂಶ = 0;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (!valid_ದತ್ತಾಂಶ)
		fatal_f("bad %s signature data blob",
		    ಕೀಲಿ_blobtype == MM_USERKEY ? "userkey" :
		    (ಕೀಲಿ_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(ಕೀಲಿ, signature, signaturelen, ದತ್ತಾಂಶ, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_ವಿಧಾನ,
	    sshkey_type(ಕೀಲಿ), sigalg == ಖಾಲಿ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ಆದರೆ (ret == 0 && ಕೀಲಿ_blobtype == MM_USERKEY && sig_details != ಖಾಲಿ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !ಕೀಲಿ_opts->no_require_user_presence;
		ಆದರೆ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(ಕೀಲಿ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_ಪೋರ್ಟ್(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || ಕೀಲಿ_opts->require_verify;
		ಆದರೆ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(ಕೀಲಿ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_ಪೋರ್ಟ್(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_ದಾಖಲೆ_ಕೀಲಿ(authctxt, ret == 0, ಕೀಲಿ);

	ಆದರೆ (ಕೀಲಿ_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, ಕೀಲಿ_opts);
	monitor_reset_ಕೀಲಿ_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ಆದರೆ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ಖಾಲಿ)) != 0)
		fatal_fr(r, "assemble");
	ಆದರೆ (sig_details != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	ಬಿಡುಗಡೆ(sigalg);
	ಬಿಡುಗಡೆ(fp);
	sshkey_free(ಕೀಲಿ);

	ಹಿಂತಿರುಗಿ ret == 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_ದಾಖಲೆ_login(ರಚನೆ ssh *ssh, Session *s, ರಚನೆ passwd *pw)
{
	socklen_t fromlen;
	ರಚನೆ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ಗಾತ್ರ(from));
	fromlen = ಗಾತ್ರ(from);
	ಆದರೆ (ssh_packet_connection_is_on_socket(ssh)) {
		ಆದರೆ (getpeername(ssh_packet_get_connection_ಒಳ(ssh),
		    (ರಚನೆ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	ದಾಖಲೆ_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ರಚನೆ sockaddr *)&from, fromlen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (ದೀರ್ಘ)s->pid);
	ಆದರೆ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_ಬಳಸದ(s->self);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pty(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಬಾಹ್ಯ ರಚನೆ monitor *pmonitor;
	Session *s;
	ಪೂರ್ಣಾಂಕ r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ಆದರೆ (s == ಖಾಲಿ)
		ಹೋಗು error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ಗಾತ್ರ(s->tty));
	ಆದರೆ (res == 0)
		ಹೋಗು error;
	pty_setowner(authctxt->pw, s->tty);

	ಆದರೆ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ಆದರೆ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_ದಾಖಲೆ_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ಆದರೆ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ಆದರೆ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ಆದರೆ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ಆದರೆ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ಹಿಂತಿರುಗಿ (0);

 error:
	ಆದರೆ (s != ಖಾಲಿ)
		mm_session_close(s);
	ಆದರೆ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_pty_cleanup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	Session *s;
	ಅಕ್ಷರ *tty;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((r = sshbuf_get_cstring(m, &tty, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse tty");
	ಆದರೆ ((s = session_by_tty(tty)) != ಖಾಲಿ)
		mm_session_close(s);
	sshbuf_reset(m);
	ಬಿಡುಗಡೆ(tty);
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_ಪದ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *req)
{
	ಬಾಹ್ಯ ರಚನೆ monitor *pmonitor;
	ಪೂರ್ಣಾಂಕ res, ಸ್ಥಿತಿ_2;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		sshpam_cleanup();
#ಆದರೆ_ಅಂತ್ಯ

	ಆಗ (waitpid(pmonitor->m_pid, &ಸ್ಥಿತಿ_2, 0) == -1)
		ಆದರೆ (errno != EINTR)
			ನಿರ್ಗಮಿಸು(1);

	res = WIFEXITED(ಸ್ಥಿತಿ_2) ? WEXITSTATUS(ಸ್ಥಿತಿ_2) : 1;

	/* Terminate process */
	ನಿರ್ಗಮಿಸು(res);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
ಪೂರ್ಣಾಂಕ
mm_answer_audit_event(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ socket, ರಚನೆ sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	ಆಯ್ಕೆ (event) {
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_PUBKEY:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_HOSTBASED:
	ಸ್ಥಿತಿ SSH_AUTH_FAIL_GSSAPI:
	ಸ್ಥಿತಿ SSH_LOGIN_EXCEED_MAXTRIES:
	ಸ್ಥಿತಿ SSH_LOGIN_ಬೇರು_DENIED:
	ಸ್ಥಿತಿ SSH_CONNECTION_CLOSE:
	ಸ್ಥಿತಿ SSH_INVALID_USER:
		audit_event(ssh, event);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("Audit event type %d not permitted", event);
	}

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_audit_command(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ socket, ರಚನೆ sshbuf *m)
{
	ಅಕ್ಷರ *cmd;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ ((r = sshbuf_get_cstring(m, &cmd, ಖಾಲಿ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_ಸತತ_command(cmd);
	ಬಿಡುಗಡೆ(cmd);
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* SSH_AUDIT_EVENTS */

ಶೂನ್ಯ
monitor_clear_keystate(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, ಬಹುಲಕ_ಒಳ);
	ssh_clear_newkeys(ssh, ಬಹುಲಕ_ಹೊರಹೋಗು);
	sshbuf_free(ಮಗು_state);
	ಮಗು_state = ಖಾಲಿ;
}

ಶೂನ್ಯ
monitor_apply_keystate(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor)
{
	ರಚನೆ kex *kex;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("packet_set_state");
	ಆದರೆ ((r = ssh_packet_ಗಣ_state(ssh, ಮಗು_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(ಮಗು_state);
	ಮಗು_state = ಖಾಲಿ;
	ಆದರೆ ((kex = ssh->kex) == ಖಾಲಿ)
		fatal_f("internal error: ssh->kex == NULL");
	ಆದರೆ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ಆದರೆ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#ಆದರೆ_ಅಂತ್ಯ
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ=&get_hostkey_ಬಹಿರಂಗ_by_type;
	kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ=&get_hostkey_ಖಾಸಗಿ_by_type;
	kex->host_ಕೀಲಿ_ಸೂಚ್ಯಂಕ=&get_hostkey_ಸೂಚ್ಯಂಕ;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

ಶೂನ್ಯ
mm_get_keystate(ರಚನೆ ssh *ssh, ರಚನೆ monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ಆದರೆ ((ಮಗು_state = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    ಮಗು_state);
	debug3_f("GOT new keys");
}


/* XXX */

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_openfds(ರಚನೆ monitor *mon, ಪೂರ್ಣಾಂಕ do_logfds)
{
	ಪೂರ್ಣಾಂಕ pair[2];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_ZEROIZE
	ಪೂರ್ಣಾಂಕ on = 1;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_ZEROIZE
	ಆದರೆ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, ಗಾತ್ರ(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ಆದರೆ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, ಗಾತ್ರ(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ಆದರೆ (do_logfds) {
		ಆದರೆ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} ಇಲ್ಲದಿದ್ದರೆ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ರಚನೆ monitor *
monitor_init(ಶೂನ್ಯ)
{
	ರಚನೆ monitor *mon;

	mon = xcalloc(1, ಗಾತ್ರ(*mon));
	monitor_openfds(mon, 1);

	ಹಿಂತಿರುಗಿ mon;
}

ಶೂನ್ಯ
monitor_reinit(ರಚನೆ monitor *mon)
{
	monitor_openfds(mon, 0);
}

ಪೂರ್ಣಾಂಕ
monitor_auth_attempted(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ auth_attempted;
}

ಪೂರ್ಣಾಂಕ
monitor_invalid_user(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ invalid_user;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಪೂರ್ಣಾಂಕ
mm_answer_gss_ಸಿದ್ಧತೆ_ctx(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	ಗಾತ್ರ_t len;
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ಆದರೆ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.ಉದ್ದಳತೆ = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	ಬಿಡುಗಡೆ(goid.elements);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_gss_accept_ctx(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	gss_ಬಫರ್_desc ಒಳ;
	gss_ಬಫರ್_desc ಹೊರಹೋಗು = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ಆದರೆ ((r = ssh_gssapi_get_ಬಫರ್_desc(m, &ಒಳ)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &ಒಳ, &ಹೊರಹೋಗು, &flags);
	ಬಿಡುಗಡೆ(ಒಳ.ಮೌಲ್ಯ);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, ಹೊರಹೋಗು.ಮೌಲ್ಯ, ಹೊರಹೋಗು.ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_ಬಫರ್(&minor, &ಹೊರಹೋಗು);

	ಆದರೆ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_gss_checkmic(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	gss_ಬಫರ್_desc gssbuf, mic;
	OM_uint32 ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ಆದರೆ ((r = ssh_gssapi_get_ಬಫರ್_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_ಬಫರ್_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	ಬಿಡುಗಡೆ(gssbuf.ಮೌಲ್ಯ);
	ಬಿಡುಗಡೆ(mic.ಮೌಲ್ಯ);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ಆದರೆ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
mm_answer_gss_userok(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r, authenticated;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *displayname;

	ಆದರೆ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_ವಿಧಾನ = "gssapi-with-mic";

	ಆದರೆ ((displayname = ssh_gssapi_displayname()) != ಖಾಲಿ)
		auth2_ದಾಖಲೆ_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ಹಿಂತಿರುಗಿ (authenticated);
}
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

