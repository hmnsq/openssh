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

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#endif

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
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"

#ifdef GSSAPI
ಸ್ಥಿರ Gssctxt *gsscontext = ರಿಕ್ತ;
#endif

/* Imports */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ u_int utmp_len;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *cfg;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;
ಬಾಹ್ಯ ಸಂರಚನಾ include_list includes;
ಬಾಹ್ಯ ಸಂರಚನಾ sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

ಪೂರ್ಣಾಙ್ಕ mm_answer_moduli(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_setcompat(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_sign(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pwnamallow(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_auth2_read_banner(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_authserv(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_authpassword(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_bsdauthquery(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_bsdauthrespond(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_keyallowed(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_keyverify(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pty(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pty_cleanup(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_term(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_state(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);

#ifdef USE_PAM
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_start(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_account(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_init_ctx(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_query(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_respond(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_pam_free_ctx(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
#endif

#ifdef GSSAPI
ಪೂರ್ಣಾಙ್ಕ mm_answer_gss_setup_ctx(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_gss_accept_ctx(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_gss_userok(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_gss_checkmic(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
ಪೂರ್ಣಾಙ್ಕ mm_answer_audit_event(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ mm_answer_audit_command(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
#endif

ಸ್ಥಿರ Authctxt *authctxt;

/* local state for key verify */
ಸ್ಥಿರ u_char *ಕೀಲಿ_blob = ರಿಕ್ತ;
ಸ್ಥಿರ size_t ಕೀಲಿ_bloblen = 0;
ಸ್ಥಿರ u_int ಕೀಲಿ_blobtype = MM_NOKEY;
ಸ್ಥಿರ ಸಂರಚನಾ sshauthopt *ಕೀಲಿ_opts = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *hostbased_cuser = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *hostbased_chost = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *auth_method = "unknown";
ಸ್ಥಿರ ವರ್ಣ *auth_submethod = ರಿಕ್ತ;
ಸ್ಥಿರ u_int session_id2_len = 0;
ಸ್ಥಿರ u_char *session_id2 = ರಿಕ್ತ;
ಸ್ಥಿರ pid_t monitor_child_pid;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ auth_attempted = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ invalid_user = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ compat_set = 0;

ಸಂರಚನಾ mon_table {
	ಗಣನಾ monitor_reqtype type;
	ಪೂರ್ಣಾಙ್ಕ flags;
	ಪೂರ್ಣಾಙ್ಕ (*f)(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ monitor_read(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ monitor *, ಸಂರಚನಾ mon_table *,
    ಸಂರಚನಾ mon_table **);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ monitor_read_log(ಸಂರಚನಾ monitor *);

ಸಂರಚನಾ mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#endif
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#ifdef USE_PAM
    {MONITOR_REQ_PAM_START, MON_ONCE, mm_answer_pam_start},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#endif
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#endif
#ifdef BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#endif
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#ifdef GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_setup_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#endif
    {0, 0, ರಿಕ್ತ}
};

ಸಂರಚನಾ mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#ifdef WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#endif
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
#ifdef SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#endif
    {0, 0, ರಿಕ್ತ}
};

ಸಂರಚನಾ mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ಸ್ಥಿರ ಶೂನ್ಯ
monitor_permit(ಸಂರಚನಾ mon_table *ent, ಗಣನಾ monitor_reqtype type, ಪೂರ್ಣಾಙ್ಕ permit)
{
	ಯಾವತ್ (ent->f != ರಿಕ್ತ) {
		ಯದಿ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ಪ್ರತ್ಯಾಗಮ;
		}
		ent++;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_permit_authentications(ಪೂರ್ಣಾಙ್ಕ permit)
{
	ಸಂರಚನಾ mon_table *ent = mon_dispatch;

	ಯಾವತ್ (ent->f != ರಿಕ್ತ) {
		ಯದಿ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

ಶೂನ್ಯ
monitor_child_preauth(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor)
{
	ಸಂರಚನಾ mon_table *ent;
	ಪೂರ್ಣಾಙ್ಕ status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ಯದಿ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ಯದಿ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, ಪರಿಮಾಣ(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ಯಾವತ್ (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = ರಿಕ್ತ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ಯದಿ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ಯದಿ (options.ಅಂಕೆ_auth_methods != 0) {
			ಯದಿ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		ಯದಿ (authenticated) {
			ಯದಿ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ಯದಿ (authctxt->pw->pw_uid == 0 &&
			    !auth_ಬೇರು_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			ಯದಿ (options.use_pam && authenticated) {
				ಸಂರಚನಾ sshbuf *m;

				ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#endif
		}
		ಯದಿ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			ಯದಿ (!partial && !authenticated)
				authctxt->failures++;
			ಯದಿ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		ಯದಿ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ಯದಿ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ಯದಿ (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ರಿಕ್ತ;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ಯಾವತ್ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ಯಾವತ್ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ಯದಿ (errno == EINTR)
			ಅನುವರ್ತ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಯದಿ (WIFEXITED(status)) {
		ಯದಿ (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} ಅನ್ಯಥಾ ಯದಿ (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	ಯದಿ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ಯದಿ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_child_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	kill(monitor_child_pid, sig);
}

ಶೂನ್ಯ
monitor_child_postauth(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(SIGTERM, &monitor_child_handler);
	ssh_signal(SIGINT, &monitor_child_handler);
#ifdef SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#endif

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

	ಯದಿ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	ಪ್ರತಿ (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
monitor_read_log(ಸಂರಚನಾ monitor *pmonitor)
{
	ಸಂರಚನಾ sshbuf *logmsg;
	u_int len, level, forced;
	ವರ್ಣ *ಸಂದೇಶ;
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((logmsg = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");

	/* Read length */
	ಯದಿ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ಯದಿ (atomicio(ಪಠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		ಯದಿ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ಯದಿ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ಯದಿ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ಯದಿ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ಯದಿ (atomicio(ಪಠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ಯದಿ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ಯದಿ (log_level_name(level) == ರಿಕ್ತ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", ಸಂದೇಶ,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	ಮುಕ್ತ(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
monitor_read(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor, ಸಂರಚನಾ mon_table *ent,
    ಸಂರಚನಾ mon_table **pent)
{
	ಸಂರಚನಾ sshbuf *m;
	ಪೂರ್ಣಾಙ್ಕ r, ret;
	u_char type;
	ಸಂರಚನಾ pollfd pfd[2];

	ಪ್ರತಿ (;;) {
		memset(&pfd, 0, ಪರಿಮಾಣ(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ಯದಿ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ಯದಿ (errno == EINTR || errno == EAGAIN)
				ಅನುವರ್ತ;
			fatal_f("poll: %s", strerror(errno));
		}
		ಯದಿ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ಅನುವರ್ತ;
		}
		ಯದಿ (pfd[0].revents)
			ಭಙ್ಗ;  /* Continues below */
	}

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ಯದಿ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ಯಾವತ್ (ent->f != ರಿಕ್ತ) {
		ಯದಿ (ent->type == type)
			ಭಙ್ಗ;
		ent++;
	}

	ಯದಿ (ent->f != ರಿಕ್ತ) {
		ಯದಿ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ಯದಿ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ಯದಿ (pent != ರಿಕ್ತ)
			*pent = ent;

		ಪ್ರತ್ಯಾಗಮ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ಪ್ರತ್ಯಾಗಮ (-1);
}

/* allowed key state */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
monitor_allowed_ಕೀಲಿ(ಧ್ರುವ u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ಯದಿ (ಕೀಲಿ_blob == ರಿಕ್ತ || ಕೀಲಿ_bloblen != bloblen ||
	    timingsafe_bcmp(ಕೀಲಿ_blob, blob, ಕೀಲಿ_bloblen))
		ಪ್ರತ್ಯಾಗಮ (0);
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_reset_ಕೀಲಿ_state(ಶೂನ್ಯ)
{
	/* reset state */
	ಮುಕ್ತ(ಕೀಲಿ_blob);
	ಮುಕ್ತ(hostbased_cuser);
	ಮುಕ್ತ(hostbased_chost);
	sshauthopt_free(ಕೀಲಿ_opts);
	ಕೀಲಿ_blob = ರಿಕ್ತ;
	ಕೀಲಿ_bloblen = 0;
	ಕೀಲಿ_blobtype = MM_NOKEY;
	ಕೀಲಿ_opts = ರಿಕ್ತ;
	hostbased_cuser = ರಿಕ್ತ;
	hostbased_chost = ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_state(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *unused)
{
	ಸಂರಚನಾ sshbuf *m = ರಿಕ್ತ, *config = ರಿಕ್ತ, *hostkeys = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *opts = ರಿಕ್ತ, *confdata = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ postauth;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ ||
	    (config = sshbuf_new()) == ರಿಕ್ತ ||
	    (opts = sshbuf_new()) == ರಿಕ್ತ ||
	    (confdata = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ಯದಿ ((r = serialise_server_options(&options, &config)) != 0)
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
	ಯದಿ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ಯದಿ (postauth) {
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

	ಪ್ರತ್ಯಾಗಮ (0);
}

#ifdef WITH_OPENSSL
ಪೂರ್ಣಾಙ್ಕ
mm_answer_moduli(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	DH *dh;
	ಧ್ರುವ BIGNUM *dh_p, *dh_g;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int min, want, max;

	ಯದಿ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ಯದಿ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	ಯದಿ (dh == ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ಅನ್ಯಥಾ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ರಿಕ್ತ, &dh_g);
		ಯದಿ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
mm_answer_setcompat(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_sign(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ auth_sock;			/* XXX move to state struct? */
	ಸಂರಚನಾ sshkey *pubkey, *ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *sigbuf = ರಿಕ್ತ;
	u_char *p = ರಿಕ್ತ, *signature = ರಿಕ್ತ;
	ವರ್ಣ *alg = ರಿಕ್ತ;
	size_t datlen, siglen;
	ಪೂರ್ಣಾಙ್ಕ r, is_proof = 0, keyid;
	u_int compat;
	ಧ್ರುವ ವರ್ಣ proof_req[] = "hostkeys-prove-00@openssh.com";
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ಯದಿ (!compat_set)
		fatal_f("state error: setcompat never called");

	ಯದಿ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	ಯದಿ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ಯದಿ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ಯದಿ ((ಕೀಲಿ = get_hostkey_public_by_index(keyid, ssh)) == ರಿಕ್ತ)
			fatal_f("no hostkey for index %d", keyid);
		ಯದಿ (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, ಪರಿಮಾಣ(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		ಯದಿ (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(ಕೀಲಿ), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		ಯದಿ ((sigbuf = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new");
		ಯದಿ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(ಕೀಲಿ, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ಯದಿ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ಯದಿ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	ಯದಿ ((ಕೀಲಿ = get_hostkey_by_index(keyid)) != ರಿಕ್ತ) {
		ಯದಿ ((r = sshkey_sign(ಕೀಲಿ, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ರಿಕ್ತ, compat)) != 0)
			fatal_fr(r, "sign");
	} ಅನ್ಯಥಾ ಯದಿ ((ಕೀಲಿ = get_hostkey_public_by_index(keyid, ssh)) != ರಿಕ್ತ &&
	    auth_sock > 0) {
		ಯದಿ ((r = ssh_agent_sign(auth_sock, ಕೀಲಿ, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ಅನ್ಯಥಾ
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	ಮುಕ್ತ(alg);
	ಮುಕ್ತ(p);
	ಮುಕ್ತ(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

#define PUTPW(b, id) \
	ಕುರು { \
		ಯದಿ ((r = sshbuf_put_string(b, \
		    &pwent->id, ಪರಿಮಾಣ(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ಯಾವತ್ (0)

ಶೂನ್ಯ
mm_encode_server_options(ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *config;

	ಯದಿ ((config = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ಯದಿ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
ಪೂರ್ಣಾಙ್ಕ
mm_answer_pwnamallow(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಸಂರಚನಾ passwd *pwent;
	ಪೂರ್ಣಾಙ್ಕ r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ಯದಿ (!compat_set)
		fatal_f("state error: setcompat never called");

	ಯದಿ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ಯದಿ ((r = sshbuf_get_cstring(m, &authctxt->user, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ಯದಿ (pwent == ರಿಕ್ತ) {
		invalid_user = 1;
		ಯದಿ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		ಗಚ್ಛ out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ಯದಿ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	ಯದಿ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#endif
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 out:
	ssh_packet_set_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	ಯದಿ (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_port(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	ಯದಿ (auth2_setup_methods_lists(authctxt) != 0) {
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

#ifdef USE_PAM
	ಯದಿ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ mm_answer_auth2_read_banner(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ *banner;
	ಪೂರ್ಣಾಙ್ಕ r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ಯದಿ ((r = sshbuf_put_cstring(m, banner != ರಿಕ್ತ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	ಮುಕ್ತ(banner);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_authserv(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	monitor_permit_authentications(1);

	ಯದಿ ((r = sshbuf_get_cstring(m, &authctxt->service, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ಯದಿ (strlen(authctxt->style) == 0) {
		ಮುಕ್ತ(authctxt->style);
		authctxt->style = ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_base_type_match(ಧ್ರುವ ವರ್ಣ *method, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *list)
{
	ವರ್ಣ *s, *l, *ol = xstrdup(list);
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	l = ol;
	ಪ್ರತಿ ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ಯದಿ (sshkey_type_from_name(s) == ಕೀಲಿ->type) {
			found = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(ಕೀಲಿ), list);
	}

	ಮುಕ್ತ(ol);
	ಪ್ರತ್ಯಾಗಮ found;
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_authpassword(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ call_ಎಣಿಕೆ;
	ವರ್ಣ *passwd;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated;
	size_t plen;

	ಯದಿ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ಯದಿ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	ಯದಿ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_ಎಣಿಕೆ++;
	ಯದಿ (plen == 0 && call_ಎಣಿಕೆ == 1)
		auth_method = "none";
	ಅನ್ಯಥಾ
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	ಪ್ರತ್ಯಾಗಮ (authenticated);
}

#ifdef BSD_AUTH
ಪೂರ್ಣಾಙ್ಕ
mm_answer_bsdauthquery(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ *name, *infotxt;
	u_int numprompts, *echo_on, success;
	ವರ್ಣ **prompts;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ಯದಿ (success) {
		ಯದಿ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ಯದಿ (success) {
		ಮುಕ್ತ(name);
		ಮುಕ್ತ(infotxt);
		ಮುಕ್ತ(prompts);
		ಮುಕ್ತ(echo_on);
	}

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_bsdauthrespond(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ *response;
	ಪೂರ್ಣಾಙ್ಕ r, authok;

	ಯದಿ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ಯದಿ (authctxt->as == ರಿಕ್ತ)
		fatal_f("no bsd auth session");

	ಯದಿ ((r = sshbuf_get_cstring(m, &response, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ರಿಕ್ತ;
	debug3_f("<%s> = <%d>", response, authok);
	ಮುಕ್ತ(response);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ಪ್ರತ್ಯಾಗಮ (authok != 0);
}
#endif

#ifdef USE_PAM
ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_start(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಯದಿ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ಯದಿ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_account(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	u_int ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ಯದಿ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ *sshpam_ctxt, *sshpam_authok;
ಬಾಹ್ಯ KbdintDevice sshpam_device;

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_init_ctx(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	u_int ok = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ಯದಿ (sshpam_ctxt != ರಿಕ್ತ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ರಿಕ್ತ;
	sshbuf_reset(m);
	ಯದಿ (sshpam_ctxt != ರಿಕ್ತ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ಯದಿ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_query(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ *name = ರಿಕ್ತ, *info = ರಿಕ್ತ, **prompts = ರಿಕ್ತ;
	u_int i, ಅಂಕೆ = 0, *echo_on = 0;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	debug3_f("entering");
	sshpam_authok = ರಿಕ್ತ;
	ಯದಿ (sshpam_ctxt == ರಿಕ್ತ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &ಅಂಕೆ, &prompts, &echo_on);
	ಯದಿ (ret == 0 && ಅಂಕೆ == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ಯದಿ (ಅಂಕೆ > 1 || name == ರಿಕ್ತ || info == ರಿಕ್ತ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಮುಕ್ತ(name);
	ಮುಕ್ತ(info);
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ; ++i) {
		ಯದಿ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		ಮುಕ್ತ(prompts[i]);
	}
	ಮುಕ್ತ(prompts);
	ಮುಕ್ತ(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_respond(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ **resp;
	u_int i, ಅಂಕೆ;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	debug3_f("entering");
	ಯದಿ (sshpam_ctxt == ರಿಕ್ತ)
		fatal_f("no context");
	sshpam_authok = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_get_u32(m, &ಅಂಕೆ)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (ಅಂಕೆ > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    ಅಂಕೆ, (unsigned)PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ);
	}
	ಯದಿ (ಅಂಕೆ > 0) {
		resp = xcalloc(ಅಂಕೆ, ಪರಿಮಾಣ(ವರ್ಣ *));
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ; ++i) {
			ಯದಿ ((r = sshbuf_get_cstring(m, &(resp[i]), ರಿಕ್ತ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, ಅಂಕೆ, resp);
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ; ++i)
			ಮುಕ್ತ(resp[i]);
		ಮುಕ್ತ(resp);
	} ಅನ್ಯಥಾ {
		ret = (sshpam_device.respond)(sshpam_ctxt, ಅಂಕೆ, ರಿಕ್ತ);
	}
	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ಯದಿ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pam_free_ctx(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r = sshpam_authok != ರಿಕ್ತ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ಯದಿ (sshpam_ctxt == ರಿಕ್ತ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ರಿಕ್ತ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif

ಪೂರ್ಣಾಙ್ಕ
mm_answer_keyallowed(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	ಪೂರ್ಣಾಙ್ಕ r, allowed = 0;
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;

	debug3_f("entering");
	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ರಿಕ್ತ)) != 0 ||
	    (r = sshkey_froms(m, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ && authctxt->valid) {
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ MM_USERKEY:
			auth_method = "publickey";
			ಯದಿ (!options.pubkey_authentication)
				ಭಙ್ಗ;
			ಯದಿ (auth2_ಕೀಲಿ_already_used(authctxt, ಕೀಲಿ))
				ಭಙ್ಗ;
			ಯದಿ (!ಕೀಲಿ_base_type_match(auth_method, ಕೀಲಿ,
			    options.pubkey_accepted_algos))
				ಭಙ್ಗ;
			allowed = user_ಕೀಲಿ_allowed(ssh, authctxt->pw, ಕೀಲಿ,
			    pubkey_auth_attempt, &opts);
			ಭಙ್ಗ;
		ಪಕ್ಷ MM_HOSTKEY:
			auth_method = "hostbased";
			ಯದಿ (!options.hostbased_authentication)
				ಭಙ್ಗ;
			ಯದಿ (auth2_ಕೀಲಿ_already_used(authctxt, ಕೀಲಿ))
				ಭಙ್ಗ;
			ಯದಿ (!ಕೀಲಿ_base_type_match(auth_method, ಕೀಲಿ,
			    options.hostbased_accepted_algos))
				ಭಙ್ಗ;
			allowed = hostbased_ಕೀಲಿ_allowed(ssh, authctxt->pw,
			    cuser, chost, ಕೀಲಿ);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal_f("unknown key type %u", type);
			ಭಙ್ಗ;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (ಕೀಲಿ == ರಿಕ್ತ || !authctxt->valid) ? "invalid" : sshkey_type(ಕೀಲಿ),
	    allowed ? "allowed" : "not allowed");

	auth2_record_ಕೀಲಿ(authctxt, 0, ಕೀಲಿ);

	/* clear temporarily storage (used by verify) */
	monitor_reset_ಕೀಲಿ_state();

	ಯದಿ (allowed) {
		/* Save temporarily for comparison in verify */
		ಯದಿ ((r = sshkey_to_blob(ಕೀಲಿ, &ಕೀಲಿ_blob, &ಕೀಲಿ_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		ಕೀಲಿ_blobtype = type;
		ಕೀಲಿ_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ಅನ್ಯಥಾ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, ರಿಕ್ತ);
		ಮುಕ್ತ(cuser);
		ಮುಕ್ತ(chost);
	}
	sshkey_free(ಕೀಲಿ);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ಯದಿ (opts != ರಿಕ್ತ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ಯದಿ (!allowed)
		sshauthopt_free(opts);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
monitor_valid_userblob(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ u_char *data, u_int datalen)
{
	ಸಂರಚನಾ sshbuf *b;
	ಸಂರಚನಾ sshkey *hostkey = ರಿಕ್ತ;
	ಧ್ರುವ u_char *p;
	ವರ್ಣ *userstyle, *cp;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ hostbound = 0, r, fail = 0;

	ಯದಿ ((b = sshbuf_from(data, datalen)) == ರಿಕ್ತ)
		fatal_f("sshbuf_from");

	ಯದಿ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ಯದಿ ((session_id2 == ರಿಕ್ತ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ಯದಿ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;
	ಯದಿ ((r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ಯದಿ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ಮುಕ್ತ(userstyle);
	ಮುಕ್ತ(cp);
	ಯದಿ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse method");
	ಯದಿ (strcmp("publickey", cp) != 0) {
		ಯದಿ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ಅನ್ಯಥಾ
			fail++;
	}
	ಮುಕ್ತ(cp);
	ಯದಿ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ಯದಿ (type == 0)
		fail++;
	ಯದಿ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ಯದಿ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ಯದಿ (hostkey != ರಿಕ್ತ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ಯದಿ (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ಪ್ರತ್ಯಾಗಮ (fail == 0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
monitor_valid_hostbasedblob(ಧ್ರುವ u_char *data, u_int datalen,
    ಧ್ರುವ ವರ್ಣ *cuser, ಧ್ರುವ ವರ್ಣ *chost)
{
	ಸಂರಚನಾ sshbuf *b;
	ಧ್ರುವ u_char *p;
	ವರ್ಣ *cp, *userstyle;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r, fail = 0;
	u_char type;

	ಯದಿ ((b = sshbuf_from(data, datalen)) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ಯದಿ ((session_id2 == ರಿಕ್ತ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ಯದಿ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)
		fail++;
	ಯದಿ ((r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ಯದಿ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	ಮುಕ್ತ(userstyle);
	ಮುಕ್ತ(cp);
	ಯದಿ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse method");
	ಯದಿ (strcmp(cp, "hostbased") != 0)
		fail++;
	ಮುಕ್ತ(cp);
	ಯದಿ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ಯದಿ ((r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse host");
	ಯದಿ (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ಯದಿ (strcmp(cp, chost) != 0)
		fail++;
	ಮುಕ್ತ(cp);

	/* verify client user */
	ಯದಿ ((r = sshbuf_get_cstring(b, &cp, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse ruser");
	ಯದಿ (strcmp(cp, cuser) != 0)
		fail++;
	ಮುಕ್ತ(cp);

	ಯದಿ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ (fail == 0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_keyverify(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ಧ್ರುವ u_char *signature, *data, *blob;
	ವರ್ಣ *sigalg = ರಿಕ್ತ, *fp = ರಿಕ್ತ;
	size_t signaturelen, datalen, bloblen;
	ಪೂರ್ಣಾಙ್ಕ r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	ಪೂರ್ಣಾಙ್ಕ encoded_ret;
	ಸಂರಚನಾ sshkey_sig_details *sig_details = ರಿಕ್ತ;

	ಯದಿ ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (hostbased_cuser == ರಿಕ್ತ || hostbased_chost == ರಿಕ್ತ ||
	  !monitor_allowed_ಕೀಲಿ(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ಯದಿ (*sigalg == '\0') {
		ಮುಕ್ತ(sigalg);
		sigalg = ರಿಕ್ತ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ಯದಿ ((r = sshkey_from_blob(blob, bloblen, &ಕೀಲಿ)) != 0)
		fatal_fr(r, "parse key");

	ವಿಕಲ್ಪ (ಕೀಲಿ_blobtype) {
	ಪಕ್ಷ MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		ಭಙ್ಗ;
	ಪಕ್ಷ MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		valid_data = 0;
		ಭಙ್ಗ;
	}
	ಯದಿ (!valid_data)
		fatal_f("bad %s signature data blob",
		    ಕೀಲಿ_blobtype == MM_USERKEY ? "userkey" :
		    (ಕೀಲಿ_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(ಕೀಲಿ, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(ಕೀಲಿ), sigalg == ರಿಕ್ತ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ಯದಿ (ret == 0 && ಕೀಲಿ_blobtype == MM_USERKEY && sig_details != ರಿಕ್ತ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !ಕೀಲಿ_opts->no_require_user_presence;
		ಯದಿ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(ಕೀಲಿ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || ಕೀಲಿ_opts->require_verify;
		ಯದಿ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(ಕೀಲಿ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_ಕೀಲಿ(authctxt, ret == 0, ಕೀಲಿ);

	ಯದಿ (ಕೀಲಿ_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, ಕೀಲಿ_opts);
	monitor_reset_ಕೀಲಿ_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ಯದಿ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ರಿಕ್ತ)) != 0)
		fatal_fr(r, "assemble");
	ಯದಿ (sig_details != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	ಮುಕ್ತ(sigalg);
	ಮುಕ್ತ(fp);
	sshkey_free(ಕೀಲಿ);

	ಪ್ರತ್ಯಾಗಮ ret == 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_record_login(ಸಂರಚನಾ ssh *ssh, Session *s, ಸಂರಚನಾ passwd *pw)
{
	socklen_t fromlen;
	ಸಂರಚನಾ sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, ಪರಿಮಾಣ(from));
	fromlen = ಪರಿಮಾಣ(from);
	ಯದಿ (ssh_packet_connection_is_on_socket(ssh)) {
		ಯದಿ (getpeername(ssh_packet_get_connection_in(ssh),
		    (ಸಂರಚನಾ sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ಸಂರಚನಾ sockaddr *)&from, fromlen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	ಯದಿ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pty(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಬಾಹ್ಯ ಸಂರಚನಾ monitor *pmonitor;
	Session *s;
	ಪೂರ್ಣಾಙ್ಕ r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ಯದಿ (s == ರಿಕ್ತ)
		ಗಚ್ಛ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, ಪರಿಮಾಣ(s->tty));
	ಯದಿ (res == 0)
		ಗಚ್ಛ error;
	pty_setowner(authctxt->pw, s->tty);

	ಯದಿ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ಯದಿ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ಯದಿ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ಯದಿ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ಯದಿ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ಯದಿ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ಪ್ರತ್ಯಾಗಮ (0);

 error:
	ಯದಿ (s != ರಿಕ್ತ)
		mm_session_close(s);
	ಯದಿ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_pty_cleanup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	Session *s;
	ವರ್ಣ *tty;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((r = sshbuf_get_cstring(m, &tty, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse tty");
	ಯದಿ ((s = session_by_tty(tty)) != ರಿಕ್ತ)
		mm_session_close(s);
	sshbuf_reset(m);
	ಮುಕ್ತ(tty);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_term(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *req)
{
	ಬಾಹ್ಯ ಸಂರಚನಾ monitor *pmonitor;
	ಪೂರ್ಣಾಙ್ಕ res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	ಯದಿ (options.use_pam)
		sshpam_cleanup();
#endif

	ಯಾವತ್ (waitpid(pmonitor->m_pid, &status, 0) == -1)
		ಯದಿ (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
ಪೂರ್ಣಾಙ್ಕ
mm_answer_audit_event(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ socket, ಸಂರಚನಾ sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	ವಿಕಲ್ಪ (event) {
	ಪಕ್ಷ SSH_AUTH_FAIL_PUBKEY:
	ಪಕ್ಷ SSH_AUTH_FAIL_HOSTBASED:
	ಪಕ್ಷ SSH_AUTH_FAIL_GSSAPI:
	ಪಕ್ಷ SSH_LOGIN_EXCEED_MAXTRIES:
	ಪಕ್ಷ SSH_LOGIN_ಬೇರು_DENIED:
	ಪಕ್ಷ SSH_CONNECTION_CLOSE:
	ಪಕ್ಷ SSH_INVALID_USER:
		audit_event(ssh, event);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("Audit event type %d not permitted", event);
	}

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_audit_command(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ socket, ಸಂರಚನಾ sshbuf *m)
{
	ವರ್ಣ *cmd;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ ((r = sshbuf_get_cstring(m, &cmd, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	ಮುಕ್ತ(cmd);
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif /* SSH_AUDIT_EVENTS */

ಶೂನ್ಯ
monitor_clear_keystate(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = ರಿಕ್ತ;
}

ಶೂನ್ಯ
monitor_apply_keystate(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor)
{
	ಸಂರಚನಾ kex *kex;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("packet_set_state");
	ಯದಿ ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = ರಿಕ್ತ;
	ಯದಿ ((kex = ssh->kex) == ರಿಕ್ತ)
		fatal_f("internal error: ssh->kex == NULL");
	ಯದಿ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ಯದಿ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#ifdef WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#endif
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_ಕೀಲಿ=&get_hostkey_public_by_type;
	kex->load_host_private_ಕೀಲಿ=&get_hostkey_private_by_type;
	kex->host_ಕೀಲಿ_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

ಶೂನ್ಯ
mm_get_keystate(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ಯದಿ ((child_state = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

ಸ್ಥಿರ ಶೂನ್ಯ
monitor_openfds(ಸಂರಚನಾ monitor *mon, ಪೂರ್ಣಾಙ್ಕ do_logfds)
{
	ಪೂರ್ಣಾಙ್ಕ pair[2];
#ifdef SO_ZEROIZE
	ಪೂರ್ಣಾಙ್ಕ on = 1;
#endif

	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	ಯದಿ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, ಪರಿಮಾಣ(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ಯದಿ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, ಪರಿಮಾಣ(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ಯದಿ (do_logfds) {
		ಯದಿ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} ಅನ್ಯಥಾ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ಸಂರಚನಾ monitor *
monitor_init(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ monitor *mon;

	mon = xcalloc(1, ಪರಿಮಾಣ(*mon));
	monitor_openfds(mon, 1);

	ಪ್ರತ್ಯಾಗಮ mon;
}

ಶೂನ್ಯ
monitor_reinit(ಸಂರಚನಾ monitor *mon)
{
	monitor_openfds(mon, 0);
}

ಪೂರ್ಣಾಙ್ಕ
monitor_auth_attempted(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ auth_attempted;
}

ಪೂರ್ಣಾಙ್ಕ
monitor_invalid_user(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ invalid_user;
}

#ifdef GSSAPI
ಪೂರ್ಣಾಙ್ಕ
mm_answer_gss_setup_ctx(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ಯದಿ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	ಮುಕ್ತ(goid.elements);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_gss_accept_ctx(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ಯದಿ ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	ಮುಕ್ತ(in.ಮೌಲ್ಯ);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.ಮೌಲ್ಯ, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	ಯದಿ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_gss_checkmic(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ಯದಿ ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	ಮುಕ್ತ(gssbuf.ಮೌಲ್ಯ);
	ಮುಕ್ತ(mic.ಮೌಲ್ಯ);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ಯದಿ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
mm_answer_gss_userok(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r, authenticated;
	ಧ್ರುವ ವರ್ಣ *displayname;

	ಯದಿ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	ಯದಿ ((displayname = ssh_gssapi_displayname()) != ರಿಕ್ತ)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ಪ್ರತ್ಯಾಗಮ (authenticated);
}
#endif /* GSSAPI */

