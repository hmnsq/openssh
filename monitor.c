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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/tree.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/dh.h>
#endif

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "auth-pam.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "session.h"
#അന്തര്ഭാവ "sshlogin.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "monitor.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "monitor_fdpass.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "srclimit.h"

#ifdef GSSAPI
സ്ഥിതം Gssctxt *gsscontext = ശൂന്യ;
#endif

/* Imports */
ബാഹ്യ ServerOptions options;
ബാഹ്യ u_int utmp_len;
ബാഹ്യ ഘടന sshbuf *cfg;
ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ഘടന include_list includes;
ബാഹ്യ ഘടന sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
സ്ഥിതം ഘടന sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

പൂർണ്ണസംഖ്യ mm_answer_moduli(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_setcompat(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_sign(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pwnamallow(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_auth2_read_banner(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_authserv(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_authpassword(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_bsdauthquery(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_bsdauthrespond(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_keyallowed(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_keyverify(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pty(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pty_cleanup(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_term(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_state(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);

#ifdef USE_PAM
പൂർണ്ണസംഖ്യ mm_answer_pam_start(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pam_account(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pam_init_ctx(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pam_query(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pam_respond(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_pam_free_ctx(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
#endif

#ifdef GSSAPI
പൂർണ്ണസംഖ്യ mm_answer_gss_setup_ctx(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_gss_accept_ctx(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_gss_userok(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_gss_checkmic(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
പൂർണ്ണസംഖ്യ mm_answer_audit_event(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ mm_answer_audit_command(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
#endif

സ്ഥിതം Authctxt *authctxt;

/* local state for key verify */
സ്ഥിതം u_char *താക്കോൽ_blob = ശൂന്യ;
സ്ഥിതം size_t താക്കോൽ_bloblen = 0;
സ്ഥിതം u_int താക്കോൽ_blobtype = MM_NOKEY;
സ്ഥിതം ഘടന sshauthopt *താക്കോൽ_opts = ശൂന്യ;
സ്ഥിതം അക്ഷരം *hostbased_cuser = ശൂന്യ;
സ്ഥിതം അക്ഷരം *hostbased_chost = ശൂന്യ;
സ്ഥിതം അക്ഷരം *auth_method = "unknown";
സ്ഥിതം അക്ഷരം *auth_submethod = ശൂന്യ;
സ്ഥിതം u_int session_id2_len = 0;
സ്ഥിതം u_char *session_id2 = ശൂന്യ;
സ്ഥിതം pid_t monitor_child_pid;
സ്ഥിതം പൂർണ്ണസംഖ്യ auth_attempted = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ invalid_user = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ compat_set = 0;

ഘടന mon_table {
	എണ്ണൽ monitor_reqtype type;
	പൂർണ്ണസംഖ്യ flags;
	പൂർണ്ണസംഖ്യ (*f)(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

സ്ഥിതം പൂർണ്ണസംഖ്യ monitor_read(ഘടന ssh *, ഘടന monitor *, ഘടന mon_table *,
    ഘടന mon_table **);
സ്ഥിതം പൂർണ്ണസംഖ്യ monitor_read_log(ഘടന monitor *);

ഘടന mon_table mon_dispatch_proto20[] = {
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
    {0, 0, ശൂന്യ}
};

ഘടന mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, ശൂന്യ}
};

ഘടന mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
സ്ഥിതം ശൂന്യം
monitor_permit(ഘടന mon_table *ent, എണ്ണൽ monitor_reqtype type, പൂർണ്ണസംഖ്യ permit)
{
	ആകുമ്പോൾ (ent->f != ശൂന്യ) {
		എങ്കിൽ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			തിരികെ;
		}
		ent++;
	}
}

സ്ഥിതം ശൂന്യം
monitor_permit_authentications(പൂർണ്ണസംഖ്യ permit)
{
	ഘടന mon_table *ent = mon_dispatch;

	ആകുമ്പോൾ (ent->f != ശൂന്യ) {
		എങ്കിൽ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

ശൂന്യം
monitor_child_preauth(ഘടന ssh *ssh, ഘടന monitor *pmonitor)
{
	ഘടന mon_table *ent;
	പൂർണ്ണസംഖ്യ status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	എങ്കിൽ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	എങ്കിൽ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, വലുപ്പം(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ആകുമ്പോൾ (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = ശൂന്യ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		എങ്കിൽ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		എങ്കിൽ (options.അക്കം_auth_methods != 0) {
			എങ്കിൽ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		എങ്കിൽ (authenticated) {
			എങ്കിൽ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			എങ്കിൽ (authctxt->pw->pw_uid == 0 &&
			    !auth_വേര്_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			എങ്കിൽ (options.use_pam && authenticated) {
				ഘടന sshbuf *m;

				എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
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
		എങ്കിൽ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			എങ്കിൽ (!partial && !authenticated)
				authctxt->failures++;
			എങ്കിൽ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		എങ്കിൽ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	എങ്കിൽ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	എങ്കിൽ (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = ശൂന്യ;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ആകുമ്പോൾ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ആകുമ്പോൾ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		എങ്കിൽ (errno == EINTR)
			തുടരുക;
		fatal_f("waitpid: %s", strerror(errno));
	}
	എങ്കിൽ (WIFEXITED(status)) {
		എങ്കിൽ (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} അല്ലെങ്കിൽ എങ്കിൽ (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	എങ്കിൽ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	എങ്കിൽ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

സ്ഥിതം ശൂന്യം
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

സ്ഥിതം ശൂന്യം
monitor_child_handler(പൂർണ്ണസംഖ്യ sig)
{
	kill(monitor_child_pid, sig);
}

ശൂന്യം
monitor_child_postauth(ഘടന ssh *ssh, ഘടന monitor *pmonitor)
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

	എങ്കിൽ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	വേണ്ടി (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, ശൂന്യ);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
monitor_read_log(ഘടന monitor *pmonitor)
{
	ഘടന sshbuf *logmsg;
	u_int len, level, forced;
	അക്ഷരം *സന്ദേശം;
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((logmsg = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");

	/* Read length */
	എങ്കിൽ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	എങ്കിൽ (atomicio(പഠ, pmonitor->m_log_recvfd, p, 4) != 4) {
		എങ്കിൽ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			തിരികെ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	എങ്കിൽ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	എങ്കിൽ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	എങ്കിൽ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	എങ്കിൽ (atomicio(പഠ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	എങ്കിൽ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &സന്ദേശം, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	എങ്കിൽ (log_level_name(level) == ശൂന്യ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", സന്ദേശം,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	സ്വതന്ത്രം(സന്ദേശം);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
monitor_read(ഘടന ssh *ssh, ഘടന monitor *pmonitor, ഘടന mon_table *ent,
    ഘടന mon_table **pent)
{
	ഘടന sshbuf *m;
	പൂർണ്ണസംഖ്യ r, ret;
	u_char type;
	ഘടന pollfd pfd[2];

	വേണ്ടി (;;) {
		memset(&pfd, 0, വലുപ്പം(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		എങ്കിൽ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			എങ്കിൽ (errno == EINTR || errno == EAGAIN)
				തുടരുക;
			fatal_f("poll: %s", strerror(errno));
		}
		എങ്കിൽ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			തുടരുക;
		}
		എങ്കിൽ (pfd[0].revents)
			നിർത്തുക;  /* Continues below */
	}

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	എങ്കിൽ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ആകുമ്പോൾ (ent->f != ശൂന്യ) {
		എങ്കിൽ (ent->type == type)
			നിർത്തുക;
		ent++;
	}

	എങ്കിൽ (ent->f != ശൂന്യ) {
		എങ്കിൽ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		എങ്കിൽ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		എങ്കിൽ (pent != ശൂന്യ)
			*pent = ent;

		തിരികെ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	തിരികെ (-1);
}

/* allowed key state */
സ്ഥിതം പൂർണ്ണസംഖ്യ
monitor_allowed_താക്കോൽ(സ്ഥിരം u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	എങ്കിൽ (താക്കോൽ_blob == ശൂന്യ || താക്കോൽ_bloblen != bloblen ||
	    timingsafe_bcmp(താക്കോൽ_blob, blob, താക്കോൽ_bloblen))
		തിരികെ (0);
	തിരികെ (1);
}

സ്ഥിതം ശൂന്യം
monitor_reset_താക്കോൽ_state(ശൂന്യം)
{
	/* reset state */
	സ്വതന്ത്രം(താക്കോൽ_blob);
	സ്വതന്ത്രം(hostbased_cuser);
	സ്വതന്ത്രം(hostbased_chost);
	sshauthopt_free(താക്കോൽ_opts);
	താക്കോൽ_blob = ശൂന്യ;
	താക്കോൽ_bloblen = 0;
	താക്കോൽ_blobtype = MM_NOKEY;
	താക്കോൽ_opts = ശൂന്യ;
	hostbased_cuser = ശൂന്യ;
	hostbased_chost = ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
mm_answer_state(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *unused)
{
	ഘടന sshbuf *m = ശൂന്യ, *config = ശൂന്യ, *hostkeys = ശൂന്യ;
	ഘടന sshbuf *opts = ശൂന്യ, *confdata = ശൂന്യ;
	പൂർണ്ണസംഖ്യ postauth;
	പൂർണ്ണസംഖ്യ r;

	debug_f("config len %zu", sshbuf_len(cfg));

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ ||
	    (config = sshbuf_new()) == ശൂന്യ ||
	    (opts = sshbuf_new()) == ശൂന്യ ||
	    (confdata = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	എങ്കിൽ ((r = serialise_server_options(&options, &config)) != 0)
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
	എങ്കിൽ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	എങ്കിൽ (postauth) {
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

	തിരികെ (0);
}

#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ
mm_answer_moduli(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	DH *dh;
	സ്ഥിരം BIGNUM *dh_p, *dh_g;
	പൂർണ്ണസംഖ്യ r;
	u_int min, want, max;

	എങ്കിൽ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	എങ്കിൽ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	എങ്കിൽ (dh == ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} അല്ലെങ്കിൽ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, ശൂന്യ, &dh_g);
		എങ്കിൽ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	തിരികെ (0);
}
#endif

പൂർണ്ണസംഖ്യ
mm_answer_setcompat(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_sign(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ auth_sock;			/* XXX move to state struct? */
	ഘടന sshkey *pubkey, *താക്കോൽ;
	ഘടന sshbuf *sigbuf = ശൂന്യ;
	u_char *p = ശൂന്യ, *signature = ശൂന്യ;
	അക്ഷരം *alg = ശൂന്യ;
	size_t datlen, siglen;
	പൂർണ്ണസംഖ്യ r, is_proof = 0, keyid;
	u_int compat;
	സ്ഥിരം അക്ഷരം proof_req[] = "hostkeys-prove-00@openssh.com";
	സ്ഥിതം പൂർണ്ണസംഖ്യ nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	എങ്കിൽ (!compat_set)
		fatal_f("state error: setcompat never called");

	എങ്കിൽ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	എങ്കിൽ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		എങ്കിൽ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		എങ്കിൽ ((താക്കോൽ = get_hostkey_public_by_index(keyid, ssh)) == ശൂന്യ)
			fatal_f("no hostkey for index %d", keyid);
		എങ്കിൽ (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, വലുപ്പം(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		എങ്കിൽ (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(താക്കോൽ), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		എങ്കിൽ ((sigbuf = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new");
		എങ്കിൽ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(താക്കോൽ, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		എങ്കിൽ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	എങ്കിൽ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	എങ്കിൽ ((താക്കോൽ = get_hostkey_by_index(keyid)) != ശൂന്യ) {
		എങ്കിൽ ((r = sshkey_sign(താക്കോൽ, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, ശൂന്യ, compat)) != 0)
			fatal_fr(r, "sign");
	} അല്ലെങ്കിൽ എങ്കിൽ ((താക്കോൽ = get_hostkey_public_by_index(keyid, ssh)) != ശൂന്യ &&
	    auth_sock > 0) {
		എങ്കിൽ ((r = ssh_agent_sign(auth_sock, താക്കോൽ, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} അല്ലെങ്കിൽ
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	സ്വതന്ത്രം(alg);
	സ്വതന്ത്രം(p);
	സ്വതന്ത്രം(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	തിരികെ (0);
}

#define PUTPW(b, id) \
	ചെയ്യുക { \
		എങ്കിൽ ((r = sshbuf_put_string(b, \
		    &pwent->id, വലുപ്പം(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ആകുമ്പോൾ (0)

ശൂന്യം
mm_encode_server_options(ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *config;

	എങ്കിൽ ((config = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	എങ്കിൽ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
പൂർണ്ണസംഖ്യ
mm_answer_pwnamallow(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	ഘടന passwd *pwent;
	പൂർണ്ണസംഖ്യ r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	എങ്കിൽ (!compat_set)
		fatal_f("state error: setcompat never called");

	എങ്കിൽ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &authctxt->user, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	എങ്കിൽ (pwent == ശൂന്യ) {
		invalid_user = 1;
		എങ്കിൽ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		പോകുക out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	എങ്കിൽ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	എങ്കിൽ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	എങ്കിൽ (options.refuse_connection) {
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
	എങ്കിൽ (auth2_setup_methods_lists(authctxt) != 0) {
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
	എങ്കിൽ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ mm_answer_auth2_read_banner(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	അക്ഷരം *banner;
	പൂർണ്ണസംഖ്യ r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	എങ്കിൽ ((r = sshbuf_put_cstring(m, banner != ശൂന്യ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	സ്വതന്ത്രം(banner);

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_authserv(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	monitor_permit_authentications(1);

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &authctxt->service, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	എങ്കിൽ (strlen(authctxt->style) == 0) {
		സ്വതന്ത്രം(authctxt->style);
		authctxt->style = ശൂന്യ;
	}

	തിരികെ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_base_type_match(സ്ഥിരം അക്ഷരം *method, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *list)
{
	അക്ഷരം *s, *l, *ol = xstrdup(list);
	പൂർണ്ണസംഖ്യ found = 0;

	l = ol;
	വേണ്ടി ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		എങ്കിൽ (sshkey_type_from_name(s) == താക്കോൽ->type) {
			found = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(താക്കോൽ), list);
	}

	സ്വതന്ത്രം(ol);
	തിരികെ found;
}

പൂർണ്ണസംഖ്യ
mm_answer_authpassword(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ call_എണ്ണം;
	അക്ഷരം *passwd;
	പൂർണ്ണസംഖ്യ r, authenticated;
	size_t plen;

	എങ്കിൽ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	എങ്കിൽ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_എണ്ണം++;
	എങ്കിൽ (plen == 0 && call_എണ്ണം == 1)
		auth_method = "none";
	അല്ലെങ്കിൽ
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	തിരികെ (authenticated);
}

#ifdef BSD_AUTH
പൂർണ്ണസംഖ്യ
mm_answer_bsdauthquery(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	അക്ഷരം *name, *infotxt;
	u_int numprompts, *echo_on, success;
	അക്ഷരം **prompts;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	എങ്കിൽ (success) {
		എങ്കിൽ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	എങ്കിൽ (success) {
		സ്വതന്ത്രം(name);
		സ്വതന്ത്രം(infotxt);
		സ്വതന്ത്രം(prompts);
		സ്വതന്ത്രം(echo_on);
	}

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_bsdauthrespond(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	അക്ഷരം *response;
	പൂർണ്ണസംഖ്യ r, authok;

	എങ്കിൽ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	എങ്കിൽ (authctxt->as == ശൂന്യ)
		fatal_f("no bsd auth session");

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &response, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = ശൂന്യ;
	debug3_f("<%s> = <%d>", response, authok);
	സ്വതന്ത്രം(response);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	തിരികെ (authok != 0);
}
#endif

#ifdef USE_PAM
പൂർണ്ണസംഖ്യ
mm_answer_pam_start(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	എങ്കിൽ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	എങ്കിൽ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_pam_account(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	u_int ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	എങ്കിൽ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	തിരികെ (ret);
}

സ്ഥിതം ശൂന്യം *sshpam_ctxt, *sshpam_authok;
ബാഹ്യ KbdintDevice sshpam_device;

പൂർണ്ണസംഖ്യ
mm_answer_pam_init_ctx(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	u_int ok = 0;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	എങ്കിൽ (sshpam_ctxt != ശൂന്യ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = ശൂന്യ;
	sshbuf_reset(m);
	എങ്കിൽ (sshpam_ctxt != ശൂന്യ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	എങ്കിൽ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_pam_query(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	അക്ഷരം *name = ശൂന്യ, *info = ശൂന്യ, **prompts = ശൂന്യ;
	u_int i, അക്കം = 0, *echo_on = 0;
	പൂർണ്ണസംഖ്യ r, ret;

	debug3_f("entering");
	sshpam_authok = ശൂന്യ;
	എങ്കിൽ (sshpam_ctxt == ശൂന്യ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &അക്കം, &prompts, &echo_on);
	എങ്കിൽ (ret == 0 && അക്കം == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	എങ്കിൽ (അക്കം > 1 || name == ശൂന്യ || info == ശൂന്യ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, അക്കം)) != 0)
		fatal_fr(r, "buffer error");
	സ്വതന്ത്രം(name);
	സ്വതന്ത്രം(info);
	വേണ്ടി (i = 0; i < അക്കം; ++i) {
		എങ്കിൽ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		സ്വതന്ത്രം(prompts[i]);
	}
	സ്വതന്ത്രം(prompts);
	സ്വതന്ത്രം(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_pam_respond(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	അക്ഷരം **resp;
	u_int i, അക്കം;
	പൂർണ്ണസംഖ്യ r, ret;

	debug3_f("entering");
	എങ്കിൽ (sshpam_ctxt == ശൂന്യ)
		fatal_f("no context");
	sshpam_authok = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_get_u32(m, &അക്കം)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (അക്കം > PAM_MAX_അക്കം_സന്ദേശം) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    അക്കം, (unsigned)PAM_MAX_അക്കം_സന്ദേശം);
	}
	എങ്കിൽ (അക്കം > 0) {
		resp = xcalloc(അക്കം, വലുപ്പം(അക്ഷരം *));
		വേണ്ടി (i = 0; i < അക്കം; ++i) {
			എങ്കിൽ ((r = sshbuf_get_cstring(m, &(resp[i]), ശൂന്യ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, അക്കം, resp);
		വേണ്ടി (i = 0; i < അക്കം; ++i)
			സ്വതന്ത്രം(resp[i]);
		സ്വതന്ത്രം(resp);
	} അല്ലെങ്കിൽ {
		ret = (sshpam_device.respond)(sshpam_ctxt, അക്കം, ശൂന്യ);
	}
	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	എങ്കിൽ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_pam_free_ctx(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r = sshpam_authok != ശൂന്യ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	എങ്കിൽ (sshpam_ctxt == ശൂന്യ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = ശൂന്യ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	തിരികെ r;
}
#endif

പൂർണ്ണസംഖ്യ
mm_answer_keyallowed(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	അക്ഷരം *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	പൂർണ്ണസംഖ്യ r, allowed = 0;
	ഘടന sshauthopt *opts = ശൂന്യ;

	debug3_f("entering");
	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, ശൂന്യ)) != 0 ||
	    (r = sshkey_froms(m, &താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (താക്കോൽ != ശൂന്യ && authctxt->valid) {
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ MM_USERKEY:
			auth_method = "publickey";
			എങ്കിൽ (!options.pubkey_authentication)
				നിർത്തുക;
			എങ്കിൽ (auth2_താക്കോൽ_already_used(authctxt, താക്കോൽ))
				നിർത്തുക;
			എങ്കിൽ (!താക്കോൽ_base_type_match(auth_method, താക്കോൽ,
			    options.pubkey_accepted_algos))
				നിർത്തുക;
			allowed = user_താക്കോൽ_allowed(ssh, authctxt->pw, താക്കോൽ,
			    pubkey_auth_attempt, &opts);
			നിർത്തുക;
		അവസ്ഥ MM_HOSTKEY:
			auth_method = "hostbased";
			എങ്കിൽ (!options.hostbased_authentication)
				നിർത്തുക;
			എങ്കിൽ (auth2_താക്കോൽ_already_used(authctxt, താക്കോൽ))
				നിർത്തുക;
			എങ്കിൽ (!താക്കോൽ_base_type_match(auth_method, താക്കോൽ,
			    options.hostbased_accepted_algos))
				നിർത്തുക;
			allowed = hostbased_താക്കോൽ_allowed(ssh, authctxt->pw,
			    cuser, chost, താക്കോൽ);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal_f("unknown key type %u", type);
			നിർത്തുക;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (താക്കോൽ == ശൂന്യ || !authctxt->valid) ? "invalid" : sshkey_type(താക്കോൽ),
	    allowed ? "allowed" : "not allowed");

	auth2_record_താക്കോൽ(authctxt, 0, താക്കോൽ);

	/* clear temporarily storage (used by verify) */
	monitor_reset_താക്കോൽ_state();

	എങ്കിൽ (allowed) {
		/* Save temporarily for comparison in verify */
		എങ്കിൽ ((r = sshkey_to_blob(താക്കോൽ, &താക്കോൽ_blob, &താക്കോൽ_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		താക്കോൽ_blobtype = type;
		താക്കോൽ_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} അല്ലെങ്കിൽ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, ശൂന്യ);
		സ്വതന്ത്രം(cuser);
		സ്വതന്ത്രം(chost);
	}
	sshkey_free(താക്കോൽ);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	എങ്കിൽ (opts != ശൂന്യ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	എങ്കിൽ (!allowed)
		sshauthopt_free(opts);

	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
monitor_valid_userblob(ഘടന ssh *ssh, സ്ഥിരം u_char *data, u_int datalen)
{
	ഘടന sshbuf *b;
	ഘടന sshkey *hostkey = ശൂന്യ;
	സ്ഥിരം u_char *p;
	അക്ഷരം *userstyle, *cp;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ hostbound = 0, r, fail = 0;

	എങ്കിൽ ((b = sshbuf_from(data, datalen)) == ശൂന്യ)
		fatal_f("sshbuf_from");

	എങ്കിൽ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	എങ്കിൽ ((session_id2 == ശൂന്യ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	എങ്കിൽ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != SSH2_സന്ദേശം_USERAUTH_REQUEST)
		fail++;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	എങ്കിൽ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	സ്വതന്ത്രം(userstyle);
	സ്വതന്ത്രം(cp);
	എങ്കിൽ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse method");
	എങ്കിൽ (strcmp("publickey", cp) != 0) {
		എങ്കിൽ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		അല്ലെങ്കിൽ
			fail++;
	}
	സ്വതന്ത്രം(cp);
	എങ്കിൽ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	എങ്കിൽ (type == 0)
		fail++;
	എങ്കിൽ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	എങ്കിൽ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	എങ്കിൽ (hostkey != ശൂന്യ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		എങ്കിൽ (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	തിരികെ (fail == 0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
monitor_valid_hostbasedblob(സ്ഥിരം u_char *data, u_int datalen,
    സ്ഥിരം അക്ഷരം *cuser, സ്ഥിരം അക്ഷരം *chost)
{
	ഘടന sshbuf *b;
	സ്ഥിരം u_char *p;
	അക്ഷരം *cp, *userstyle;
	size_t len;
	പൂർണ്ണസംഖ്യ r, fail = 0;
	u_char type;

	എങ്കിൽ ((b = sshbuf_from(data, datalen)) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	എങ്കിൽ ((session_id2 == ശൂന്യ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	എങ്കിൽ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != SSH2_സന്ദേശം_USERAUTH_REQUEST)
		fail++;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	എങ്കിൽ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	സ്വതന്ത്രം(userstyle);
	സ്വതന്ത്രം(cp);
	എങ്കിൽ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse method");
	എങ്കിൽ (strcmp(cp, "hostbased") != 0)
		fail++;
	സ്വതന്ത്രം(cp);
	എങ്കിൽ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse host");
	എങ്കിൽ (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	എങ്കിൽ (strcmp(cp, chost) != 0)
		fail++;
	സ്വതന്ത്രം(cp);

	/* verify client user */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &cp, ശൂന്യ)) != 0)
		fatal_fr(r, "parse ruser");
	എങ്കിൽ (strcmp(cp, cuser) != 0)
		fail++;
	സ്വതന്ത്രം(cp);

	എങ്കിൽ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	തിരികെ (fail == 0);
}

പൂർണ്ണസംഖ്യ
mm_answer_keyverify(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	ഘടന sshkey *താക്കോൽ;
	സ്ഥിരം u_char *signature, *data, *blob;
	അക്ഷരം *sigalg = ശൂന്യ, *fp = ശൂന്യ;
	size_t signaturelen, datalen, bloblen;
	പൂർണ്ണസംഖ്യ r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	പൂർണ്ണസംഖ്യ encoded_ret;
	ഘടന sshkey_sig_details *sig_details = ശൂന്യ;

	എങ്കിൽ ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (hostbased_cuser == ശൂന്യ || hostbased_chost == ശൂന്യ ||
	  !monitor_allowed_താക്കോൽ(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	എങ്കിൽ (*sigalg == '\0') {
		സ്വതന്ത്രം(sigalg);
		sigalg = ശൂന്യ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	എങ്കിൽ ((r = sshkey_from_blob(blob, bloblen, &താക്കോൽ)) != 0)
		fatal_fr(r, "parse key");

	തിരഞ്ഞെടുപ്പ് (താക്കോൽ_blobtype) {
	അവസ്ഥ MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		നിർത്തുക;
	അവസ്ഥ MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		valid_data = 0;
		നിർത്തുക;
	}
	എങ്കിൽ (!valid_data)
		fatal_f("bad %s signature data blob",
		    താക്കോൽ_blobtype == MM_USERKEY ? "userkey" :
		    (താക്കോൽ_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(താക്കോൽ, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(താക്കോൽ), sigalg == ശൂന്യ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	എങ്കിൽ (ret == 0 && താക്കോൽ_blobtype == MM_USERKEY && sig_details != ശൂന്യ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !താക്കോൽ_opts->no_require_user_presence;
		എങ്കിൽ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(താക്കോൽ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || താക്കോൽ_opts->require_verify;
		എങ്കിൽ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(താക്കോൽ), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_താക്കോൽ(authctxt, ret == 0, താക്കോൽ);

	എങ്കിൽ (താക്കോൽ_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, താക്കോൽ_opts);
	monitor_reset_താക്കോൽ_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	എങ്കിൽ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != ശൂന്യ)) != 0)
		fatal_fr(r, "assemble");
	എങ്കിൽ (sig_details != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	സ്വതന്ത്രം(sigalg);
	സ്വതന്ത്രം(fp);
	sshkey_free(താക്കോൽ);

	തിരികെ ret == 0;
}

സ്ഥിതം ശൂന്യം
mm_record_login(ഘടന ssh *ssh, Session *s, ഘടന passwd *pw)
{
	socklen_t fromlen;
	ഘടന sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, വലുപ്പം(from));
	fromlen = വലുപ്പം(from);
	എങ്കിൽ (ssh_packet_connection_is_on_socket(ssh)) {
		എങ്കിൽ (getpeername(ssh_packet_get_connection_in(ssh),
		    (ഘടന sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ഘടന sockaddr *)&from, fromlen);
}

സ്ഥിതം ശൂന്യം
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	എങ്കിൽ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

പൂർണ്ണസംഖ്യ
mm_answer_pty(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	ബാഹ്യ ഘടന monitor *pmonitor;
	Session *s;
	പൂർണ്ണസംഖ്യ r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	എങ്കിൽ (s == ശൂന്യ)
		പോകുക error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, വലുപ്പം(s->tty));
	എങ്കിൽ (res == 0)
		പോകുക error;
	pty_setowner(authctxt->pw, s->tty);

	എങ്കിൽ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	എങ്കിൽ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	എങ്കിൽ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	എങ്കിൽ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	എങ്കിൽ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	എങ്കിൽ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	തിരികെ (0);

 error:
	എങ്കിൽ (s != ശൂന്യ)
		mm_session_close(s);
	എങ്കിൽ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_pty_cleanup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	Session *s;
	അക്ഷരം *tty;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &tty, ശൂന്യ)) != 0)
		fatal_fr(r, "parse tty");
	എങ്കിൽ ((s = session_by_tty(tty)) != ശൂന്യ)
		mm_session_close(s);
	sshbuf_reset(m);
	സ്വതന്ത്രം(tty);
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_term(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *req)
{
	ബാഹ്യ ഘടന monitor *pmonitor;
	പൂർണ്ണസംഖ്യ res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	എങ്കിൽ (options.use_pam)
		sshpam_cleanup();
#endif

	ആകുമ്പോൾ (waitpid(pmonitor->m_pid, &status, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
പൂർണ്ണസംഖ്യ
mm_answer_audit_event(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ socket, ഘടന sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	തിരഞ്ഞെടുപ്പ് (event) {
	അവസ്ഥ SSH_AUTH_FAIL_PUBKEY:
	അവസ്ഥ SSH_AUTH_FAIL_HOSTBASED:
	അവസ്ഥ SSH_AUTH_FAIL_GSSAPI:
	അവസ്ഥ SSH_LOGIN_EXCEED_MAXTRIES:
	അവസ്ഥ SSH_LOGIN_വേര്_DENIED:
	അവസ്ഥ SSH_CONNECTION_CLOSE:
	അവസ്ഥ SSH_INVALID_USER:
		audit_event(ssh, event);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("Audit event type %d not permitted", event);
	}

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_audit_command(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ socket, ഘടന sshbuf *m)
{
	അക്ഷരം *cmd;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ ((r = sshbuf_get_cstring(m, &cmd, ശൂന്യ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	സ്വതന്ത്രം(cmd);
	തിരികെ (0);
}
#endif /* SSH_AUDIT_EVENTS */

ശൂന്യം
monitor_clear_keystate(ഘടന ssh *ssh, ഘടന monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = ശൂന്യ;
}

ശൂന്യം
monitor_apply_keystate(ഘടന ssh *ssh, ഘടന monitor *pmonitor)
{
	ഘടന kex *kex;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("packet_set_state");
	എങ്കിൽ ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = ശൂന്യ;
	എങ്കിൽ ((kex = ssh->kex) == ശൂന്യ)
		fatal_f("internal error: ssh->kex == NULL");
	എങ്കിൽ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	എങ്കിൽ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_താക്കോൽ=&get_hostkey_public_by_type;
	kex->load_host_private_താക്കോൽ=&get_hostkey_private_by_type;
	kex->host_താക്കോൽ_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

ശൂന്യം
mm_get_keystate(ഘടന ssh *ssh, ഘടന monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	എങ്കിൽ ((child_state = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

സ്ഥിതം ശൂന്യം
monitor_openfds(ഘടന monitor *mon, പൂർണ്ണസംഖ്യ do_logfds)
{
	പൂർണ്ണസംഖ്യ pair[2];
#ifdef SO_ZEROIZE
	പൂർണ്ണസംഖ്യ on = 1;
#endif

	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	എങ്കിൽ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, വലുപ്പം(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	എങ്കിൽ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, വലുപ്പം(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	എങ്കിൽ (do_logfds) {
		എങ്കിൽ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} അല്ലെങ്കിൽ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ഘടന monitor *
monitor_init(ശൂന്യം)
{
	ഘടന monitor *mon;

	mon = xcalloc(1, വലുപ്പം(*mon));
	monitor_openfds(mon, 1);

	തിരികെ mon;
}

ശൂന്യം
monitor_reinit(ഘടന monitor *mon)
{
	monitor_openfds(mon, 0);
}

പൂർണ്ണസംഖ്യ
monitor_auth_attempted(ശൂന്യം)
{
	തിരികെ auth_attempted;
}

പൂർണ്ണസംഖ്യ
monitor_invalid_user(ശൂന്യം)
{
	തിരികെ invalid_user;
}

#ifdef GSSAPI
പൂർണ്ണസംഖ്യ
mm_answer_gss_setup_ctx(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	എങ്കിൽ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	സ്വതന്ത്രം(goid.elements);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_gss_accept_ctx(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	എങ്കിൽ ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	സ്വതന്ത്രം(in.മൂല്യം);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.മൂല്യം, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	എങ്കിൽ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_gss_checkmic(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	എങ്കിൽ ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	സ്വതന്ത്രം(gssbuf.മൂല്യം);
	സ്വതന്ത്രം(mic.മൂല്യം);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	എങ്കിൽ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
mm_answer_gss_userok(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r, authenticated;
	സ്ഥിരം അക്ഷരം *displayname;

	എങ്കിൽ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	എങ്കിൽ ((displayname = ssh_gssapi_displayname()) != ശൂന്യ)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	തിരികെ (authenticated);
}
#endif /* GSSAPI */

