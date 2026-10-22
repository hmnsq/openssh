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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>
#شامل <sys/socket.h>
#شامل <sys/tree.h>
#شامل <sys/queue.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <paths.h>
#شامل <poll.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#ifdef WITH_OPENSSL
#شامل <openssl/dh.h>
#endif

#شامل "openbsd-compat/openssl-compat.h"

#شامل "atomicio.h"
#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "dh.h"
#شامل "auth-pam.h"
#شامل "packet.h"
#شامل "auth-options.h"
#شامل "sshpty.h"
#شامل "channels.h"
#شامل "session.h"
#شامل "sshlogin.h"
#شامل "canohost.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "monitor.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "monitor_fdpass.h"
#شامل "compat.h"
#شامل "ssh2.h"
#شامل "authfd.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "srclimit.h"

#ifdef GSSAPI
ایستا Gssctxt *gsscontext = پوچ;
#endif

/* Imports */
بیرونی ServerOptions options;
بیرونی u_int utmp_len;
بیرونی ساختار sshbuf *cfg;
بیرونی ساختار sshbuf *loginmsg;
بیرونی ساختار include_list includes;
بیرونی ساختار sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ایستا ساختار sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

صحیح mm_answer_moduli(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_setcompat(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_sign(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pwnamallow(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_auth2_read_banner(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_authserv(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_authpassword(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_bsdauthquery(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_bsdauthrespond(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_keyallowed(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_keyverify(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pty(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pty_cleanup(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_term(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_state(ساختار ssh *, صحیح, ساختار sshbuf *);

#ifdef USE_PAM
صحیح mm_answer_pam_start(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pam_account(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pam_init_ctx(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pam_query(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pam_respond(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_pam_free_ctx(ساختار ssh *, صحیح, ساختار sshbuf *);
#endif

#ifdef GSSAPI
صحیح mm_answer_gss_setup_ctx(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_gss_accept_ctx(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_gss_userok(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_gss_checkmic(ساختار ssh *, صحیح, ساختار sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
صحیح mm_answer_audit_event(ساختار ssh *, صحیح, ساختار sshbuf *);
صحیح mm_answer_audit_command(ساختار ssh *, صحیح, ساختار sshbuf *);
#endif

ایستا Authctxt *authctxt;

/* local state for key verify */
ایستا u_char *کلید_blob = پوچ;
ایستا size_t کلید_bloblen = 0;
ایستا u_int کلید_blobtype = MM_NOKEY;
ایستا ساختار sshauthopt *کلید_opts = پوچ;
ایستا نویسه *hostbased_cuser = پوچ;
ایستا نویسه *hostbased_chost = پوچ;
ایستا نویسه *auth_method = "unknown";
ایستا نویسه *auth_submethod = پوچ;
ایستا u_int session_id2_len = 0;
ایستا u_char *session_id2 = پوچ;
ایستا pid_t monitor_child_pid;
ایستا صحیح auth_attempted = 0;
ایستا صحیح invalid_user = 0;
ایستا صحیح compat_set = 0;

ساختار mon_table {
	شمارش monitor_reqtype type;
	صحیح flags;
	صحیح (*f)(ساختار ssh *, صحیح, ساختار sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

ایستا صحیح monitor_read(ساختار ssh *, ساختار monitor *, ساختار mon_table *,
    ساختار mon_table **);
ایستا صحیح monitor_read_log(ساختار monitor *);

ساختار mon_table mon_dispatch_proto20[] = {
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
    {0, 0, پوچ}
};

ساختار mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, پوچ}
};

ساختار mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ایستا تهی
monitor_permit(ساختار mon_table *ent, شمارش monitor_reqtype type, صحیح permit)
{
	وقتی (ent->f != پوچ) {
		اگر (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			بازگشت;
		}
		ent++;
	}
}

ایستا تهی
monitor_permit_authentications(صحیح permit)
{
	ساختار mon_table *ent = mon_dispatch;

	وقتی (ent->f != پوچ) {
		اگر (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

تهی
monitor_child_preauth(ساختار ssh *ssh, ساختار monitor *pmonitor)
{
	ساختار mon_table *ent;
	صحیح status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	اگر (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	اگر (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, اندازه(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	وقتی (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = پوچ;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		اگر ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		اگر (options.رقم_auth_methods != 0) {
			اگر (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		اگر (authenticated) {
			اگر (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			اگر (authctxt->pw->pw_uid == 0 &&
			    !auth_ریشه_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			اگر (options.use_pam && authenticated) {
				ساختار sshbuf *m;

				اگر ((m = sshbuf_new()) == پوچ)
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
		اگر (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			اگر (!partial && !authenticated)
				authctxt->failures++;
			اگر (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		اگر (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	اگر (!authctxt->valid)
		fatal_f("authenticated invalid user");
	اگر (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = پوچ;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	وقتی (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	وقتی (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		اگر (errno == EINTR)
			ادامه;
		fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (WIFEXITED(status)) {
		اگر (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} وگرنه اگر (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	اگر (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	اگر (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ایستا تهی
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

ایستا تهی
monitor_child_handler(صحیح sig)
{
	kill(monitor_child_pid, sig);
}

تهی
monitor_child_postauth(ساختار ssh *ssh, ساختار monitor *pmonitor)
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

	اگر (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	برای (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, پوچ);
}

ایستا صحیح
monitor_read_log(ساختار monitor *pmonitor)
{
	ساختار sshbuf *logmsg;
	u_int len, level, forced;
	نویسه *پیام;
	u_char *p;
	صحیح r;

	اگر ((logmsg = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");

	/* Read length */
	اگر ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	اگر (atomicio(اقرأ, pmonitor->m_log_recvfd, p, 4) != 4) {
		اگر (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			بازگشت -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	اگر ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	اگر (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	اگر ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	اگر (atomicio(اقرأ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	اگر ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &پیام, پوچ)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	اگر (log_level_name(level) == پوچ)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", پیام,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	آزاد(پیام);

	بازگشت 0;
}

ایستا صحیح
monitor_read(ساختار ssh *ssh, ساختار monitor *pmonitor, ساختار mon_table *ent,
    ساختار mon_table **pent)
{
	ساختار sshbuf *m;
	صحیح r, ret;
	u_char type;
	ساختار pollfd pfd[2];

	برای (;;) {
		memset(&pfd, 0, اندازه(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		اگر (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				ادامه;
			fatal_f("poll: %s", strerror(errno));
		}
		اگر (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			ادامه;
		}
		اگر (pfd[0].revents)
			بشکن;  /* Continues below */
	}

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	اگر ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	وقتی (ent->f != پوچ) {
		اگر (ent->type == type)
			بشکن;
		ent++;
	}

	اگر (ent->f != پوچ) {
		اگر (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		اگر (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		اگر (pent != پوچ)
			*pent = ent;

		بازگشت ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	بازگشت (-1);
}

/* allowed key state */
ایستا صحیح
monitor_allowed_کلید(ثابت u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	اگر (کلید_blob == پوچ || کلید_bloblen != bloblen ||
	    timingsafe_bcmp(کلید_blob, blob, کلید_bloblen))
		بازگشت (0);
	بازگشت (1);
}

ایستا تهی
monitor_reset_کلید_state(تهی)
{
	/* reset state */
	آزاد(کلید_blob);
	آزاد(hostbased_cuser);
	آزاد(hostbased_chost);
	sshauthopt_free(کلید_opts);
	کلید_blob = پوچ;
	کلید_bloblen = 0;
	کلید_blobtype = MM_NOKEY;
	کلید_opts = پوچ;
	hostbased_cuser = پوچ;
	hostbased_chost = پوچ;
}

صحیح
mm_answer_state(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *unused)
{
	ساختار sshbuf *m = پوچ, *config = پوچ, *hostkeys = پوچ;
	ساختار sshbuf *opts = پوچ, *confdata = پوچ;
	صحیح postauth;
	صحیح r;

	debug_f("config len %zu", sshbuf_len(cfg));

	اگر ((m = sshbuf_new()) == پوچ ||
	    (config = sshbuf_new()) == پوچ ||
	    (opts = sshbuf_new()) == پوچ ||
	    (confdata = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	اگر ((r = serialise_server_options(&options, &config)) != 0)
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
	اگر ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	اگر (postauth) {
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

	بازگشت (0);
}

#ifdef WITH_OPENSSL
صحیح
mm_answer_moduli(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	DH *dh;
	ثابت BIGNUM *dh_p, *dh_g;
	صحیح r;
	u_int min, want, max;

	اگر ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	اگر (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	اگر (dh == پوچ) {
		اگر ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} وگرنه {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, پوچ, &dh_g);
		اگر ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	بازگشت (0);
}
#endif

صحیح
mm_answer_setcompat(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	صحیح r;

	debug3_f("entering");

	اگر ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	بازگشت (0);
}

صحیح
mm_answer_sign(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	بیرونی صحیح auth_sock;			/* XXX move to state struct? */
	ساختار sshkey *pubkey, *کلید;
	ساختار sshbuf *sigbuf = پوچ;
	u_char *p = پوچ, *signature = پوچ;
	نویسه *alg = پوچ;
	size_t datlen, siglen;
	صحیح r, is_proof = 0, keyid;
	u_int compat;
	ثابت نویسه proof_req[] = "hostkeys-prove-00@openssh.com";
	ایستا صحیح nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	اگر (!compat_set)
		fatal_f("state error: setcompat never called");

	اگر ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	اگر ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	اگر (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		اگر (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		اگر ((کلید = get_hostkey_public_by_index(keyid, ssh)) == پوچ)
			fatal_f("no hostkey for index %d", keyid);
		اگر (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, اندازه(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		اگر (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(کلید), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		اگر ((sigbuf = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new");
		اگر ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(کلید, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		اگر (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	اگر (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	اگر ((کلید = get_hostkey_by_index(keyid)) != پوچ) {
		اگر ((r = sshkey_sign(کلید, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, پوچ, compat)) != 0)
			fatal_fr(r, "sign");
	} وگرنه اگر ((کلید = get_hostkey_public_by_index(keyid, ssh)) != پوچ &&
	    auth_sock > 0) {
		اگر ((r = ssh_agent_sign(auth_sock, کلید, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} وگرنه
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	آزاد(alg);
	آزاد(p);
	آزاد(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	بازگشت (0);
}

#define PUTPW(b, id) \
	انجامبده { \
		اگر ((r = sshbuf_put_string(b, \
		    &pwent->id, اندازه(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} وقتی (0)

تهی
mm_encode_server_options(ساختار sshbuf *m)
{
	صحیح r;
	ساختار sshbuf *config;

	اگر ((config = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	اگر ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
صحیح
mm_answer_pwnamallow(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	ساختار passwd *pwent;
	صحیح r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	اگر (!compat_set)
		fatal_f("state error: setcompat never called");

	اگر (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	اگر ((r = sshbuf_get_cstring(m, &authctxt->user, پوچ)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	اگر (pwent == پوچ) {
		invalid_user = 1;
		اگر ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		برو out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	اگر ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	اگر ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	اگر (options.refuse_connection) {
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
	اگر (auth2_setup_methods_lists(authctxt) != 0) {
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
	اگر (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	بازگشت (0);
}

صحیح mm_answer_auth2_read_banner(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	نویسه *banner;
	صحیح r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	اگر ((r = sshbuf_put_cstring(m, banner != پوچ ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	آزاد(banner);

	بازگشت (0);
}

صحیح
mm_answer_authserv(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	صحیح r;

	monitor_permit_authentications(1);

	اگر ((r = sshbuf_get_cstring(m, &authctxt->service, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, پوچ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	اگر (strlen(authctxt->style) == 0) {
		آزاد(authctxt->style);
		authctxt->style = پوچ;
	}

	بازگشت (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ایستا صحیح
کلید_base_type_match(ثابت نویسه *method, ثابت ساختار sshkey *کلید,
    ثابت نویسه *list)
{
	نویسه *s, *l, *ol = xstrdup(list);
	صحیح found = 0;

	l = ol;
	برای ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		اگر (sshkey_type_from_name(s) == کلید->type) {
			found = 1;
			بشکن;
		}
	}
	اگر (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(کلید), list);
	}

	آزاد(ol);
	بازگشت found;
}

صحیح
mm_answer_authpassword(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	ایستا صحیح call_شمار;
	نویسه *passwd;
	صحیح r, authenticated;
	size_t plen;

	اگر (!options.password_authentication)
		fatal_f("password authentication not enabled");
	اگر ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	اگر ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_شمار++;
	اگر (plen == 0 && call_شمار == 1)
		auth_method = "none";
	وگرنه
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	بازگشت (authenticated);
}

#ifdef BSD_AUTH
صحیح
mm_answer_bsdauthquery(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	نویسه *name, *infotxt;
	u_int numprompts, *echo_on, success;
	نویسه **prompts;
	صحیح r;

	اگر (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	اگر (success) {
		اگر ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	اگر (success) {
		آزاد(name);
		آزاد(infotxt);
		آزاد(prompts);
		آزاد(echo_on);
	}

	بازگشت (0);
}

صحیح
mm_answer_bsdauthrespond(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	نویسه *response;
	صحیح r, authok;

	اگر (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	اگر (authctxt->as == پوچ)
		fatal_f("no bsd auth session");

	اگر ((r = sshbuf_get_cstring(m, &response, پوچ)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = پوچ;
	debug3_f("<%s> = <%d>", response, authok);
	آزاد(response);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	بازگشت (authok != 0);
}
#endif

#ifdef USE_PAM
صحیح
mm_answer_pam_start(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	اگر (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	اگر (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	بازگشت (0);
}

صحیح
mm_answer_pam_account(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	u_int ret;
	صحیح r;

	اگر (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	اگر ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	بازگشت (ret);
}

ایستا تهی *sshpam_ctxt, *sshpam_authok;
بیرونی KbdintDevice sshpam_device;

صحیح
mm_answer_pam_init_ctx(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	u_int ok = 0;
	صحیح r;

	debug3_f("entering");
	اگر (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	اگر (sshpam_ctxt != پوچ)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = پوچ;
	sshbuf_reset(m);
	اگر (sshpam_ctxt != پوچ) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	اگر ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	بازگشت (0);
}

صحیح
mm_answer_pam_query(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	نویسه *name = پوچ, *info = پوچ, **prompts = پوچ;
	u_int i, رقم = 0, *echo_on = 0;
	صحیح r, ret;

	debug3_f("entering");
	sshpam_authok = پوچ;
	اگر (sshpam_ctxt == پوچ)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &رقم, &prompts, &echo_on);
	اگر (ret == 0 && رقم == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	اگر (رقم > 1 || name == پوچ || info == پوچ)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, رقم)) != 0)
		fatal_fr(r, "buffer error");
	آزاد(name);
	آزاد(info);
	برای (i = 0; i < رقم; ++i) {
		اگر ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		آزاد(prompts[i]);
	}
	آزاد(prompts);
	آزاد(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	بازگشت (0);
}

صحیح
mm_answer_pam_respond(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	نویسه **resp;
	u_int i, رقم;
	صحیح r, ret;

	debug3_f("entering");
	اگر (sshpam_ctxt == پوچ)
		fatal_f("no context");
	sshpam_authok = پوچ;
	اگر ((r = sshbuf_get_u32(m, &رقم)) != 0)
		fatal_fr(r, "buffer error");
	اگر (رقم > PAM_MAX_رقم_پیام) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    رقم, (unsigned)PAM_MAX_رقم_پیام);
	}
	اگر (رقم > 0) {
		resp = xcalloc(رقم, اندازه(نویسه *));
		برای (i = 0; i < رقم; ++i) {
			اگر ((r = sshbuf_get_cstring(m, &(resp[i]), پوچ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, رقم, resp);
		برای (i = 0; i < رقم; ++i)
			آزاد(resp[i]);
		آزاد(resp);
	} وگرنه {
		ret = (sshpam_device.respond)(sshpam_ctxt, رقم, پوچ);
	}
	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	اگر (ret == 0)
		sshpam_authok = sshpam_ctxt;
	بازگشت (0);
}

صحیح
mm_answer_pam_free_ctx(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	صحیح r = sshpam_authok != پوچ && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	اگر (sshpam_ctxt == پوچ)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = پوچ;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	بازگشت r;
}
#endif

صحیح
mm_answer_keyallowed(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	ساختار sshkey *کلید = پوچ;
	نویسه *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	صحیح r, allowed = 0;
	ساختار sshauthopt *opts = پوچ;

	debug3_f("entering");
	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, پوچ)) != 0 ||
	    (r = sshkey_froms(m, &کلید)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	اگر (کلید != پوچ && authctxt->valid) {
		انتخاب (type) {
		حالت MM_USERKEY:
			auth_method = "publickey";
			اگر (!options.pubkey_authentication)
				بشکن;
			اگر (auth2_کلید_already_used(authctxt, کلید))
				بشکن;
			اگر (!کلید_base_type_match(auth_method, کلید,
			    options.pubkey_accepted_algos))
				بشکن;
			allowed = user_کلید_allowed(ssh, authctxt->pw, کلید,
			    pubkey_auth_attempt, &opts);
			بشکن;
		حالت MM_HOSTKEY:
			auth_method = "hostbased";
			اگر (!options.hostbased_authentication)
				بشکن;
			اگر (auth2_کلید_already_used(authctxt, کلید))
				بشکن;
			اگر (!کلید_base_type_match(auth_method, کلید,
			    options.hostbased_accepted_algos))
				بشکن;
			allowed = hostbased_کلید_allowed(ssh, authctxt->pw,
			    cuser, chost, کلید);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			بشکن;
		پیشفرض:
			fatal_f("unknown key type %u", type);
			بشکن;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (کلید == پوچ || !authctxt->valid) ? "invalid" : sshkey_type(کلید),
	    allowed ? "allowed" : "not allowed");

	auth2_record_کلید(authctxt, 0, کلید);

	/* clear temporarily storage (used by verify) */
	monitor_reset_کلید_state();

	اگر (allowed) {
		/* Save temporarily for comparison in verify */
		اگر ((r = sshkey_to_blob(کلید, &کلید_blob, &کلید_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		کلید_blobtype = type;
		کلید_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} وگرنه {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, پوچ);
		آزاد(cuser);
		آزاد(chost);
	}
	sshkey_free(کلید);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	اگر (opts != پوچ && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	اگر (!allowed)
		sshauthopt_free(opts);

	بازگشت (0);
}

ایستا صحیح
monitor_valid_userblob(ساختار ssh *ssh, ثابت u_char *data, u_int datalen)
{
	ساختار sshbuf *b;
	ساختار sshkey *hostkey = پوچ;
	ثابت u_char *p;
	نویسه *userstyle, *cp;
	size_t len;
	u_char type;
	صحیح hostbound = 0, r, fail = 0;

	اگر ((b = sshbuf_from(data, datalen)) == پوچ)
		fatal_f("sshbuf_from");

	اگر ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	اگر ((session_id2 == پوچ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیام_USERAUTH_REQUEST)
		fail++;
	اگر ((r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	اگر (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	آزاد(userstyle);
	آزاد(cp);
	اگر ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp("publickey", cp) != 0) {
		اگر (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		وگرنه
			fail++;
	}
	آزاد(cp);
	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	اگر (type == 0)
		fail++;
	اگر ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	اگر (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	اگر (hostkey != پوچ) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		اگر (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	بازگشت (fail == 0);
}

ایستا صحیح
monitor_valid_hostbasedblob(ثابت u_char *data, u_int datalen,
    ثابت نویسه *cuser, ثابت نویسه *chost)
{
	ساختار sshbuf *b;
	ثابت u_char *p;
	نویسه *cp, *userstyle;
	size_t len;
	صحیح r, fail = 0;
	u_char type;

	اگر ((b = sshbuf_from(data, datalen)) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	اگر ((session_id2 == پوچ) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیام_USERAUTH_REQUEST)
		fail++;
	اگر ((r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	اگر (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	آزاد(userstyle);
	آزاد(cp);
	اگر ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp(cp, "hostbased") != 0)
		fail++;
	آزاد(cp);
	اگر ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	اگر ((r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse host");
	اگر (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	اگر (strcmp(cp, chost) != 0)
		fail++;
	آزاد(cp);

	/* verify client user */
	اگر ((r = sshbuf_get_cstring(b, &cp, پوچ)) != 0)
		fatal_fr(r, "parse ruser");
	اگر (strcmp(cp, cuser) != 0)
		fail++;
	آزاد(cp);

	اگر (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	بازگشت (fail == 0);
}

صحیح
mm_answer_keyverify(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	ساختار sshkey *کلید;
	ثابت u_char *signature, *data, *blob;
	نویسه *sigalg = پوچ, *fp = پوچ;
	size_t signaturelen, datalen, bloblen;
	صحیح r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	صحیح encoded_ret;
	ساختار sshkey_sig_details *sig_details = پوچ;

	اگر ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, پوچ)) != 0)
		fatal_fr(r, "parse");

	اگر (hostbased_cuser == پوچ || hostbased_chost == پوچ ||
	  !monitor_allowed_کلید(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	اگر (*sigalg == '\0') {
		آزاد(sigalg);
		sigalg = پوچ;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	اگر ((r = sshkey_from_blob(blob, bloblen, &کلید)) != 0)
		fatal_fr(r, "parse key");

	انتخاب (کلید_blobtype) {
	حالت MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		بشکن;
	حالت MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		بشکن;
	پیشفرض:
		valid_data = 0;
		بشکن;
	}
	اگر (!valid_data)
		fatal_f("bad %s signature data blob",
		    کلید_blobtype == MM_USERKEY ? "userkey" :
		    (کلید_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(کلید, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(کلید), sigalg == پوچ ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	اگر (ret == 0 && کلید_blobtype == MM_USERKEY && sig_details != پوچ) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !کلید_opts->no_require_user_presence;
		اگر (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(کلید), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || کلید_opts->require_verify;
		اگر (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(کلید), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_کلید(authctxt, ret == 0, کلید);

	اگر (کلید_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, کلید_opts);
	monitor_reset_کلید_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	اگر ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != پوچ)) != 0)
		fatal_fr(r, "assemble");
	اگر (sig_details != پوچ) {
		اگر ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	آزاد(sigalg);
	آزاد(fp);
	sshkey_free(کلید);

	بازگشت ret == 0;
}

ایستا تهی
mm_record_login(ساختار ssh *ssh, Session *s, ساختار passwd *pw)
{
	socklen_t fromlen;
	ساختار sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, اندازه(from));
	fromlen = اندازه(from);
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		اگر (getpeername(ssh_packet_get_connection_in(ssh),
		    (ساختار sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ساختار sockaddr *)&from, fromlen);
}

ایستا تهی
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	اگر (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

صحیح
mm_answer_pty(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	بیرونی ساختار monitor *pmonitor;
	Session *s;
	صحیح r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	اگر (s == پوچ)
		برو error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, اندازه(s->tty));
	اگر (res == 0)
		برو error;
	pty_setowner(authctxt->pw, s->tty);

	اگر ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	اگر (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	اگر ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	اگر (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	اگر ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	اگر (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	بازگشت (0);

 error:
	اگر (s != پوچ)
		mm_session_close(s);
	اگر ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	بازگشت (0);
}

صحیح
mm_answer_pty_cleanup(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	Session *s;
	نویسه *tty;
	صحیح r;

	debug3_f("entering");

	اگر ((r = sshbuf_get_cstring(m, &tty, پوچ)) != 0)
		fatal_fr(r, "parse tty");
	اگر ((s = session_by_tty(tty)) != پوچ)
		mm_session_close(s);
	sshbuf_reset(m);
	آزاد(tty);
	بازگشت (0);
}

صحیح
mm_answer_term(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *req)
{
	بیرونی ساختار monitor *pmonitor;
	صحیح res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	اگر (options.use_pam)
		sshpam_cleanup();
#endif

	وقتی (waitpid(pmonitor->m_pid, &status, 0) == -1)
		اگر (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
صحیح
mm_answer_audit_event(ساختار ssh *ssh, صحیح socket, ساختار sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	صحیح r;

	debug3_f("entering");

	اگر ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	انتخاب (event) {
	حالت SSH_AUTH_FAIL_PUBKEY:
	حالت SSH_AUTH_FAIL_HOSTBASED:
	حالت SSH_AUTH_FAIL_GSSAPI:
	حالت SSH_LOGIN_EXCEED_MAXTRIES:
	حالت SSH_LOGIN_ریشه_DENIED:
	حالت SSH_CONNECTION_CLOSE:
	حالت SSH_INVALID_USER:
		audit_event(ssh, event);
		بشکن;
	پیشفرض:
		fatal("Audit event type %d not permitted", event);
	}

	بازگشت (0);
}

صحیح
mm_answer_audit_command(ساختار ssh *ssh, صحیح socket, ساختار sshbuf *m)
{
	نویسه *cmd;
	صحیح r;

	debug3_f("entering");
	اگر ((r = sshbuf_get_cstring(m, &cmd, پوچ)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	آزاد(cmd);
	بازگشت (0);
}
#endif /* SSH_AUDIT_EVENTS */

تهی
monitor_clear_keystate(ساختار ssh *ssh, ساختار monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = پوچ;
}

تهی
monitor_apply_keystate(ساختار ssh *ssh, ساختار monitor *pmonitor)
{
	ساختار kex *kex;
	صحیح r;

	debug3_f("packet_set_state");
	اگر ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = پوچ;
	اگر ((kex = ssh->kex) == پوچ)
		fatal_f("internal error: ssh->kex == NULL");
	اگر (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	اگر (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_کلید=&get_hostkey_public_by_type;
	kex->load_host_private_کلید=&get_hostkey_private_by_type;
	kex->host_کلید_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

تهی
mm_get_keystate(ساختار ssh *ssh, ساختار monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	اگر ((child_state = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

ایستا تهی
monitor_openfds(ساختار monitor *mon, صحیح do_logfds)
{
	صحیح pair[2];
#ifdef SO_ZEROIZE
	صحیح on = 1;
#endif

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	اگر (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, اندازه(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	اگر (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, اندازه(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	اگر (do_logfds) {
		اگر (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} وگرنه
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ساختار monitor *
monitor_init(تهی)
{
	ساختار monitor *mon;

	mon = xcalloc(1, اندازه(*mon));
	monitor_openfds(mon, 1);

	بازگشت mon;
}

تهی
monitor_reinit(ساختار monitor *mon)
{
	monitor_openfds(mon, 0);
}

صحیح
monitor_auth_attempted(تهی)
{
	بازگشت auth_attempted;
}

صحیح
monitor_invalid_user(تهی)
{
	بازگشت invalid_user;
}

#ifdef GSSAPI
صحیح
mm_answer_gss_setup_ctx(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	اگر ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	آزاد(goid.elements);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	بازگشت (0);
}

صحیح
mm_answer_gss_accept_ctx(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	اگر ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	آزاد(in.مقدار);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.مقدار, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	اگر (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	بازگشت (0);
}

صحیح
mm_answer_gss_checkmic(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	اگر ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	آزاد(gssbuf.مقدار);
	آزاد(mic.مقدار);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	اگر (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	بازگشت (0);
}

صحیح
mm_answer_gss_userok(ساختار ssh *ssh, صحیح sock, ساختار sshbuf *m)
{
	صحیح r, authenticated;
	ثابت نویسه *displayname;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	اگر ((displayname = ssh_gssapi_displayname()) != پوچ)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	بازگشت (authenticated);
}
#endif /* GSSAPI */

