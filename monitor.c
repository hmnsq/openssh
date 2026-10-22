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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/dh.h>
#اگر_ختم

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
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "monitor_fdpass.h"
#شامل "compat.h"
#شامل "ssh2.h"
#شامل "authfd.h"
#شامل "match.h"
#شامل "ssherr.h"
#شامل "sk-api.h"
#شامل "srclimit.h"

#اگر_تعریف_شدہ GSSAPI
ساکن Gssctxt *gsscontext = تہی;
#اگر_ختم

/* Imports */
خارجی ServerOptions options;
خارجی u_int utmp_len;
خارجی ساخت sshbuf *cfg;
خارجی ساخت sshbuf *loginmsg;
خارجی ساخت include_list includes;
خارجی ساخت sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ساکن ساخت sshbuf *بچہ_state;

/* Functions on the monitor that answer unprivileged requests */

صحیح mm_answer_moduli(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_setcompat(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_sign(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pwnamallow(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_auth2_read_banner(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_authserv(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_authpassword(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_bsdauthquery(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_bsdauthrespond(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_keyallowed(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_keyverify(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pty(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pty_cleanup(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_رکن(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_state(ساخت ssh *, صحیح, ساخت sshbuf *);

#اگر_تعریف_شدہ USE_PAM
صحیح mm_answer_pam_آغاز(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pam_account(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pam_init_ctx(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pam_query(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pam_respond(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_pam_free_ctx(ساخت ssh *, صحیح, ساخت sshbuf *);
#اگر_ختم

#اگر_تعریف_شدہ GSSAPI
صحیح mm_answer_gss_تیاری_ctx(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_gss_accept_ctx(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_gss_userok(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_gss_checkmic(ساخت ssh *, صحیح, ساخت sshbuf *);
#اگر_ختم

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
صحیح mm_answer_audit_event(ساخت ssh *, صحیح, ساخت sshbuf *);
صحیح mm_answer_audit_command(ساخت ssh *, صحیح, ساخت sshbuf *);
#اگر_ختم

ساکن Authctxt *authctxt;

/* local state for key verify */
ساکن u_char *کلید_blob = تہی;
ساکن سائز_t کلید_bloblen = 0;
ساکن u_int کلید_blobtype = MM_NOKEY;
ساکن ساخت sshauthopt *کلید_opts = تہی;
ساکن حرف *hostbased_cuser = تہی;
ساکن حرف *hostbased_chost = تہی;
ساکن حرف *auth_طریقہ = "unknown";
ساکن حرف *auth_submethod = تہی;
ساکن u_int session_id2_len = 0;
ساکن u_char *session_id2 = تہی;
ساکن pid_t monitor_بچہ_pid;
ساکن صحیح auth_attempted = 0;
ساکن صحیح invalid_user = 0;
ساکن صحیح compat_سیٹ = 0;

ساخت mon_جدول {
	شمار monitor_reqtype type;
	صحیح flags;
	صحیح (*f)(ساخت ssh *, صحیح, ساخت sshbuf *);
};

#تعریف_کرو MON_ISAUTH	0x0004	/* Required for Authentication */
#تعریف_کرو MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#تعریف_کرو MON_ONCE	0x0010	/* Disable after calling */
#تعریف_کرو MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#تعریف_کرو MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#تعریف_کرو MON_PERMIT	0x1000	/* Request is permitted */

ساکن صحیح monitor_read(ساخت ssh *, ساخت monitor *, ساخت mon_جدول *,
    ساخت mon_جدول **);
ساکن صحیح monitor_read_log(ساخت monitor *);

ساخت mon_جدول mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#اگر_تعریف_شدہ WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#اگر_ختم
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#اگر_تعریف_شدہ USE_PAM
    {MONITOR_REQ_PAM_آغاز, MON_ONCE, mm_answer_pam_آغاز},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#اگر_ختم
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#اگر_ختم
#اگر_تعریف_شدہ BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#اگر_ختم
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#اگر_تعریف_شدہ GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_تیاری_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#اگر_ختم
    {0, 0, تہی}
};

ساخت mon_جدول mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#اگر_تعریف_شدہ WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#اگر_ختم
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_رکن, 0, mm_answer_رکن},
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#اگر_ختم
    {0, 0, تہی}
};

ساخت mon_جدول *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ساکن خالی
monitor_permit(ساخت mon_جدول *ent, شمار monitor_reqtype type, صحیح permit)
{
	جب (ent->f != تہی) {
		اگر (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			واپس;
		}
		ent++;
	}
}

ساکن خالی
monitor_permit_authentications(صحیح permit)
{
	ساخت mon_جدول *ent = mon_dispatch;

	جب (ent->f != تہی) {
		اگر (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

خالی
monitor_بچہ_preauth(ساخت ssh *ssh, ساخت monitor *pmonitor)
{
	ساخت mon_جدول *ent;
	صحیح حالت_2, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	اگر (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	اگر (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, حجم(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	جب (!authenticated) {
		partial = 0;
		auth_طریقہ = "unknown";
		auth_submethod = تہی;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		اگر ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		اگر (options.عدد_auth_methods != 0) {
			اگر (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_طریقہ, auth_submethod)) {
				debug3_f("method %s: partial", auth_طریقہ);
				authenticated = 0;
				partial = 1;
			}
		}

		اگر (authenticated) {
			اگر (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			اگر (authctxt->pw->pw_uid == 0 &&
			    !auth_جڑ_allowed(ssh, auth_طریقہ))
				authenticated = 0;
#اگر_تعریف_شدہ USE_PAM
			/* PAM needs to perform account checks after auth */
			اگر (options.use_pam && authenticated) {
				ساخت sshbuf *m;

				اگر ((m = sshbuf_new()) == تہی)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#اگر_ختم
		}
		اگر (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_طریقہ, auth_submethod);
			اگر (!partial && !authenticated)
				authctxt->failures++;
			اگر (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_طریقہ, auth_submethod);
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
	اگر (strcmp(auth_طریقہ, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = تہی;
	ssh_packet_سیٹ_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	جب (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	جب (waitpid(pmonitor->m_pid, &حالت_2, 0) == -1) {
		اگر (errno == EINTR)
			جاری;
		fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (WIFEXITED(حالت_2)) {
		اگر (WEXITSTATUS(حالت_2) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (طویل)pmonitor->m_pid, WEXITSTATUS(حالت_2));
	} ورنہ اگر (WIFSIGNALED(حالت_2)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (طویل)pmonitor->m_pid, WTERMSIG(حالت_2));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (طویل)pmonitor->m_pid);

	اگر (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	اگر (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ساکن خالی
monitor_سیٹ_بچہ_handler(pid_t pid)
{
	monitor_بچہ_pid = pid;
}

ساکن خالی
monitor_بچہ_handler(صحیح sig)
{
	kill(monitor_بچہ_pid, sig);
}

خالی
monitor_بچہ_postauth(ساخت ssh *ssh, ساخت monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_سیٹ_بچہ_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_بچہ_handler);
	ssh_signal(SIGTERM, &monitor_بچہ_handler);
	ssh_signal(SIGINT, &monitor_بچہ_handler);
#اگر_تعریف_شدہ SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#اگر_ختم

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_رکن, 1);

	اگر (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	برائے (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, تہی);
}

ساکن صحیح
monitor_read_log(ساخت monitor *pmonitor)
{
	ساخت sshbuf *logmsg;
	u_int len, level, forced;
	حرف *پیغام;
	u_char *p;
	صحیح r;

	اگر ((logmsg = sshbuf_new()) == تہی)
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
			واپس -1;
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
	    (r = sshbuf_get_cstring(logmsg, &پیغام, تہی)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	اگر (log_level_name(level) == تہی)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", پیغام,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	آزاد(پیغام);

	واپس 0;
}

ساکن صحیح
monitor_read(ساخت ssh *ssh, ساخت monitor *pmonitor, ساخت mon_جدول *ent,
    ساخت mon_جدول **pent)
{
	ساخت sshbuf *m;
	صحیح r, ret;
	u_char type;
	ساخت pollfd pfd[2];

	برائے (;;) {
		memset(&pfd, 0, حجم(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		اگر (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				جاری;
			fatal_f("poll: %s", strerror(errno));
		}
		اگر (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			جاری;
		}
		اگر (pfd[0].revents)
			توڑو;  /* Continues below */
	}

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	اگر ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	جب (ent->f != تہی) {
		اگر (ent->type == type)
			توڑو;
		ent++;
	}

	اگر (ent->f != تہی) {
		اگر (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		اگر (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		اگر (pent != تہی)
			*pent = ent;

		واپس ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	واپس (-1);
}

/* allowed key state */
ساکن صحیح
monitor_allowed_کلید(ثابت u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	اگر (کلید_blob == تہی || کلید_bloblen != bloblen ||
	    timingsafe_bcmp(کلید_blob, blob, کلید_bloblen))
		واپس (0);
	واپس (1);
}

ساکن خالی
monitor_reset_کلید_state(خالی)
{
	/* reset state */
	آزاد(کلید_blob);
	آزاد(hostbased_cuser);
	آزاد(hostbased_chost);
	sshauthopt_free(کلید_opts);
	کلید_blob = تہی;
	کلید_bloblen = 0;
	کلید_blobtype = MM_NOKEY;
	کلید_opts = تہی;
	hostbased_cuser = تہی;
	hostbased_chost = تہی;
}

صحیح
mm_answer_state(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *غیر_مستعمل)
{
	ساخت sshbuf *m = تہی, *config = تہی, *hostkeys = تہی;
	ساخت sshbuf *opts = تہی, *confdata = تہی;
	صحیح postauth;
	صحیح r;

	debug_f("config len %zu", sshbuf_len(cfg));

	اگر ((m = sshbuf_new()) == تہی ||
	    (config = sshbuf_new()) == تہی ||
	    (opts = sshbuf_new()) == تہی ||
	    (confdata = sshbuf_new()) == تہی)
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
	    (r = sshbuf_put_stringb(m, ssh->kex->server_نسخہ)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_نسخہ)) != 0)
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

	واپس (0);
}

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
mm_answer_moduli(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
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

	dh = انتخاب_dh(min, want, max);
	اگر (dh == تہی) {
		اگر ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ورنہ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, تہی, &dh_g);
		اگر ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	واپس (0);
}
#اگر_ختم

صحیح
mm_answer_setcompat(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	صحیح r;

	debug3_f("entering");

	اگر ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_سیٹ = 1;

	واپس (0);
}

صحیح
mm_answer_sign(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	خارجی صحیح auth_sock;			/* XXX move to state struct? */
	ساخت sshkey *pubkey, *کلید;
	ساخت sshbuf *sigbuf = تہی;
	u_char *p = تہی, *signature = تہی;
	حرف *alg = تہی;
	سائز_t datlen, siglen;
	صحیح r, is_proof = 0, keyid;
	u_int compat;
	ثابت حرف proof_req[] = "hostkeys-prove-00@openssh.com";
	ساکن صحیح nhostkey_proofs_مکمل, *hostkey_proofs_مکمل;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	اگر (!compat_سیٹ)
		fatal_f("state error: setcompat never called");

	اگر ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	اگر ((keyid = get_hostkey_اشاریہ(pubkey, 1, ssh)) == -1)
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
		اگر ((کلید = get_hostkey_عوامی_by_اشاریہ(keyid, ssh)) == تہی)
			fatal_f("no hostkey for index %d", keyid);
		اگر (keyid >= nhostkey_proofs_مکمل) {
			hostkey_proofs_مکمل = xrecallocarray(
			    hostkey_proofs_مکمل, nhostkey_proofs_مکمل,
			    keyid + 1, حجم(*hostkey_proofs_مکمل));
			nhostkey_proofs_مکمل = keyid + 1;
		}
		اگر (hostkey_proofs_مکمل[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(کلید), keyid);
		}
		hostkey_proofs_مکمل[keyid] = 1;
		اگر ((sigbuf = sshbuf_new()) == تہی)
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
		حافظہ_نقل(session_id2, p, session_id2_len);
	}

	اگر ((کلید = get_hostkey_by_اشاریہ(keyid)) != تہی) {
		اگر ((r = sshkey_sign(کلید, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, تہی, compat)) != 0)
			fatal_fr(r, "sign");
	} ورنہ اگر ((کلید = get_hostkey_عوامی_by_اشاریہ(keyid, ssh)) != تہی &&
	    auth_sock > 0) {
		اگر ((r = ssh_agent_sign(auth_sock, کلید, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ورنہ
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

	واپس (0);
}

#تعریف_کرو PUTPW(b, id) \
	کرو { \
		اگر ((r = sshbuf_put_string(b, \
		    &pwent->id, حجم(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} جب (0)

خالی
mm_encode_server_options(ساخت sshbuf *m)
{
	صحیح r;
	ساخت sshbuf *config;

	اگر ((config = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	اگر ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
صحیح
mm_answer_pwnamallow(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	ساخت passwd *pwent;
	صحیح r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	اگر (!compat_سیٹ)
		fatal_f("state error: setcompat never called");

	اگر (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	اگر ((r = sshbuf_get_cstring(m, &authctxt->user, تہی)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	اگر (pwent == تہی) {
		invalid_user = 1;
		اگر ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		جاؤ برآمد;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	اگر ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#اگر_ختم
	اگر ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#اگر_ختم
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#اگر_ختم
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 برآمد:
	ssh_packet_سیٹ_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	اگر (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_پورٹ(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	اگر (auth2_تیاری_methods_lists(authctxt) != 0) {
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

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_آغاز, 1);
#اگر_ختم

	واپس (0);
}

صحیح mm_answer_auth2_read_banner(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	حرف *banner;
	صحیح r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	اگر ((r = sshbuf_put_cstring(m, banner != تہی ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	آزاد(banner);

	واپس (0);
}

صحیح
mm_answer_authserv(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	صحیح r;

	monitor_permit_authentications(1);

	اگر ((r = sshbuf_get_cstring(m, &authctxt->service, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, تہی)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	اگر (لڑی_لمبائی(authctxt->style) == 0) {
		آزاد(authctxt->style);
		authctxt->style = تہی;
	}

	واپس (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ساکن صحیح
کلید_بنیاد_type_مطابقت(ثابت حرف *طریقہ, ثابت ساخت sshkey *کلید,
    ثابت حرف *list)
{
	حرف *s, *l, *ol = xstrdup(list);
	صحیح ملا = 0;

	l = ol;
	برائے ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		اگر (sshkey_type_from_name(s) == کلید->type) {
			ملا = 1;
			توڑو;
		}
	}
	اگر (!ملا) {
		error("%s key type %s is not in permitted list %s", طریقہ,
		    sshkey_ssh_name(کلید), list);
	}

	آزاد(ol);
	واپس ملا;
}

صحیح
mm_answer_authpassword(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	ساکن صحیح call_گنتی;
	حرف *passwd;
	صحیح r, authenticated;
	سائز_t plen;

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
#اگر_تعریف_شدہ USE_PAM
	اگر ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#اگر_ختم

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_گنتی++;
	اگر (plen == 0 && call_گنتی == 1)
		auth_طریقہ = "none";
	ورنہ
		auth_طریقہ = "password";

	/* Causes monitor loop to terminate if authenticated */
	واپس (authenticated);
}

#اگر_تعریف_شدہ BSD_AUTH
صحیح
mm_answer_bsdauthquery(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	حرف *name, *infotxt;
	u_int numprompts, *echo_on, success;
	حرف **prompts;
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

	واپس (0);
}

صحیح
mm_answer_bsdauthrespond(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	حرف *response;
	صحیح r, authok;

	اگر (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	اگر (authctxt->as == تہی)
		fatal_f("no bsd auth session");

	اگر ((r = sshbuf_get_cstring(m, &response, تہی)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = تہی;
	debug3_f("<%s> = <%d>", response, authok);
	آزاد(response);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_طریقہ = "keyboard-interactive";
	auth_submethod = "bsdauth";

	واپس (authok != 0);
}
#اگر_ختم

#اگر_تعریف_شدہ USE_PAM
صحیح
mm_answer_pam_آغاز(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	اگر (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	آغاز_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	اگر (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	واپس (0);
}

صحیح
mm_answer_pam_account(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
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

	واپس (ret);
}

ساکن خالی *sshpam_ctxt, *sshpam_authok;
خارجی KbdintDevice sshpam_device;

صحیح
mm_answer_pam_init_ctx(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	u_int ok = 0;
	صحیح r;

	debug3_f("entering");
	اگر (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	اگر (sshpam_ctxt != تہی)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = تہی;
	sshbuf_reset(m);
	اگر (sshpam_ctxt != تہی) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	اگر ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	واپس (0);
}

صحیح
mm_answer_pam_query(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	حرف *name = تہی, *info = تہی, **prompts = تہی;
	u_int i, عدد = 0, *echo_on = 0;
	صحیح r, ret;

	debug3_f("entering");
	sshpam_authok = تہی;
	اگر (sshpam_ctxt == تہی)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &عدد, &prompts, &echo_on);
	اگر (ret == 0 && عدد == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	اگر (عدد > 1 || name == تہی || info == تہی)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, عدد)) != 0)
		fatal_fr(r, "buffer error");
	آزاد(name);
	آزاد(info);
	برائے (i = 0; i < عدد; ++i) {
		اگر ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		آزاد(prompts[i]);
	}
	آزاد(prompts);
	آزاد(echo_on);
	auth_طریقہ = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	واپس (0);
}

صحیح
mm_answer_pam_respond(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	حرف **resp;
	u_int i, عدد;
	صحیح r, ret;

	debug3_f("entering");
	اگر (sshpam_ctxt == تہی)
		fatal_f("no context");
	sshpam_authok = تہی;
	اگر ((r = sshbuf_get_u32(m, &عدد)) != 0)
		fatal_fr(r, "buffer error");
	اگر (عدد > PAM_MAX_عدد_پیغام) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    عدد, (غیرعلامتی)PAM_MAX_عدد_پیغام);
	}
	اگر (عدد > 0) {
		resp = xcalloc(عدد, حجم(حرف *));
		برائے (i = 0; i < عدد; ++i) {
			اگر ((r = sshbuf_get_cstring(m, &(resp[i]), تہی)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, عدد, resp);
		برائے (i = 0; i < عدد; ++i)
			آزاد(resp[i]);
		آزاد(resp);
	} ورنہ {
		ret = (sshpam_device.respond)(sshpam_ctxt, عدد, تہی);
	}
	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_طریقہ = "keyboard-interactive";
	auth_submethod = "pam";
	اگر (ret == 0)
		sshpam_authok = sshpam_ctxt;
	واپس (0);
}

صحیح
mm_answer_pam_free_ctx(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	صحیح r = sshpam_authok != تہی && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	اگر (sshpam_ctxt == تہی)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = تہی;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_طریقہ = "keyboard-interactive";
	auth_submethod = "pam";
	واپس r;
}
#اگر_ختم

صحیح
mm_answer_keyallowed(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	ساخت sshkey *کلید = تہی;
	حرف *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	صحیح r, allowed = 0;
	ساخت sshauthopt *opts = تہی;

	debug3_f("entering");
	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, تہی)) != 0 ||
	    (r = sshkey_froms(m, &کلید)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	اگر (کلید != تہی && authctxt->valid) {
		انتخاب (type) {
		حالت MM_USERKEY:
			auth_طریقہ = "publickey";
			اگر (!options.pubkey_authentication)
				توڑو;
			اگر (auth2_کلید_already_مستعمل(authctxt, کلید))
				توڑو;
			اگر (!کلید_بنیاد_type_مطابقت(auth_طریقہ, کلید,
			    options.pubkey_accepted_algos))
				توڑو;
			allowed = user_کلید_allowed(ssh, authctxt->pw, کلید,
			    pubkey_auth_attempt, &opts);
			توڑو;
		حالت MM_HOSTKEY:
			auth_طریقہ = "hostbased";
			اگر (!options.hostbased_authentication)
				توڑو;
			اگر (auth2_کلید_already_مستعمل(authctxt, کلید))
				توڑو;
			اگر (!کلید_بنیاد_type_مطابقت(auth_طریقہ, کلید,
			    options.hostbased_accepted_algos))
				توڑو;
			allowed = hostbased_کلید_allowed(ssh, authctxt->pw,
			    cuser, chost, کلید);
			auth2_ریکارڈ_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			توڑو;
		طےشدہ:
			fatal_f("unknown key type %u", type);
			توڑو;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_طریقہ,
	    pubkey_auth_attempt ? "" : " test",
	    (کلید == تہی || !authctxt->valid) ? "invalid" : sshkey_type(کلید),
	    allowed ? "allowed" : "not allowed");

	auth2_ریکارڈ_کلید(authctxt, 0, کلید);

	/* clear temporarily storage (used by verify) */
	monitor_reset_کلید_state();

	اگر (allowed) {
		/* Save temporarily for comparison in verify */
		اگر ((r = sshkey_مقصد_blob(کلید, &کلید_blob, &کلید_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		کلید_blobtype = type;
		کلید_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ورنہ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_طریقہ, تہی);
		آزاد(cuser);
		آزاد(chost);
	}
	sshkey_free(کلید);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	اگر (opts != تہی && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	اگر (!allowed)
		sshauthopt_free(opts);

	واپس (0);
}

ساکن صحیح
monitor_valid_userblob(ساخت ssh *ssh, ثابت u_char *ڈیٹا, u_int datalen)
{
	ساخت sshbuf *b;
	ساخت sshkey *hostkey = تہی;
	ثابت u_char *p;
	حرف *userstyle, *cp;
	سائز_t len;
	u_char type;
	صحیح hostbound = 0, r, fail = 0;

	اگر ((b = sshbuf_from(ڈیٹا, datalen)) == تہی)
		fatal_f("sshbuf_from");

	اگر ((r = sshbuf_get_string_براہ_راست(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	اگر ((session_id2 == تہی) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیغام_USERAUTH_REQUEST)
		fail++;
	اگر ((r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
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
	    (r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp("publickey", cp) != 0) {
		اگر (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ورنہ
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
	اگر (hostkey != تہی) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		اگر (get_hostkey_اشاریہ(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	واپس (fail == 0);
}

ساکن صحیح
monitor_valid_hostbasedblob(ثابت u_char *ڈیٹا, u_int datalen,
    ثابت حرف *cuser, ثابت حرف *chost)
{
	ساخت sshbuf *b;
	ثابت u_char *p;
	حرف *cp, *userstyle;
	سائز_t len;
	صحیح r, fail = 0;
	u_char type;

	اگر ((b = sshbuf_from(ڈیٹا, datalen)) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_get_string_براہ_راست(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	اگر ((session_id2 == تہی) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	اگر ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_پیغام_USERAUTH_REQUEST)
		fail++;
	اگر ((r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
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
	    (r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
		fatal_fr(r, "parse method");
	اگر (strcmp(cp, "hostbased") != 0)
		fail++;
	آزاد(cp);
	اگر ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	اگر ((r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
		fatal_fr(r, "parse host");
	اگر (((len = لڑی_لمبائی(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	اگر (strcmp(cp, chost) != 0)
		fail++;
	آزاد(cp);

	/* verify client user */
	اگر ((r = sshbuf_get_cstring(b, &cp, تہی)) != 0)
		fatal_fr(r, "parse ruser");
	اگر (strcmp(cp, cuser) != 0)
		fail++;
	آزاد(cp);

	اگر (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	واپس (fail == 0);
}

صحیح
mm_answer_keyverify(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	ساخت sshkey *کلید;
	ثابت u_char *signature, *ڈیٹا, *blob;
	حرف *sigalg = تہی, *fp = تہی;
	سائز_t signaturelen, datalen, bloblen;
	صحیح r, ret, req_presence = 0, req_verify = 0, valid_ڈیٹا = 0;
	صحیح encoded_ret;
	ساخت sshkey_sig_details *sig_details = تہی;

	اگر ((r = sshbuf_get_string_براہ_راست(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(m, &ڈیٹا, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, تہی)) != 0)
		fatal_fr(r, "parse");

	اگر (hostbased_cuser == تہی || hostbased_chost == تہی ||
	  !monitor_allowed_کلید(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	اگر (*sigalg == '\0') {
		آزاد(sigalg);
		sigalg = تہی;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	اگر ((r = sshkey_from_blob(blob, bloblen, &کلید)) != 0)
		fatal_fr(r, "parse key");

	انتخاب (کلید_blobtype) {
	حالت MM_USERKEY:
		valid_ڈیٹا = monitor_valid_userblob(ssh, ڈیٹا, datalen);
		auth_طریقہ = "publickey";
		توڑو;
	حالت MM_HOSTKEY:
		valid_ڈیٹا = monitor_valid_hostbasedblob(ڈیٹا, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_طریقہ = "hostbased";
		توڑو;
	طےشدہ:
		valid_ڈیٹا = 0;
		توڑو;
	}
	اگر (!valid_ڈیٹا)
		fatal_f("bad %s signature data blob",
		    کلید_blobtype == MM_USERKEY ? "userkey" :
		    (کلید_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(کلید, signature, signaturelen, ڈیٹا, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_طریقہ,
	    sshkey_type(کلید), sigalg == تہی ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	اگر (ret == 0 && کلید_blobtype == MM_USERKEY && sig_details != تہی) {
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
			    ssh_remote_پورٹ(ssh));
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
			    ssh_remote_پورٹ(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_ریکارڈ_کلید(authctxt, ret == 0, کلید);

	اگر (کلید_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, کلید_opts);
	monitor_reset_کلید_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	اگر ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != تہی)) != 0)
		fatal_fr(r, "assemble");
	اگر (sig_details != تہی) {
		اگر ((r = sshbuf_put_u32(m, sig_details->sk_شمار)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	آزاد(sigalg);
	آزاد(fp);
	sshkey_free(کلید);

	واپس ret == 0;
}

ساکن خالی
mm_ریکارڈ_login(ساخت ssh *ssh, Session *s, ساخت passwd *pw)
{
	socklen_t fromlen;
	ساخت sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, حجم(from));
	fromlen = حجم(from);
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		اگر (getpeername(ssh_packet_get_connection_اندر(ssh),
		    (ساخت sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	ریکارڈ_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (ساخت sockaddr *)&from, fromlen);
}

ساکن خالی
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (طویل)s->pid);
	اگر (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_غیر_مستعمل(s->self);
}

صحیح
mm_answer_pty(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	خارجی ساخت monitor *pmonitor;
	Session *s;
	صحیح r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	اگر (s == تہی)
		جاؤ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, حجم(s->tty));
	اگر (res == 0)
		جاؤ error;
	pty_setowner(authctxt->pw, s->tty);

	اگر ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	اگر (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_ریکارڈ_login(ssh, s, authctxt->pw);

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

	واپس (0);

 error:
	اگر (s != تہی)
		mm_session_close(s);
	اگر ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	واپس (0);
}

صحیح
mm_answer_pty_cleanup(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	Session *s;
	حرف *tty;
	صحیح r;

	debug3_f("entering");

	اگر ((r = sshbuf_get_cstring(m, &tty, تہی)) != 0)
		fatal_fr(r, "parse tty");
	اگر ((s = session_by_tty(tty)) != تہی)
		mm_session_close(s);
	sshbuf_reset(m);
	آزاد(tty);
	واپس (0);
}

صحیح
mm_answer_رکن(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *req)
{
	خارجی ساخت monitor *pmonitor;
	صحیح res, حالت_2;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam)
		sshpam_cleanup();
#اگر_ختم

	جب (waitpid(pmonitor->m_pid, &حالت_2, 0) == -1)
		اگر (errno != EINTR)
			باہر_نکلو(1);

	res = WIFEXITED(حالت_2) ? WEXITSTATUS(حالت_2) : 1;

	/* Terminate process */
	باہر_نکلو(res);
}

#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
صحیح
mm_answer_audit_event(ساخت ssh *ssh, صحیح socket, ساخت sshbuf *m)
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
	حالت SSH_LOGIN_جڑ_DENIED:
	حالت SSH_CONNECTION_CLOSE:
	حالت SSH_INVALID_USER:
		audit_event(ssh, event);
		توڑو;
	طےشدہ:
		fatal("Audit event type %d not permitted", event);
	}

	واپس (0);
}

صحیح
mm_answer_audit_command(ساخت ssh *ssh, صحیح socket, ساخت sshbuf *m)
{
	حرف *cmd;
	صحیح r;

	debug3_f("entering");
	اگر ((r = sshbuf_get_cstring(m, &cmd, تہی)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_تسلسل_command(cmd);
	آزاد(cmd);
	واپس (0);
}
#اگر_ختم /* SSH_AUDIT_EVENTS */

خالی
monitor_clear_keystate(ساخت ssh *ssh, ساخت monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, منوال_اندر);
	ssh_clear_newkeys(ssh, منوال_برآمد);
	sshbuf_free(بچہ_state);
	بچہ_state = تہی;
}

خالی
monitor_apply_keystate(ساخت ssh *ssh, ساخت monitor *pmonitor)
{
	ساخت kex *kex;
	صحیح r;

	debug3_f("packet_set_state");
	اگر ((r = ssh_packet_سیٹ_state(ssh, بچہ_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(بچہ_state);
	بچہ_state = تہی;
	اگر ((kex = ssh->kex) == تہی)
		fatal_f("internal error: ssh->kex == NULL");
	اگر (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	اگر (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#اگر_تعریف_شدہ WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#اگر_ختم
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->بھرو_host_عوامی_کلید=&get_hostkey_عوامی_by_type;
	kex->بھرو_host_نجی_کلید=&get_hostkey_نجی_by_type;
	kex->host_کلید_اشاریہ=&get_hostkey_اشاریہ;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

خالی
mm_get_keystate(ساخت ssh *ssh, ساخت monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	اگر ((بچہ_state = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    بچہ_state);
	debug3_f("GOT new keys");
}


/* XXX */

ساکن خالی
monitor_openfds(ساخت monitor *mon, صحیح do_logfds)
{
	صحیح pair[2];
#اگر_تعریف_شدہ SO_ZEROIZE
	صحیح on = 1;
#اگر_ختم

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#اگر_تعریف_شدہ SO_ZEROIZE
	اگر (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, حجم(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	اگر (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, حجم(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#اگر_ختم
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
	} ورنہ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

ساخت monitor *
monitor_init(خالی)
{
	ساخت monitor *mon;

	mon = xcalloc(1, حجم(*mon));
	monitor_openfds(mon, 1);

	واپس mon;
}

خالی
monitor_reinit(ساخت monitor *mon)
{
	monitor_openfds(mon, 0);
}

صحیح
monitor_auth_attempted(خالی)
{
	واپس auth_attempted;
}

صحیح
monitor_invalid_user(خالی)
{
	واپس invalid_user;
}

#اگر_تعریف_شدہ GSSAPI
صحیح
mm_answer_gss_تیاری_ctx(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	سائز_t len;
	u_char *p;
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	اگر ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.لمبائی = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	آزاد(goid.elements);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	واپس (0);
}

صحیح
mm_answer_gss_accept_ctx(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	gss_بفر_desc اندر;
	gss_بفر_desc برآمد = GSS_C_خالی_خانے_بفر;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	اگر ((r = ssh_gssapi_get_بفر_desc(m, &اندر)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &اندر, &برآمد, &flags);
	آزاد(اندر.قدر);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, برآمد.قدر, برآمد.لمبائی)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_بفر(&minor, &برآمد);

	اگر (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	واپس (0);
}

صحیح
mm_answer_gss_checkmic(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	gss_بفر_desc gssbuf, mic;
	OM_uint32 ret;
	صحیح r;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	اگر ((r = ssh_gssapi_get_بفر_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_بفر_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	آزاد(gssbuf.قدر);
	آزاد(mic.قدر);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	اگر (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	واپس (0);
}

صحیح
mm_answer_gss_userok(ساخت ssh *ssh, صحیح sock, ساخت sshbuf *m)
{
	صحیح r, authenticated;
	ثابت حرف *displayname;

	اگر (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	اگر ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_طریقہ = "gssapi-with-mic";

	اگر ((displayname = ssh_gssapi_displayname()) != تہی)
		auth2_ریکارڈ_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	واپس (authenticated);
}
#اگر_ختم /* GSSAPI */

