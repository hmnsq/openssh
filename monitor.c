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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/socket.h>
#ضمن <sys/tree.h>
#ضمن <sys/queue.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <paths.h>
#ضمن <poll.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#اگر_تعریف_شده WITH_OPENSSL
#ضمن <openssl/dh.h>
#پایان_اگر

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "atomicio.h"
#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "dh.h"
#ضمن "auth-pam.h"
#ضمن "packet.h"
#ضمن "auth-options.h"
#ضمن "sshpty.h"
#ضمن "channels.h"
#ضمن "session.h"
#ضمن "sshlogin.h"
#ضمن "canohost.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "monitor.h"
#اگر_تعریف_شده GSSAPI
#ضمن "ssh-gss.h"
#پایان_اگر
#ضمن "monitor_wrap.h"
#ضمن "monitor_fdpass.h"
#ضمن "compat.h"
#ضمن "ssh2.h"
#ضمن "authfd.h"
#ضمن "match.h"
#ضمن "ssherr.h"
#ضمن "sk-api.h"
#ضمن "srclimit.h"

#اگر_تعریف_شده GSSAPI
ساكن Gssctxt *gsscontext = عدم;
#پایان_اگر

/* Imports */
خارجي ServerOptions options;
خارجي u_int utmp_len;
خارجي بنية sshbuf *cfg;
خارجي بنية sshbuf *loginmsg;
خارجي بنية include_list includes;
خارجي بنية sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
ساكن بنية sshbuf *فرزند_state;

/* Functions on the monitor that answer unprivileged requests */

صحيح mm_answer_moduli(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_setcompat(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_sign(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pwnamallow(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_auth2_read_banner(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_authserv(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_authpassword(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_bsdauthquery(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_bsdauthrespond(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_keyallowed(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_keyverify(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pty(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pty_cleanup(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_جمله(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_state(بنية ssh *, صحيح, بنية sshbuf *);

#اگر_تعریف_شده USE_PAM
صحيح mm_answer_pam_شروع(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pam_account(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pam_init_ctx(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pam_query(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pam_respond(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_pam_free_ctx(بنية ssh *, صحيح, بنية sshbuf *);
#پایان_اگر

#اگر_تعریف_شده GSSAPI
صحيح mm_answer_gss_راهاندازی_ctx(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_gss_accept_ctx(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_gss_userok(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_gss_checkmic(بنية ssh *, صحيح, بنية sshbuf *);
#پایان_اگر

#اگر_تعریف_شده SSH_AUDIT_EVENTS
صحيح mm_answer_audit_event(بنية ssh *, صحيح, بنية sshbuf *);
صحيح mm_answer_audit_command(بنية ssh *, صحيح, بنية sshbuf *);
#پایان_اگر

ساكن Authctxt *authctxt;

/* local state for key verify */
ساكن u_char *کلید_blob = عدم;
ساكن اندازه_t کلید_bloblen = 0;
ساكن u_int کلید_blobtype = MM_NOKEY;
ساكن بنية sshauthopt *کلید_opts = عدم;
ساكن حرف *hostbased_cuser = عدم;
ساكن حرف *hostbased_chost = عدم;
ساكن حرف *auth_روش = "unknown";
ساكن حرف *auth_submethod = عدم;
ساكن u_int session_id2_len = 0;
ساكن u_char *session_id2 = عدم;
ساكن pid_t monitor_فرزند_pid;
ساكن صحيح auth_attempted = 0;
ساكن صحيح invalid_user = 0;
ساكن صحيح compat_مجموعه = 0;

بنية mon_جدول {
	تعداد monitor_reqtype type;
	صحيح flags;
	صحيح (*f)(بنية ssh *, صحيح, بنية sshbuf *);
};

#تعریف_کن MON_ISAUTH	0x0004	/* Required for Authentication */
#تعریف_کن MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#تعریف_کن MON_ONCE	0x0010	/* Disable after calling */
#تعریف_کن MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#تعریف_کن MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#تعریف_کن MON_PERMIT	0x1000	/* Request is permitted */

ساكن صحيح monitor_read(بنية ssh *, بنية monitor *, بنية mon_جدول *,
    بنية mon_جدول **);
ساكن صحيح monitor_read_log(بنية monitor *);

بنية mon_جدول mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#اگر_تعریف_شده WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#پایان_اگر
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#اگر_تعریف_شده USE_PAM
    {MONITOR_REQ_PAM_شروع, MON_ONCE, mm_answer_pam_شروع},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#پایان_اگر
#اگر_تعریف_شده SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#پایان_اگر
#اگر_تعریف_شده BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#پایان_اگر
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#اگر_تعریف_شده GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_راهاندازی_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#پایان_اگر
    {0, 0, عدم}
};

بنية mon_جدول mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#اگر_تعریف_شده WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#پایان_اگر
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_جمله, 0, mm_answer_جمله},
#اگر_تعریف_شده SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#پایان_اگر
    {0, 0, عدم}
};

بنية mon_جدول *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
ساكن فراغ
monitor_permit(بنية mon_جدول *ent, تعداد monitor_reqtype type, صحيح permit)
{
	طالما (ent->f != عدم) {
		إذا (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			أرجع;
		}
		ent++;
	}
}

ساكن فراغ
monitor_permit_authentications(صحيح permit)
{
	بنية mon_جدول *ent = mon_dispatch;

	طالما (ent->f != عدم) {
		إذا (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

فراغ
monitor_فرزند_preauth(بنية ssh *ssh, بنية monitor *pmonitor)
{
	بنية mon_جدول *ent;
	صحيح وضعیت, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	إذا (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	إذا (pmonitor->m_log_sendfd >= 0)
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
	طالما (!authenticated) {
		partial = 0;
		auth_روش = "unknown";
		auth_submethod = عدم;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		إذا ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		إذا (options.رقم_auth_methods != 0) {
			إذا (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_روش, auth_submethod)) {
				debug3_f("method %s: partial", auth_روش);
				authenticated = 0;
				partial = 1;
			}
		}

		إذا (authenticated) {
			إذا (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			إذا (authctxt->pw->pw_uid == 0 &&
			    !auth_ریشه_allowed(ssh, auth_روش))
				authenticated = 0;
#اگر_تعریف_شده USE_PAM
			/* PAM needs to perform account checks after auth */
			إذا (options.use_pam && authenticated) {
				بنية sshbuf *m;

				إذا ((m = sshbuf_new()) == عدم)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#پایان_اگر
		}
		إذا (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_روش, auth_submethod);
			إذا (!partial && !authenticated)
				authctxt->failures++;
			إذا (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_روش, auth_submethod);
			}
		}
		إذا (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	إذا (!authctxt->valid)
		fatal_f("authenticated invalid user");
	إذا (strcmp(auth_روش, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = عدم;
	ssh_packet_مجموعه_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	طالما (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	طالما (waitpid(pmonitor->m_pid, &وضعیت, 0) == -1) {
		إذا (errno == EINTR)
			استمر;
		fatal_f("waitpid: %s", strerror(errno));
	}
	إذا (WIFEXITED(وضعیت)) {
		إذا (WEXITSTATUS(وضعیت) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (دراز)pmonitor->m_pid, WEXITSTATUS(وضعیت));
	} وإلا إذا (WIFSIGNALED(وضعیت)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (دراز)pmonitor->m_pid, WTERMSIG(وضعیت));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (دراز)pmonitor->m_pid);

	إذا (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	إذا (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

ساكن فراغ
monitor_مجموعه_فرزند_handler(pid_t pid)
{
	monitor_فرزند_pid = pid;
}

ساكن فراغ
monitor_فرزند_handler(صحيح sig)
{
	kill(monitor_فرزند_pid, sig);
}

فراغ
monitor_فرزند_postauth(بنية ssh *ssh, بنية monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_مجموعه_فرزند_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_فرزند_handler);
	ssh_signal(SIGTERM, &monitor_فرزند_handler);
	ssh_signal(SIGINT, &monitor_فرزند_handler);
#اگر_تعریف_شده SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#پایان_اگر

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_جمله, 1);

	إذا (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	لكل (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, عدم);
}

ساكن صحيح
monitor_read_log(بنية monitor *pmonitor)
{
	بنية sshbuf *logmsg;
	u_int len, level, forced;
	حرف *پیام;
	u_char *p;
	صحيح r;

	إذا ((logmsg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	/* Read length */
	إذا ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	إذا (atomicio(اقرأ, pmonitor->m_log_recvfd, p, 4) != 4) {
		إذا (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			أرجع -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	إذا ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	إذا (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	إذا ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	إذا (atomicio(اقرأ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	إذا ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &پیام, عدم)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	إذا (log_level_name(level) == عدم)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", پیام,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	حرر(پیام);

	أرجع 0;
}

ساكن صحيح
monitor_read(بنية ssh *ssh, بنية monitor *pmonitor, بنية mon_جدول *ent,
    بنية mon_جدول **pent)
{
	بنية sshbuf *m;
	صحيح r, ret;
	u_char type;
	بنية pollfd pfd[2];

	لكل (;;) {
		memset(&pfd, 0, حجم(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		إذا (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			إذا (errno == EINTR || errno == EAGAIN)
				استمر;
			fatal_f("poll: %s", strerror(errno));
		}
		إذا (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			استمر;
		}
		إذا (pfd[0].revents)
			اكسر;  /* Continues below */
	}

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	إذا ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	طالما (ent->f != عدم) {
		إذا (ent->type == type)
			اكسر;
		ent++;
	}

	إذا (ent->f != عدم) {
		إذا (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		إذا (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		إذا (pent != عدم)
			*pent = ent;

		أرجع ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	أرجع (-1);
}

/* allowed key state */
ساكن صحيح
monitor_allowed_کلید(ثابت u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	إذا (کلید_blob == عدم || کلید_bloblen != bloblen ||
	    timingsafe_bcmp(کلید_blob, blob, کلید_bloblen))
		أرجع (0);
	أرجع (1);
}

ساكن فراغ
monitor_reset_کلید_state(فراغ)
{
	/* reset state */
	حرر(کلید_blob);
	حرر(hostbased_cuser);
	حرر(hostbased_chost);
	sshauthopt_free(کلید_opts);
	کلید_blob = عدم;
	کلید_bloblen = 0;
	کلید_blobtype = MM_NOKEY;
	کلید_opts = عدم;
	hostbased_cuser = عدم;
	hostbased_chost = عدم;
}

صحيح
mm_answer_state(بنية ssh *ssh, صحيح sock, بنية sshbuf *استفادهنشده)
{
	بنية sshbuf *m = عدم, *config = عدم, *hostkeys = عدم;
	بنية sshbuf *opts = عدم, *confdata = عدم;
	صحيح postauth;
	صحيح r;

	debug_f("config len %zu", sshbuf_len(cfg));

	إذا ((m = sshbuf_new()) == عدم ||
	    (config = sshbuf_new()) == عدم ||
	    (opts = sshbuf_new()) == عدم ||
	    (confdata = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	إذا ((r = serialise_server_options(&options, &config)) != 0)
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
	إذا ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_نسخه)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_نسخه)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	إذا (postauth) {
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

	أرجع (0);
}

#اگر_تعریف_شده WITH_OPENSSL
صحيح
mm_answer_moduli(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	DH *dh;
	ثابت BIGNUM *dh_p, *dh_g;
	صحيح r;
	u_int min, want, max;

	إذا ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	إذا (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = انتخاب_dh(min, want, max);
	إذا (dh == عدم) {
		إذا ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} وإلا {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, عدم, &dh_g);
		إذا ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	أرجع (0);
}
#پایان_اگر

صحيح
mm_answer_setcompat(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	صحيح r;

	debug3_f("entering");

	إذا ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_مجموعه = 1;

	أرجع (0);
}

صحيح
mm_answer_sign(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	خارجي صحيح auth_sock;			/* XXX move to state struct? */
	بنية sshkey *pubkey, *کلید;
	بنية sshbuf *sigbuf = عدم;
	u_char *p = عدم, *signature = عدم;
	حرف *alg = عدم;
	اندازه_t datlen, siglen;
	صحيح r, is_proof = 0, keyid;
	u_int compat;
	ثابت حرف proof_req[] = "hostkeys-prove-00@openssh.com";
	ساكن صحيح nhostkey_proofs_انجامشده, *hostkey_proofs_انجامشده;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	إذا (!compat_مجموعه)
		fatal_f("state error: setcompat never called");

	إذا ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	إذا ((keyid = get_hostkey_شاخص(pubkey, 1, ssh)) == -1)
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
	إذا (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		إذا (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		إذا ((کلید = get_hostkey_عمومی_by_شاخص(keyid, ssh)) == عدم)
			fatal_f("no hostkey for index %d", keyid);
		إذا (keyid >= nhostkey_proofs_انجامشده) {
			hostkey_proofs_انجامشده = xrecallocarray(
			    hostkey_proofs_انجامشده, nhostkey_proofs_انجامشده,
			    keyid + 1, حجم(*hostkey_proofs_انجامشده));
			nhostkey_proofs_انجامشده = keyid + 1;
		}
		إذا (hostkey_proofs_انجامشده[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(کلید), keyid);
		}
		hostkey_proofs_انجامشده[keyid] = 1;
		إذا ((sigbuf = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new");
		إذا ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(کلید, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		إذا (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	إذا (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		کپی_حافظه(session_id2, p, session_id2_len);
	}

	إذا ((کلید = get_hostkey_by_شاخص(keyid)) != عدم) {
		إذا ((r = sshkey_sign(کلید, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, عدم, compat)) != 0)
			fatal_fr(r, "sign");
	} وإلا إذا ((کلید = get_hostkey_عمومی_by_شاخص(keyid, ssh)) != عدم &&
	    auth_sock > 0) {
		إذا ((r = ssh_agent_sign(auth_sock, کلید, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} وإلا
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	حرر(alg);
	حرر(p);
	حرر(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	أرجع (0);
}

#تعریف_کن PUTPW(b, id) \
	افعل { \
		إذا ((r = sshbuf_put_string(b, \
		    &pwent->id, حجم(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} طالما (0)

فراغ
mm_encode_server_options(بنية sshbuf *m)
{
	صحيح r;
	بنية sshbuf *config;

	إذا ((config = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	إذا ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
صحيح
mm_answer_pwnamallow(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	بنية passwd *pwent;
	صحيح r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	إذا (!compat_مجموعه)
		fatal_f("state error: setcompat never called");

	إذا (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	إذا ((r = sshbuf_get_cstring(m, &authctxt->user, عدم)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	إذا (pwent == عدم) {
		invalid_user = 1;
		إذا ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		اذهب بیرون;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	إذا ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#اگر_تعریف_شده HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#پایان_اگر
#اگر_تعریف_شده HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#پایان_اگر
	إذا ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#اگر_تعریف_شده HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#پایان_اگر
#اگر_تعریف_شده HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#پایان_اگر
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 بیرون:
	ssh_packet_مجموعه_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	إذا (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_پورت(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	إذا (auth2_راهاندازی_methods_lists(authctxt) != 0) {
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

#اگر_تعریف_شده USE_PAM
	إذا (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_شروع, 1);
#پایان_اگر

	أرجع (0);
}

صحيح mm_answer_auth2_read_banner(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	حرف *banner;
	صحيح r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	إذا ((r = sshbuf_put_cstring(m, banner != عدم ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	حرر(banner);

	أرجع (0);
}

صحيح
mm_answer_authserv(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	صحيح r;

	monitor_permit_authentications(1);

	إذا ((r = sshbuf_get_cstring(m, &authctxt->service, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, عدم)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	إذا (طول_رشته(authctxt->style) == 0) {
		حرر(authctxt->style);
		authctxt->style = عدم;
	}

	أرجع (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
ساكن صحيح
کلید_پایه_type_تطابق(ثابت حرف *روش, ثابت بنية sshkey *کلید,
    ثابت حرف *list)
{
	حرف *s, *l, *ol = xstrdup(list);
	صحيح یافت = 0;

	l = ol;
	لكل ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		إذا (sshkey_type_from_name(s) == کلید->type) {
			یافت = 1;
			اكسر;
		}
	}
	إذا (!یافت) {
		error("%s key type %s is not in permitted list %s", روش,
		    sshkey_ssh_name(کلید), list);
	}

	حرر(ol);
	أرجع یافت;
}

صحيح
mm_answer_authpassword(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	ساكن صحيح call_شمار;
	حرف *passwd;
	صحيح r, authenticated;
	اندازه_t plen;

	إذا (!options.password_authentication)
		fatal_f("password authentication not enabled");
	إذا ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#اگر_تعریف_شده USE_PAM
	إذا ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#پایان_اگر

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_شمار++;
	إذا (plen == 0 && call_شمار == 1)
		auth_روش = "none";
	وإلا
		auth_روش = "password";

	/* Causes monitor loop to terminate if authenticated */
	أرجع (authenticated);
}

#اگر_تعریف_شده BSD_AUTH
صحيح
mm_answer_bsdauthquery(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	حرف *name, *infotxt;
	u_int numprompts, *echo_on, success;
	حرف **prompts;
	صحيح r;

	إذا (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	إذا (success) {
		إذا ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	إذا (success) {
		حرر(name);
		حرر(infotxt);
		حرر(prompts);
		حرر(echo_on);
	}

	أرجع (0);
}

صحيح
mm_answer_bsdauthrespond(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	حرف *response;
	صحيح r, authok;

	إذا (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	إذا (authctxt->as == عدم)
		fatal_f("no bsd auth session");

	إذا ((r = sshbuf_get_cstring(m, &response, عدم)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = عدم;
	debug3_f("<%s> = <%d>", response, authok);
	حرر(response);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_روش = "keyboard-interactive";
	auth_submethod = "bsdauth";

	أرجع (authok != 0);
}
#پایان_اگر

#اگر_تعریف_شده USE_PAM
صحيح
mm_answer_pam_شروع(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	إذا (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	شروع_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	إذا (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	أرجع (0);
}

صحيح
mm_answer_pam_account(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	u_int ret;
	صحيح r;

	إذا (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	إذا ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	أرجع (ret);
}

ساكن فراغ *sshpam_ctxt, *sshpam_authok;
خارجي KbdintDevice sshpam_device;

صحيح
mm_answer_pam_init_ctx(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	u_int ok = 0;
	صحيح r;

	debug3_f("entering");
	إذا (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	إذا (sshpam_ctxt != عدم)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = عدم;
	sshbuf_reset(m);
	إذا (sshpam_ctxt != عدم) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	إذا ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	أرجع (0);
}

صحيح
mm_answer_pam_query(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	حرف *name = عدم, *info = عدم, **prompts = عدم;
	u_int i, رقم = 0, *echo_on = 0;
	صحيح r, ret;

	debug3_f("entering");
	sshpam_authok = عدم;
	إذا (sshpam_ctxt == عدم)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &رقم, &prompts, &echo_on);
	إذا (ret == 0 && رقم == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	إذا (رقم > 1 || name == عدم || info == عدم)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, رقم)) != 0)
		fatal_fr(r, "buffer error");
	حرر(name);
	حرر(info);
	لكل (i = 0; i < رقم; ++i) {
		إذا ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		حرر(prompts[i]);
	}
	حرر(prompts);
	حرر(echo_on);
	auth_روش = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	أرجع (0);
}

صحيح
mm_answer_pam_respond(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	حرف **resp;
	u_int i, رقم;
	صحيح r, ret;

	debug3_f("entering");
	إذا (sshpam_ctxt == عدم)
		fatal_f("no context");
	sshpam_authok = عدم;
	إذا ((r = sshbuf_get_u32(m, &رقم)) != 0)
		fatal_fr(r, "buffer error");
	إذا (رقم > PAM_MAX_رقم_پیام) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    رقم, (بیعلامت)PAM_MAX_رقم_پیام);
	}
	إذا (رقم > 0) {
		resp = xcalloc(رقم, حجم(حرف *));
		لكل (i = 0; i < رقم; ++i) {
			إذا ((r = sshbuf_get_cstring(m, &(resp[i]), عدم)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, رقم, resp);
		لكل (i = 0; i < رقم; ++i)
			حرر(resp[i]);
		حرر(resp);
	} وإلا {
		ret = (sshpam_device.respond)(sshpam_ctxt, رقم, عدم);
	}
	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_روش = "keyboard-interactive";
	auth_submethod = "pam";
	إذا (ret == 0)
		sshpam_authok = sshpam_ctxt;
	أرجع (0);
}

صحيح
mm_answer_pam_free_ctx(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	صحيح r = sshpam_authok != عدم && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	إذا (sshpam_ctxt == عدم)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = عدم;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_روش = "keyboard-interactive";
	auth_submethod = "pam";
	أرجع r;
}
#پایان_اگر

صحيح
mm_answer_keyallowed(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	بنية sshkey *کلید = عدم;
	حرف *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	صحيح r, allowed = 0;
	بنية sshauthopt *opts = عدم;

	debug3_f("entering");
	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, عدم)) != 0 ||
	    (r = sshkey_froms(m, &کلید)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	إذا (کلید != عدم && authctxt->valid) {
		بدل (type) {
		حالة MM_USERKEY:
			auth_روش = "publickey";
			إذا (!options.pubkey_authentication)
				اكسر;
			إذا (auth2_کلید_already_استفاده_شده(authctxt, کلید))
				اكسر;
			إذا (!کلید_پایه_type_تطابق(auth_روش, کلید,
			    options.pubkey_accepted_algos))
				اكسر;
			allowed = user_کلید_allowed(ssh, authctxt->pw, کلید,
			    pubkey_auth_attempt, &opts);
			اكسر;
		حالة MM_HOSTKEY:
			auth_روش = "hostbased";
			إذا (!options.hostbased_authentication)
				اكسر;
			إذا (auth2_کلید_already_استفاده_شده(authctxt, کلید))
				اكسر;
			إذا (!کلید_پایه_type_تطابق(auth_روش, کلید,
			    options.hostbased_accepted_algos))
				اكسر;
			allowed = hostbased_کلید_allowed(ssh, authctxt->pw,
			    cuser, chost, کلید);
			auth2_رکورد_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			اكسر;
		افتراضي:
			fatal_f("unknown key type %u", type);
			اكسر;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_روش,
	    pubkey_auth_attempt ? "" : " test",
	    (کلید == عدم || !authctxt->valid) ? "invalid" : sshkey_type(کلید),
	    allowed ? "allowed" : "not allowed");

	auth2_رکورد_کلید(authctxt, 0, کلید);

	/* clear temporarily storage (used by verify) */
	monitor_reset_کلید_state();

	إذا (allowed) {
		/* Save temporarily for comparison in verify */
		إذا ((r = sshkey_مقصد_blob(کلید, &کلید_blob, &کلید_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		کلید_blobtype = type;
		کلید_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} وإلا {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_روش, عدم);
		حرر(cuser);
		حرر(chost);
	}
	sshkey_free(کلید);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	إذا (opts != عدم && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	إذا (!allowed)
		sshauthopt_free(opts);

	أرجع (0);
}

ساكن صحيح
monitor_valid_userblob(بنية ssh *ssh, ثابت u_char *داده, u_int datalen)
{
	بنية sshbuf *b;
	بنية sshkey *hostkey = عدم;
	ثابت u_char *p;
	حرف *userstyle, *cp;
	اندازه_t len;
	u_char type;
	صحيح hostbound = 0, r, fail = 0;

	إذا ((b = sshbuf_from(داده, datalen)) == عدم)
		fatal_f("sshbuf_from");

	إذا ((r = sshbuf_get_string_مستقیم(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	إذا ((session_id2 == عدم) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	إذا ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != SSH2_پیام_USERAUTH_REQUEST)
		fail++;
	إذا ((r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	إذا (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	حرر(userstyle);
	حرر(cp);
	إذا ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse method");
	إذا (strcmp("publickey", cp) != 0) {
		إذا (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		وإلا
			fail++;
	}
	حرر(cp);
	إذا ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	إذا (type == 0)
		fail++;
	إذا ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	إذا (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	إذا (hostkey != عدم) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		إذا (get_hostkey_شاخص(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	أرجع (fail == 0);
}

ساكن صحيح
monitor_valid_hostbasedblob(ثابت u_char *داده, u_int datalen,
    ثابت حرف *cuser, ثابت حرف *chost)
{
	بنية sshbuf *b;
	ثابت u_char *p;
	حرف *cp, *userstyle;
	اندازه_t len;
	صحيح r, fail = 0;
	u_char type;

	إذا ((b = sshbuf_from(داده, datalen)) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_get_string_مستقیم(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	إذا ((session_id2 == عدم) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	إذا ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != SSH2_پیام_USERAUTH_REQUEST)
		fail++;
	إذا ((r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	إذا (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	حرر(userstyle);
	حرر(cp);
	إذا ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse method");
	إذا (strcmp(cp, "hostbased") != 0)
		fail++;
	حرر(cp);
	إذا ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	إذا ((r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse host");
	إذا (((len = طول_رشته(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	إذا (strcmp(cp, chost) != 0)
		fail++;
	حرر(cp);

	/* verify client user */
	إذا ((r = sshbuf_get_cstring(b, &cp, عدم)) != 0)
		fatal_fr(r, "parse ruser");
	إذا (strcmp(cp, cuser) != 0)
		fail++;
	حرر(cp);

	إذا (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	أرجع (fail == 0);
}

صحيح
mm_answer_keyverify(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	بنية sshkey *کلید;
	ثابت u_char *signature, *داده, *blob;
	حرف *sigalg = عدم, *fp = عدم;
	اندازه_t signaturelen, datalen, bloblen;
	صحيح r, ret, req_presence = 0, req_verify = 0, valid_داده = 0;
	صحيح encoded_ret;
	بنية sshkey_sig_details *sig_details = عدم;

	إذا ((r = sshbuf_get_string_مستقیم(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(m, &داده, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, عدم)) != 0)
		fatal_fr(r, "parse");

	إذا (hostbased_cuser == عدم || hostbased_chost == عدم ||
	  !monitor_allowed_کلید(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	إذا (*sigalg == '\0') {
		حرر(sigalg);
		sigalg = عدم;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	إذا ((r = sshkey_from_blob(blob, bloblen, &کلید)) != 0)
		fatal_fr(r, "parse key");

	بدل (کلید_blobtype) {
	حالة MM_USERKEY:
		valid_داده = monitor_valid_userblob(ssh, داده, datalen);
		auth_روش = "publickey";
		اكسر;
	حالة MM_HOSTKEY:
		valid_داده = monitor_valid_hostbasedblob(داده, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_روش = "hostbased";
		اكسر;
	افتراضي:
		valid_داده = 0;
		اكسر;
	}
	إذا (!valid_داده)
		fatal_f("bad %s signature data blob",
		    کلید_blobtype == MM_USERKEY ? "userkey" :
		    (کلید_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	إذا ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(کلید, signature, signaturelen, داده, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_روش,
	    sshkey_type(کلید), sigalg == عدم ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	إذا (ret == 0 && کلید_blobtype == MM_USERKEY && sig_details != عدم) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !کلید_opts->no_require_user_presence;
		إذا (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(کلید), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_پورت(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || کلید_opts->require_verify;
		إذا (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(کلید), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_پورت(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_رکورد_کلید(authctxt, ret == 0, کلید);

	إذا (کلید_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, کلید_opts);
	monitor_reset_کلید_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	إذا ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != عدم)) != 0)
		fatal_fr(r, "assemble");
	إذا (sig_details != عدم) {
		إذا ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	حرر(sigalg);
	حرر(fp);
	sshkey_free(کلید);

	أرجع ret == 0;
}

ساكن فراغ
mm_رکورد_login(بنية ssh *ssh, Session *s, بنية passwd *pw)
{
	socklen_t fromlen;
	بنية sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, حجم(from));
	fromlen = حجم(from);
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		إذا (getpeername(ssh_packet_get_connection_درون(ssh),
		    (بنية sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	رکورد_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (بنية sockaddr *)&from, fromlen);
}

ساكن فراغ
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (دراز)s->pid);
	إذا (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_استفادهنشده(s->self);
}

صحيح
mm_answer_pty(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	خارجي بنية monitor *pmonitor;
	Session *s;
	صحيح r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	إذا (s == عدم)
		اذهب error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, حجم(s->tty));
	إذا (res == 0)
		اذهب error;
	pty_setowner(authctxt->pw, s->tty);

	إذا ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	إذا (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_رکورد_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	إذا ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	إذا (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	إذا ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	إذا (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	أرجع (0);

 error:
	إذا (s != عدم)
		mm_session_close(s);
	إذا ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	أرجع (0);
}

صحيح
mm_answer_pty_cleanup(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	Session *s;
	حرف *tty;
	صحيح r;

	debug3_f("entering");

	إذا ((r = sshbuf_get_cstring(m, &tty, عدم)) != 0)
		fatal_fr(r, "parse tty");
	إذا ((s = session_by_tty(tty)) != عدم)
		mm_session_close(s);
	sshbuf_reset(m);
	حرر(tty);
	أرجع (0);
}

صحيح
mm_answer_جمله(بنية ssh *ssh, صحيح sock, بنية sshbuf *req)
{
	خارجي بنية monitor *pmonitor;
	صحيح res, وضعیت;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#اگر_تعریف_شده USE_PAM
	إذا (options.use_pam)
		sshpam_cleanup();
#پایان_اگر

	طالما (waitpid(pmonitor->m_pid, &وضعیت, 0) == -1)
		إذا (errno != EINTR)
			خروج(1);

	res = WIFEXITED(وضعیت) ? WEXITSTATUS(وضعیت) : 1;

	/* Terminate process */
	خروج(res);
}

#اگر_تعریف_شده SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
صحيح
mm_answer_audit_event(بنية ssh *ssh, صحيح socket, بنية sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	صحيح r;

	debug3_f("entering");

	إذا ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	بدل (event) {
	حالة SSH_AUTH_FAIL_PUBKEY:
	حالة SSH_AUTH_FAIL_HOSTBASED:
	حالة SSH_AUTH_FAIL_GSSAPI:
	حالة SSH_LOGIN_EXCEED_MAXTRIES:
	حالة SSH_LOGIN_ریشه_DENIED:
	حالة SSH_CONNECTION_CLOSE:
	حالة SSH_INVALID_USER:
		audit_event(ssh, event);
		اكسر;
	افتراضي:
		fatal("Audit event type %d not permitted", event);
	}

	أرجع (0);
}

صحيح
mm_answer_audit_command(بنية ssh *ssh, صحيح socket, بنية sshbuf *m)
{
	حرف *cmd;
	صحيح r;

	debug3_f("entering");
	إذا ((r = sshbuf_get_cstring(m, &cmd, عدم)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_پیاپی_command(cmd);
	حرر(cmd);
	أرجع (0);
}
#پایان_اگر /* SSH_AUDIT_EVENTS */

فراغ
monitor_clear_keystate(بنية ssh *ssh, بنية monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, نما_درون);
	ssh_clear_newkeys(ssh, نما_بیرون);
	sshbuf_free(فرزند_state);
	فرزند_state = عدم;
}

فراغ
monitor_apply_keystate(بنية ssh *ssh, بنية monitor *pmonitor)
{
	بنية kex *kex;
	صحيح r;

	debug3_f("packet_set_state");
	إذا ((r = ssh_packet_مجموعه_state(ssh, فرزند_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(فرزند_state);
	فرزند_state = عدم;
	إذا ((kex = ssh->kex) == عدم)
		fatal_f("internal error: ssh->kex == NULL");
	إذا (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	إذا (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#اگر_تعریف_شده WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#پایان_اگر
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->بارگیری_host_عمومی_کلید=&get_hostkey_عمومی_by_type;
	kex->بارگیری_host_خصوصی_کلید=&get_hostkey_خصوصی_by_type;
	kex->host_کلید_شاخص=&get_hostkey_شاخص;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

فراغ
mm_get_keystate(بنية ssh *ssh, بنية monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	إذا ((فرزند_state = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    فرزند_state);
	debug3_f("GOT new keys");
}


/* XXX */

ساكن فراغ
monitor_openfds(بنية monitor *mon, صحيح do_logfds)
{
	صحيح pair[2];
#اگر_تعریف_شده SO_ZEROIZE
	صحيح on = 1;
#پایان_اگر

	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#اگر_تعریف_شده SO_ZEROIZE
	إذا (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, حجم(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	إذا (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, حجم(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#پایان_اگر
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	إذا (do_logfds) {
		إذا (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} وإلا
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

بنية monitor *
monitor_init(فراغ)
{
	بنية monitor *mon;

	mon = xcalloc(1, حجم(*mon));
	monitor_openfds(mon, 1);

	أرجع mon;
}

فراغ
monitor_reinit(بنية monitor *mon)
{
	monitor_openfds(mon, 0);
}

صحيح
monitor_auth_attempted(فراغ)
{
	أرجع auth_attempted;
}

صحيح
monitor_invalid_user(فراغ)
{
	أرجع invalid_user;
}

#اگر_تعریف_شده GSSAPI
صحيح
mm_answer_gss_راهاندازی_ctx(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	اندازه_t len;
	u_char *p;
	صحيح r;

	إذا (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	إذا ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.درازی = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	حرر(goid.elements);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	أرجع (0);
}

صحيح
mm_answer_gss_accept_ctx(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	gss_میانگیر_desc درون;
	gss_میانگیر_desc بیرون = GSS_C_خالی_میانگیر;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	صحيح r;

	إذا (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	إذا ((r = ssh_gssapi_get_میانگیر_desc(m, &درون)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &درون, &بیرون, &flags);
	حرر(درون.مقدار);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, بیرون.مقدار, بیرون.درازی)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_میانگیر(&minor, &بیرون);

	إذا (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	أرجع (0);
}

صحيح
mm_answer_gss_checkmic(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	gss_میانگیر_desc gssbuf, mic;
	OM_uint32 ret;
	صحيح r;

	إذا (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	إذا ((r = ssh_gssapi_get_میانگیر_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_میانگیر_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	حرر(gssbuf.مقدار);
	حرر(mic.مقدار);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	إذا (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	أرجع (0);
}

صحيح
mm_answer_gss_userok(بنية ssh *ssh, صحيح sock, بنية sshbuf *m)
{
	صحيح r, authenticated;
	ثابت حرف *displayname;

	إذا (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	إذا ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_روش = "gssapi-with-mic";

	إذا ((displayname = ssh_gssapi_displayname()) != عدم)
		auth2_رکورد_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	أرجع (authenticated);
}
#پایان_اگر /* GSSAPI */

