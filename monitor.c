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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/tree.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/dh.h>
#यदि_अन्तः

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"
#अन्तर्भाव "sshlogin.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "monitor.h"
#यदि_परिभाषितम् GSSAPI
#अन्तर्भाव "ssh-gss.h"
#यदि_अन्तः
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "monitor_fdpass.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "srclimit.h"

#यदि_परिभाषितम् GSSAPI
स्थिर Gssctxt *gsscontext = रिक्त;
#यदि_अन्तः

/* Imports */
बाह्य ServerOptions options;
बाह्य u_int utmp_len;
बाह्य संरचना sshbuf *cfg;
बाह्य संरचना sshbuf *loginmsg;
बाह्य संरचना include_list includes;
बाह्य संरचना sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
स्थिर संरचना sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

पूर्णाङ्क mm_answer_moduli(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_setcompat(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_sign(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pwnamallow(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_auth2_read_banner(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_authserv(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_authpassword(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_bsdauthquery(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_bsdauthrespond(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_keyallowed(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_keyverify(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pty(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pty_cleanup(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_पदांशः(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_state(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);

#यदि_परिभाषितम् USE_PAM
पूर्णाङ्क mm_answer_pam_start(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pam_account(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pam_init_ctx(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pam_query(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pam_respond(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_pam_free_ctx(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
#यदि_अन्तः

#यदि_परिभाषितम् GSSAPI
पूर्णाङ्क mm_answer_gss_सज्जता_ctx(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_gss_accept_ctx(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_gss_userok(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_gss_checkmic(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
#यदि_अन्तः

#यदि_परिभाषितम् SSH_AUDIT_EVENTS
पूर्णाङ्क mm_answer_audit_event(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
पूर्णाङ्क mm_answer_audit_command(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
#यदि_अन्तः

स्थिर Authctxt *authctxt;

/* local state for key verify */
स्थिर u_char *कुञ्चिका_blob = रिक्त;
स्थिर आकार_t कुञ्चिका_bloblen = 0;
स्थिर u_int कुञ्चिका_blobtype = MM_NOKEY;
स्थिर संरचना sshauthopt *कुञ्चिका_opts = रिक्त;
स्थिर वर्ण *hostbased_cuser = रिक्त;
स्थिर वर्ण *hostbased_chost = रिक्त;
स्थिर वर्ण *auth_विधानम् = "unknown";
स्थिर वर्ण *auth_submethod = रिक्त;
स्थिर u_int session_id2_len = 0;
स्थिर u_char *session_id2 = रिक्त;
स्थिर pid_t monitor_child_pid;
स्थिर पूर्णाङ्क auth_attempted = 0;
स्थिर पूर्णाङ्क invalid_user = 0;
स्थिर पूर्णाङ्क compat_समुच्चयः = 0;

संरचना mon_सारणी {
	गणना monitor_reqtype type;
	पूर्णाङ्क flags;
	पूर्णाङ्क (*f)(संरचना ssh *, पूर्णाङ्क, संरचना sshbuf *);
};

#परिभाषय MON_ISAUTH	0x0004	/* Required for Authentication */
#परिभाषय MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#परिभाषय MON_ONCE	0x0010	/* Disable after calling */
#परिभाषय MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#परिभाषय MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#परिभाषय MON_PERMIT	0x1000	/* Request is permitted */

स्थिर पूर्णाङ्क monitor_read(संरचना ssh *, संरचना monitor *, संरचना mon_सारणी *,
    संरचना mon_सारणी **);
स्थिर पूर्णाङ्क monitor_read_log(संरचना monitor *);

संरचना mon_सारणी mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#यदि_परिभाषितम् WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#यदि_अन्तः
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#यदि_परिभाषितम् USE_PAM
    {MONITOR_REQ_PAM_START, MON_ONCE, mm_answer_pam_start},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#यदि_अन्तः
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#यदि_अन्तः
#यदि_परिभाषितम् BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#यदि_अन्तः
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#यदि_परिभाषितम् GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_सज्जता_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#यदि_अन्तः
    {0, 0, रिक्त}
};

संरचना mon_सारणी mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#यदि_परिभाषितम् WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#यदि_अन्तः
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_पदांशः, 0, mm_answer_पदांशः},
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#यदि_अन्तः
    {0, 0, रिक्त}
};

संरचना mon_सारणी *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
स्थिर शून्य
monitor_permit(संरचना mon_सारणी *ent, गणना monitor_reqtype type, पूर्णाङ्क permit)
{
	यावत् (ent->f != रिक्त) {
		यदि (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			प्रत्यागम;
		}
		ent++;
	}
}

स्थिर शून्य
monitor_permit_authentications(पूर्णाङ्क permit)
{
	संरचना mon_सारणी *ent = mon_dispatch;

	यावत् (ent->f != रिक्त) {
		यदि (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

शून्य
monitor_child_preauth(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	संरचना mon_सारणी *ent;
	पूर्णाङ्क स्थितिः, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	यदि (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	यदि (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	स्मृतिं_पूरय(authctxt, 0, परिमाण(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	यावत् (!authenticated) {
		partial = 0;
		auth_विधानम् = "unknown";
		auth_submethod = रिक्त;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		यदि ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		यदि (options.अङ्कः_auth_methods != 0) {
			यदि (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_विधानम्, auth_submethod)) {
				debug3_f("method %s: partial", auth_विधानम्);
				authenticated = 0;
				partial = 1;
			}
		}

		यदि (authenticated) {
			यदि (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			यदि (authctxt->pw->pw_uid == 0 &&
			    !auth_मूलम्_allowed(ssh, auth_विधानम्))
				authenticated = 0;
#यदि_परिभाषितम् USE_PAM
			/* PAM needs to perform account checks after auth */
			यदि (options.use_pam && authenticated) {
				संरचना sshbuf *m;

				यदि ((m = sshbuf_new()) == रिक्त)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#यदि_अन्तः
		}
		यदि (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_विधानम्, auth_submethod);
			यदि (!partial && !authenticated)
				authctxt->failures++;
			यदि (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_विधानम्, auth_submethod);
			}
		}
		यदि (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	यदि (!authctxt->valid)
		fatal_f("authenticated invalid user");
	यदि (वाक्यं_तुलय(auth_विधानम्, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = रिक्त;
	ssh_packet_समुच्चयः_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	यावत् (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	यावत् (waitpid(pmonitor->m_pid, &स्थितिः, 0) == -1) {
		यदि (errno == EINTR)
			अनुवर्त;
		fatal_f("waitpid: %s", strerror(errno));
	}
	यदि (WIFEXITED(स्थितिः)) {
		यदि (WEXITSTATUS(स्थितिः) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (दीर्घ)pmonitor->m_pid, WEXITSTATUS(स्थितिः));
	} अन्यथा यदि (WIFSIGNALED(स्थितिः)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (दीर्घ)pmonitor->m_pid, WTERMSIG(स्थितिः));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (दीर्घ)pmonitor->m_pid);

	यदि (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	यदि (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

स्थिर शून्य
monitor_समुच्चयः_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

स्थिर शून्य
monitor_child_handler(पूर्णाङ्क sig)
{
	kill(monitor_child_pid, sig);
}

शून्य
monitor_child_postauth(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	close(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_समुच्चयः_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(SIGTERM, &monitor_child_handler);
	ssh_signal(SIGINT, &monitor_child_handler);
#यदि_परिभाषितम् SIGXFSZ
	ssh_signal(SIGXFSZ, SIG_IGN);
#यदि_अन्तः

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_पदांशः, 1);

	यदि (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	प्रति (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, रिक्त);
}

स्थिर पूर्णाङ्क
monitor_read_log(संरचना monitor *pmonitor)
{
	संरचना sshbuf *logmsg;
	u_int len, level, forced;
	वर्ण *सन्देशः;
	u_char *p;
	पूर्णाङ्क r;

	यदि ((logmsg = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	/* Read length */
	यदि ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	यदि (atomicio(पठ, pmonitor->m_log_recvfd, p, 4) != 4) {
		यदि (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			प्रत्यागम -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	यदि ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	यदि (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	यदि ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	यदि (atomicio(पठ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	यदि ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &सन्देशः, रिक्त)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	यदि (log_level_name(level) == रिक्त)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", सन्देशः,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	मुक्त(सन्देशः);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
monitor_read(संरचना ssh *ssh, संरचना monitor *pmonitor, संरचना mon_सारणी *ent,
    संरचना mon_सारणी **pent)
{
	संरचना sshbuf *m;
	पूर्णाङ्क r, ret;
	u_char type;
	संरचना pollfd pfd[2];

	प्रति (;;) {
		स्मृतिं_पूरय(&pfd, 0, परिमाण(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		यदि (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			यदि (errno == EINTR || errno == EAGAIN)
				अनुवर्त;
			fatal_f("poll: %s", strerror(errno));
		}
		यदि (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			अनुवर्त;
		}
		यदि (pfd[0].revents)
			भङ्ग;  /* Continues below */
	}

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	यदि ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	यावत् (ent->f != रिक्त) {
		यदि (ent->type == type)
			भङ्ग;
		ent++;
	}

	यदि (ent->f != रिक्त) {
		यदि (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		यदि (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		यदि (pent != रिक्त)
			*pent = ent;

		प्रत्यागम ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	प्रत्यागम (-1);
}

/* allowed key state */
स्थिर पूर्णाङ्क
monitor_allowed_कुञ्चिका(ध्रुव u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	यदि (कुञ्चिका_blob == रिक्त || कुञ्चिका_bloblen != bloblen ||
	    timingsafe_bcmp(कुञ्चिका_blob, blob, कुञ्चिका_bloblen))
		प्रत्यागम (0);
	प्रत्यागम (1);
}

स्थिर शून्य
monitor_reset_कुञ्चिका_state(शून्य)
{
	/* reset state */
	मुक्त(कुञ्चिका_blob);
	मुक्त(hostbased_cuser);
	मुक्त(hostbased_chost);
	sshauthopt_free(कुञ्चिका_opts);
	कुञ्चिका_blob = रिक्त;
	कुञ्चिका_bloblen = 0;
	कुञ्चिका_blobtype = MM_NOKEY;
	कुञ्चिका_opts = रिक्त;
	hostbased_cuser = रिक्त;
	hostbased_chost = रिक्त;
}

पूर्णाङ्क
mm_answer_state(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *अप्रयुक्तम्)
{
	संरचना sshbuf *m = रिक्त, *config = रिक्त, *hostkeys = रिक्त;
	संरचना sshbuf *opts = रिक्त, *confdata = रिक्त;
	पूर्णाङ्क postauth;
	पूर्णाङ्क r;

	debug_f("config len %zu", sshbuf_len(cfg));

	यदि ((m = sshbuf_new()) == रिक्त ||
	    (config = sshbuf_new()) == रिक्त ||
	    (opts = sshbuf_new()) == रिक्त ||
	    (confdata = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	यदि ((r = serialise_server_options(&options, &config)) != 0)
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
	यदि ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_संस्करणम्)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	यदि (postauth) {
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

	प्रत्यागम (0);
}

#यदि_परिभाषितम् WITH_OPENSSL
पूर्णाङ्क
mm_answer_moduli(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	DH *dh;
	ध्रुव BIGNUM *dh_p, *dh_g;
	पूर्णाङ्क r;
	u_int min, want, max;

	यदि ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	यदि (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = वृणु_dh(min, want, max);
	यदि (dh == रिक्त) {
		यदि ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} अन्यथा {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, रिक्त, &dh_g);
		यदि ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	प्रत्यागम (0);
}
#यदि_अन्तः

पूर्णाङ्क
mm_answer_setcompat(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_समुच्चयः = 1;

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_sign(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	बाह्य पूर्णाङ्क auth_sock;			/* XXX move to state struct? */
	संरचना sshkey *pubkey, *कुञ्चिका;
	संरचना sshbuf *sigbuf = रिक्त;
	u_char *p = रिक्त, *signature = रिक्त;
	वर्ण *alg = रिक्त;
	आकार_t datlen, siglen;
	पूर्णाङ्क r, is_proof = 0, keyid;
	u_int compat;
	ध्रुव वर्ण proof_req[] = "hostkeys-prove-00@openssh.com";
	स्थिर पूर्णाङ्क nhostkey_proofs_समाप्तम्, *hostkey_proofs_समाप्तम्;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	यदि (!compat_समुच्चयः)
		fatal_f("state error: setcompat never called");

	यदि ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	यदि ((keyid = get_hostkey_सूचकांक(pubkey, 1, ssh)) == -1)
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
	यदि (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		यदि (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		यदि ((कुञ्चिका = get_hostkey_लौकिकम्_by_सूचकांक(keyid, ssh)) == रिक्त)
			fatal_f("no hostkey for index %d", keyid);
		यदि (keyid >= nhostkey_proofs_समाप्तम्) {
			hostkey_proofs_समाप्तम् = xrecallocarray(
			    hostkey_proofs_समाप्तम्, nhostkey_proofs_समाप्तम्,
			    keyid + 1, परिमाण(*hostkey_proofs_समाप्तम्));
			nhostkey_proofs_समाप्तम् = keyid + 1;
		}
		यदि (hostkey_proofs_समाप्तम्[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(कुञ्चिका), keyid);
		}
		hostkey_proofs_समाप्तम्[keyid] = 1;
		यदि ((sigbuf = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
		यदि ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(कुञ्चिका, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		यदि (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	यदि (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		स्मृतिं_प्रतिलिख(session_id2, p, session_id2_len);
	}

	यदि ((कुञ्चिका = get_hostkey_by_सूचकांक(keyid)) != रिक्त) {
		यदि ((r = sshkey_sign(कुञ्चिका, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, रिक्त, compat)) != 0)
			fatal_fr(r, "sign");
	} अन्यथा यदि ((कुञ्चिका = get_hostkey_लौकिकम्_by_सूचकांक(keyid, ssh)) != रिक्त &&
	    auth_sock > 0) {
		यदि ((r = ssh_agent_sign(auth_sock, कुञ्चिका, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} अन्यथा
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	मुक्त(alg);
	मुक्त(p);
	मुक्त(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	प्रत्यागम (0);
}

#परिभाषय PUTPW(b, id) \
	कुरु { \
		यदि ((r = sshbuf_put_string(b, \
		    &pwent->id, परिमाण(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} यावत् (0)

शून्य
mm_encode_server_options(संरचना sshbuf *m)
{
	पूर्णाङ्क r;
	संरचना sshbuf *config;

	यदि ((config = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	यदि ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
पूर्णाङ्क
mm_answer_pwnamallow(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	संरचना passwd *pwent;
	पूर्णाङ्क r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	यदि (!compat_समुच्चयः)
		fatal_f("state error: setcompat never called");

	यदि (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	यदि ((r = sshbuf_get_cstring(m, &authctxt->user, रिक्त)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	यदि (pwent == रिक्त) {
		invalid_user = 1;
		यदि ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		गच्छ बहिर्गमनम्;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	यदि ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#यदि_परिभाषितम् HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#यदि_अन्तः
	यदि ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#यदि_परिभाषितम् HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#यदि_अन्तः
#यदि_परिभाषितम् HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#यदि_अन्तः
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 बहिर्गमनम्:
	ssh_packet_समुच्चयः_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	यदि (options.refuse_connection) {
		logit("administratively prohibited connection for "
		    "%s%s from %.128s port %d",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user, ssh_remote_ipaddr(ssh),
		    ssh_remote_पत्तनम्(ssh));
		cleanup_exit(EXIT_CONFIG_REFUSED);
	}

	/* Send active options to unpriv */
	mm_encode_server_options(m);

	/* Create valid auth method lists */
	यदि (auth2_सज्जता_methods_lists(authctxt) != 0) {
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

#यदि_परिभाषितम् USE_PAM
	यदि (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#यदि_अन्तः

	प्रत्यागम (0);
}

पूर्णाङ्क mm_answer_auth2_read_banner(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	वर्ण *banner;
	पूर्णाङ्क r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	यदि ((r = sshbuf_put_cstring(m, banner != रिक्त ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	मुक्त(banner);

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_authserv(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	monitor_permit_authentications(1);

	यदि ((r = sshbuf_get_cstring(m, &authctxt->service, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	यदि (वाक्यदैर्घ्यम्(authctxt->style) == 0) {
		मुक्त(authctxt->style);
		authctxt->style = रिक्त;
	}

	प्रत्यागम (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
स्थिर पूर्णाङ्क
कुञ्चिका_आधारः_type_मेलनम्(ध्रुव वर्ण *विधानम्, ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव वर्ण *list)
{
	वर्ण *s, *l, *ol = xstrdup(list);
	पूर्णाङ्क प्राप्तम् = 0;

	l = ol;
	प्रति ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		यदि (sshkey_type_from_name(s) == कुञ्चिका->type) {
			प्राप्तम् = 1;
			भङ्ग;
		}
	}
	यदि (!प्राप्तम्) {
		error("%s key type %s is not in permitted list %s", विधानम्,
		    sshkey_ssh_name(कुञ्चिका), list);
	}

	मुक्त(ol);
	प्रत्यागम प्राप्तम्;
}

पूर्णाङ्क
mm_answer_authpassword(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	स्थिर पूर्णाङ्क call_गणनम्;
	वर्ण *passwd;
	पूर्णाङ्क r, authenticated;
	आकार_t plen;

	यदि (!options.password_authentication)
		fatal_f("password authentication not enabled");
	यदि ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#यदि_परिभाषितम् USE_PAM
	यदि ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#यदि_अन्तः

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_गणनम्++;
	यदि (plen == 0 && call_गणनम् == 1)
		auth_विधानम् = "none";
	अन्यथा
		auth_विधानम् = "password";

	/* Causes monitor loop to terminate if authenticated */
	प्रत्यागम (authenticated);
}

#यदि_परिभाषितम् BSD_AUTH
पूर्णाङ्क
mm_answer_bsdauthquery(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	वर्ण *name, *infotxt;
	u_int numprompts, *echo_on, success;
	वर्ण **prompts;
	पूर्णाङ्क r;

	यदि (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	यदि (success) {
		यदि ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	यदि (success) {
		मुक्त(name);
		मुक्त(infotxt);
		मुक्त(prompts);
		मुक्त(echo_on);
	}

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_bsdauthrespond(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	वर्ण *response;
	पूर्णाङ्क r, authok;

	यदि (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	यदि (authctxt->as == रिक्त)
		fatal_f("no bsd auth session");

	यदि ((r = sshbuf_get_cstring(m, &response, रिक्त)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = रिक्त;
	debug3_f("<%s> = <%d>", response, authok);
	मुक्त(response);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_विधानम् = "keyboard-interactive";
	auth_submethod = "bsdauth";

	प्रत्यागम (authok != 0);
}
#यदि_अन्तः

#यदि_परिभाषितम् USE_PAM
पूर्णाङ्क
mm_answer_pam_start(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	यदि (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	यदि (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_pam_account(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	u_int ret;
	पूर्णाङ्क r;

	यदि (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	यदि ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	प्रत्यागम (ret);
}

स्थिर शून्य *sshpam_ctxt, *sshpam_authok;
बाह्य KbdintDevice sshpam_device;

पूर्णाङ्क
mm_answer_pam_init_ctx(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	u_int ok = 0;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	यदि (sshpam_ctxt != रिक्त)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = रिक्त;
	sshbuf_reset(m);
	यदि (sshpam_ctxt != रिक्त) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	यदि ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_pam_query(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	वर्ण *name = रिक्त, *info = रिक्त, **prompts = रिक्त;
	u_int i, अङ्कः = 0, *echo_on = 0;
	पूर्णाङ्क r, ret;

	debug3_f("entering");
	sshpam_authok = रिक्त;
	यदि (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &अङ्कः, &prompts, &echo_on);
	यदि (ret == 0 && अङ्कः == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	यदि (अङ्कः > 1 || name == रिक्त || info == रिक्त)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, अङ्कः)) != 0)
		fatal_fr(r, "buffer error");
	मुक्त(name);
	मुक्त(info);
	प्रति (i = 0; i < अङ्कः; ++i) {
		यदि ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(prompts[i]);
	}
	मुक्त(prompts);
	मुक्त(echo_on);
	auth_विधानम् = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_pam_respond(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	वर्ण **resp;
	u_int i, अङ्कः;
	पूर्णाङ्क r, ret;

	debug3_f("entering");
	यदि (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	sshpam_authok = रिक्त;
	यदि ((r = sshbuf_get_u32(m, &अङ्कः)) != 0)
		fatal_fr(r, "buffer error");
	यदि (अङ्कः > PAM_MAX_अङ्कः_सन्देशः) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    अङ्कः, (अचिह्नित)PAM_MAX_अङ्कः_सन्देशः);
	}
	यदि (अङ्कः > 0) {
		resp = xcalloc(अङ्कः, परिमाण(वर्ण *));
		प्रति (i = 0; i < अङ्कः; ++i) {
			यदि ((r = sshbuf_get_cstring(m, &(resp[i]), रिक्त)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, अङ्कः, resp);
		प्रति (i = 0; i < अङ्कः; ++i)
			मुक्त(resp[i]);
		मुक्त(resp);
	} अन्यथा {
		ret = (sshpam_device.respond)(sshpam_ctxt, अङ्कः, रिक्त);
	}
	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_विधानम् = "keyboard-interactive";
	auth_submethod = "pam";
	यदि (ret == 0)
		sshpam_authok = sshpam_ctxt;
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_pam_free_ctx(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	पूर्णाङ्क r = sshpam_authok != रिक्त && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	यदि (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = रिक्त;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_विधानम् = "keyboard-interactive";
	auth_submethod = "pam";
	प्रत्यागम r;
}
#यदि_अन्तः

पूर्णाङ्क
mm_answer_keyallowed(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	वर्ण *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	पूर्णाङ्क r, allowed = 0;
	संरचना sshauthopt *opts = रिक्त;

	debug3_f("entering");
	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, रिक्त)) != 0 ||
	    (r = sshkey_froms(m, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	यदि (कुञ्चिका != रिक्त && authctxt->valid) {
		विकल्प (type) {
		पक्ष MM_USERKEY:
			auth_विधानम् = "publickey";
			यदि (!options.pubkey_authentication)
				भङ्ग;
			यदि (auth2_कुञ्चिका_already_प्रयुक्तम्(authctxt, कुञ्चिका))
				भङ्ग;
			यदि (!कुञ्चिका_आधारः_type_मेलनम्(auth_विधानम्, कुञ्चिका,
			    options.pubkey_accepted_algos))
				भङ्ग;
			allowed = user_कुञ्चिका_allowed(ssh, authctxt->pw, कुञ्चिका,
			    pubkey_auth_attempt, &opts);
			भङ्ग;
		पक्ष MM_HOSTKEY:
			auth_विधानम् = "hostbased";
			यदि (!options.hostbased_authentication)
				भङ्ग;
			यदि (auth2_कुञ्चिका_already_प्रयुक्तम्(authctxt, कुञ्चिका))
				भङ्ग;
			यदि (!कुञ्चिका_आधारः_type_मेलनम्(auth_विधानम्, कुञ्चिका,
			    options.hostbased_accepted_algos))
				भङ्ग;
			allowed = hostbased_कुञ्चिका_allowed(ssh, authctxt->pw,
			    cuser, chost, कुञ्चिका);
			auth2_लेखः_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			भङ्ग;
		स्वभाव:
			fatal_f("unknown key type %u", type);
			भङ्ग;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_विधानम्,
	    pubkey_auth_attempt ? "" : " test",
	    (कुञ्चिका == रिक्त || !authctxt->valid) ? "invalid" : sshkey_type(कुञ्चिका),
	    allowed ? "allowed" : "not allowed");

	auth2_लेखः_कुञ्चिका(authctxt, 0, कुञ्चिका);

	/* clear temporarily storage (used by verify) */
	monitor_reset_कुञ्चिका_state();

	यदि (allowed) {
		/* Save temporarily for comparison in verify */
		यदि ((r = sshkey_गन्तव्यम्_blob(कुञ्चिका, &कुञ्चिका_blob, &कुञ्चिका_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		कुञ्चिका_blobtype = type;
		कुञ्चिका_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} अन्यथा {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_विधानम्, रिक्त);
		मुक्त(cuser);
		मुक्त(chost);
	}
	sshkey_free(कुञ्चिका);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	यदि (opts != रिक्त && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	यदि (!allowed)
		sshauthopt_free(opts);

	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
monitor_valid_userblob(संरचना ssh *ssh, ध्रुव u_char *दत्त, u_int datalen)
{
	संरचना sshbuf *b;
	संरचना sshkey *hostkey = रिक्त;
	ध्रुव u_char *p;
	वर्ण *userstyle, *cp;
	आकार_t len;
	u_char type;
	पूर्णाङ्क hostbound = 0, r, fail = 0;

	यदि ((b = sshbuf_from(दत्त, datalen)) == रिक्त)
		fatal_f("sshbuf_from");

	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	यदि ((session_id2 == रिक्त) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	यदि ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != SSH2_सन्देशः_USERAUTH_REQUEST)
		fail++;
	यदि ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	यदि (वाक्यं_तुलय(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	यदि ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse method");
	यदि (वाक्यं_तुलय("publickey", cp) != 0) {
		यदि (वाक्यं_तुलय("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		अन्यथा
			fail++;
	}
	मुक्त(cp);
	यदि ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	यदि (type == 0)
		fail++;
	यदि ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	यदि (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	यदि (hostkey != रिक्त) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		यदि (get_hostkey_सूचकांक(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	प्रत्यागम (fail == 0);
}

स्थिर पूर्णाङ्क
monitor_valid_hostbasedblob(ध्रुव u_char *दत्त, u_int datalen,
    ध्रुव वर्ण *cuser, ध्रुव वर्ण *chost)
{
	संरचना sshbuf *b;
	ध्रुव u_char *p;
	वर्ण *cp, *userstyle;
	आकार_t len;
	पूर्णाङ्क r, fail = 0;
	u_char type;

	यदि ((b = sshbuf_from(दत्त, datalen)) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	यदि ((session_id2 == रिक्त) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	यदि ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != SSH2_सन्देशः_USERAUTH_REQUEST)
		fail++;
	यदि ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	यदि (वाक्यं_तुलय(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	यदि ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse method");
	यदि (वाक्यं_तुलय(cp, "hostbased") != 0)
		fail++;
	मुक्त(cp);
	यदि ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	यदि ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse host");
	यदि (((len = वाक्यदैर्घ्यम्(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	यदि (वाक्यं_तुलय(cp, chost) != 0)
		fail++;
	मुक्त(cp);

	/* verify client user */
	यदि ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse ruser");
	यदि (वाक्यं_तुलय(cp, cuser) != 0)
		fail++;
	मुक्त(cp);

	यदि (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	प्रत्यागम (fail == 0);
}

पूर्णाङ्क
mm_answer_keyverify(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	संरचना sshkey *कुञ्चिका;
	ध्रुव u_char *signature, *दत्त, *blob;
	वर्ण *sigalg = रिक्त, *fp = रिक्त;
	आकार_t signaturelen, datalen, bloblen;
	पूर्णाङ्क r, ret, req_presence = 0, req_verify = 0, valid_दत्त = 0;
	पूर्णाङ्क encoded_ret;
	संरचना sshkey_sig_details *sig_details = रिक्त;

	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(m, &दत्त, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, रिक्त)) != 0)
		fatal_fr(r, "parse");

	यदि (hostbased_cuser == रिक्त || hostbased_chost == रिक्त ||
	  !monitor_allowed_कुञ्चिका(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	यदि (*sigalg == '\0') {
		मुक्त(sigalg);
		sigalg = रिक्त;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	यदि ((r = sshkey_from_blob(blob, bloblen, &कुञ्चिका)) != 0)
		fatal_fr(r, "parse key");

	विकल्प (कुञ्चिका_blobtype) {
	पक्ष MM_USERKEY:
		valid_दत्त = monitor_valid_userblob(ssh, दत्त, datalen);
		auth_विधानम् = "publickey";
		भङ्ग;
	पक्ष MM_HOSTKEY:
		valid_दत्त = monitor_valid_hostbasedblob(दत्त, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_विधानम् = "hostbased";
		भङ्ग;
	स्वभाव:
		valid_दत्त = 0;
		भङ्ग;
	}
	यदि (!valid_दत्त)
		fatal_f("bad %s signature data blob",
		    कुञ्चिका_blobtype == MM_USERKEY ? "userkey" :
		    (कुञ्चिका_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	यदि ((fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(कुञ्चिका, signature, signaturelen, दत्त, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_विधानम्,
	    sshkey_type(कुञ्चिका), sigalg == रिक्त ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	यदि (ret == 0 && कुञ्चिका_blobtype == MM_USERKEY && sig_details != रिक्त) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !कुञ्चिका_opts->no_require_user_presence;
		यदि (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(कुञ्चिका), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_पत्तनम्(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || कुञ्चिका_opts->require_verify;
		यदि (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(कुञ्चिका), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_पत्तनम्(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_लेखः_कुञ्चिका(authctxt, ret == 0, कुञ्चिका);

	यदि (कुञ्चिका_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, कुञ्चिका_opts);
	monitor_reset_कुञ्चिका_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	यदि ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != रिक्त)) != 0)
		fatal_fr(r, "assemble");
	यदि (sig_details != रिक्त) {
		यदि ((r = sshbuf_put_u32(m, sig_details->sk_गणक)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	मुक्त(sigalg);
	मुक्त(fp);
	sshkey_free(कुञ्चिका);

	प्रत्यागम ret == 0;
}

स्थिर शून्य
mm_लेखः_login(संरचना ssh *ssh, Session *s, संरचना passwd *pw)
{
	socklen_t fromlen;
	संरचना sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	स्मृतिं_पूरय(&from, 0, परिमाण(from));
	fromlen = परिमाण(from);
	यदि (ssh_packet_connection_is_on_socket(ssh)) {
		यदि (getpeername(ssh_packet_get_connection_अन्तर्(ssh),
		    (संरचना sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	लेखः_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (संरचना sockaddr *)&from, fromlen);
}

स्थिर शून्य
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (दीर्घ)s->pid);
	यदि (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_अप्रयुक्तम्(s->self);
}

पूर्णाङ्क
mm_answer_pty(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	बाह्य संरचना monitor *pmonitor;
	Session *s;
	पूर्णाङ्क r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	यदि (s == रिक्त)
		गच्छ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, परिमाण(s->tty));
	यदि (res == 0)
		गच्छ error;
	pty_setowner(authctxt->pw, s->tty);

	यदि ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	यदि (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_लेखः_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	यदि ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	यदि (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	यदि ((fd0 = उद्घाटय(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	यदि (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	प्रत्यागम (0);

 error:
	यदि (s != रिक्त)
		mm_session_close(s);
	यदि ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_pty_cleanup(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	Session *s;
	वर्ण *tty;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((r = sshbuf_get_cstring(m, &tty, रिक्त)) != 0)
		fatal_fr(r, "parse tty");
	यदि ((s = session_by_tty(tty)) != रिक्त)
		mm_session_close(s);
	sshbuf_reset(m);
	मुक्त(tty);
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_पदांशः(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *req)
{
	बाह्य संरचना monitor *pmonitor;
	पूर्णाङ्क res, स्थितिः;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#यदि_परिभाषितम् USE_PAM
	यदि (options.use_pam)
		sshpam_cleanup();
#यदि_अन्तः

	यावत् (waitpid(pmonitor->m_pid, &स्थितिः, 0) == -1)
		यदि (errno != EINTR)
			निर्गच्छ(1);

	res = WIFEXITED(स्थितिः) ? WEXITSTATUS(स्थितिः) : 1;

	/* Terminate process */
	निर्गच्छ(res);
}

#यदि_परिभाषितम् SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
पूर्णाङ्क
mm_answer_audit_event(संरचना ssh *ssh, पूर्णाङ्क socket, संरचना sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	विकल्प (event) {
	पक्ष SSH_AUTH_FAIL_PUBKEY:
	पक्ष SSH_AUTH_FAIL_HOSTBASED:
	पक्ष SSH_AUTH_FAIL_GSSAPI:
	पक्ष SSH_LOGIN_EXCEED_MAXTRIES:
	पक्ष SSH_LOGIN_मूलम्_DENIED:
	पक्ष SSH_CONNECTION_CLOSE:
	पक्ष SSH_INVALID_USER:
		audit_event(ssh, event);
		भङ्ग;
	स्वभाव:
		fatal("Audit event type %d not permitted", event);
	}

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_audit_command(संरचना ssh *ssh, पूर्णाङ्क socket, संरचना sshbuf *m)
{
	वर्ण *cmd;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि ((r = sshbuf_get_cstring(m, &cmd, रिक्त)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_सततम्_command(cmd);
	मुक्त(cmd);
	प्रत्यागम (0);
}
#यदि_अन्तः /* SSH_AUDIT_EVENTS */

शून्य
monitor_clear_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, बहुलकम्_अन्तर्);
	ssh_clear_newkeys(ssh, बहुलकम्_बहिर्गमनम्);
	sshbuf_free(child_state);
	child_state = रिक्त;
}

शून्य
monitor_apply_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	संरचना kex *kex;
	पूर्णाङ्क r;

	debug3_f("packet_set_state");
	यदि ((r = ssh_packet_समुच्चयः_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = रिक्त;
	यदि ((kex = ssh->kex) == रिक्त)
		fatal_f("internal error: ssh->kex == NULL");
	यदि (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	यदि (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#यदि_परिभाषितम् WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#यदि_अन्तः
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->आरोपय_host_लौकिकम्_कुञ्चिका=&get_hostkey_लौकिकम्_by_type;
	kex->आरोपय_host_वैयक्तिकम्_कुञ्चिका=&get_hostkey_वैयक्तिकम्_by_type;
	kex->host_कुञ्चिका_सूचकांक=&get_hostkey_सूचकांक;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

शून्य
mm_get_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	यदि ((child_state = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

स्थिर शून्य
monitor_openfds(संरचना monitor *mon, पूर्णाङ्क do_logfds)
{
	पूर्णाङ्क pair[2];
#यदि_परिभाषितम् SO_ZEROIZE
	पूर्णाङ्क on = 1;
#यदि_अन्तः

	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#यदि_परिभाषितम् SO_ZEROIZE
	यदि (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, परिमाण(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	यदि (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, परिमाण(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#यदि_अन्तः
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	यदि (do_logfds) {
		यदि (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} अन्यथा
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

संरचना monitor *
monitor_init(शून्य)
{
	संरचना monitor *mon;

	mon = xcalloc(1, परिमाण(*mon));
	monitor_openfds(mon, 1);

	प्रत्यागम mon;
}

शून्य
monitor_reinit(संरचना monitor *mon)
{
	monitor_openfds(mon, 0);
}

पूर्णाङ्क
monitor_auth_attempted(शून्य)
{
	प्रत्यागम auth_attempted;
}

पूर्णाङ्क
monitor_invalid_user(शून्य)
{
	प्रत्यागम invalid_user;
}

#यदि_परिभाषितम् GSSAPI
पूर्णाङ्क
mm_answer_gss_सज्जता_ctx(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	आकार_t len;
	u_char *p;
	पूर्णाङ्क r;

	यदि (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	यदि ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.दीर्घता = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	मुक्त(goid.elements);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_gss_accept_ctx(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	gss_बफर_desc अन्तर्;
	gss_बफर_desc बहिर्गमनम् = GSS_C_रिक्तानि_बफर;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	पूर्णाङ्क r;

	यदि (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	यदि ((r = ssh_gssapi_get_बफर_desc(m, &अन्तर्)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &अन्तर्, &बहिर्गमनम्, &flags);
	मुक्त(अन्तर्.मानम्);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, बहिर्गमनम्.मानम्, बहिर्गमनम्.दीर्घता)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_बफर(&minor, &बहिर्गमनम्);

	यदि (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_gss_checkmic(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	gss_बफर_desc gssbuf, mic;
	OM_uint32 ret;
	पूर्णाङ्क r;

	यदि (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	यदि ((r = ssh_gssapi_get_बफर_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_बफर_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	मुक्त(gssbuf.मानम्);
	मुक्त(mic.मानम्);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	यदि (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	प्रत्यागम (0);
}

पूर्णाङ्क
mm_answer_gss_userok(संरचना ssh *ssh, पूर्णाङ्क sock, संरचना sshbuf *m)
{
	पूर्णाङ्क r, authenticated;
	ध्रुव वर्ण *displayname;

	यदि (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	यदि ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_विधानम् = "gssapi-with-mic";

	यदि ((displayname = ssh_gssapi_displayname()) != रिक्त)
		auth2_लेखः_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	प्रत्यागम (authenticated);
}
#यदि_अन्तः /* GSSAPI */

