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

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/dh.h>
#endif

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
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "monitor_fdpass.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "srclimit.h"

#ifdef GSSAPI
स्थिर Gssctxt *gsscontext = रिक्त;
#endif

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

पूर्णांक mm_answer_moduli(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_setcompat(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_sign(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pwnamallow(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_auth2_read_banner(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_authserv(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_authpassword(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_bsdauthquery(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_bsdauthrespond(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_keyallowed(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_keyverify(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pty(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pty_cleanup(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_term(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_state(संरचना ssh *, पूर्णांक, संरचना sshbuf *);

#ifdef USE_PAM
पूर्णांक mm_answer_pam_start(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pam_account(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pam_init_ctx(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pam_query(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pam_respond(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_pam_free_ctx(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
#endif

#ifdef GSSAPI
पूर्णांक mm_answer_gss_setup_ctx(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_gss_accept_ctx(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_gss_userok(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_gss_checkmic(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
पूर्णांक mm_answer_audit_event(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
पूर्णांक mm_answer_audit_command(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
#endif

स्थिर Authctxt *authctxt;

/* local state for key verify */
स्थिर u_char *किल्ली_blob = रिक्त;
स्थिर माप_प्रकार किल्ली_bloblen = 0;
स्थिर u_int किल्ली_blobtype = MM_NOKEY;
स्थिर संरचना sshauthopt *किल्ली_opts = रिक्त;
स्थिर अक्षर *hostbased_cuser = रिक्त;
स्थिर अक्षर *hostbased_chost = रिक्त;
स्थिर अक्षर *auth_method = "unknown";
स्थिर अक्षर *auth_submethod = रिक्त;
स्थिर u_int session_id2_len = 0;
स्थिर u_char *session_id2 = रिक्त;
स्थिर pid_t monitor_child_pid;
स्थिर पूर्णांक auth_attempted = 0;
स्थिर पूर्णांक invalid_user = 0;
स्थिर पूर्णांक compat_set = 0;

संरचना mon_table {
	गणना monitor_reqtype type;
	पूर्णांक flags;
	पूर्णांक (*f)(संरचना ssh *, पूर्णांक, संरचना sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

स्थिर पूर्णांक monitor_read(संरचना ssh *, संरचना monitor *, संरचना mon_table *,
    संरचना mon_table **);
स्थिर पूर्णांक monitor_read_log(संरचना monitor *);

संरचना mon_table mon_dispatch_proto20[] = {
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
    {0, 0, रिक्त}
};

संरचना mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, रिक्त}
};

संरचना mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
स्थिर शून्य
monitor_permit(संरचना mon_table *ent, गणना monitor_reqtype type, पूर्णांक permit)
{
	पर्यंत (ent->f != रिक्त) {
		जर (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			परत;
		}
		ent++;
	}
}

स्थिर शून्य
monitor_permit_authentications(पूर्णांक permit)
{
	संरचना mon_table *ent = mon_dispatch;

	पर्यंत (ent->f != रिक्त) {
		जर (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

शून्य
monitor_child_preauth(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	संरचना mon_table *ent;
	पूर्णांक status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	जर (pmonitor->m_recvfd >= 0)
		बंद(pmonitor->m_recvfd);
	जर (pmonitor->m_log_sendfd >= 0)
		बंद(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	स_रखो(authctxt, 0, आकार(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	पर्यंत (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = रिक्त;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		जर ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		जर (options.अंक_auth_methods != 0) {
			जर (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		जर (authenticated) {
			जर (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			जर (authctxt->pw->pw_uid == 0 &&
			    !auth_मूळ_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			जर (options.use_pam && authenticated) {
				संरचना sshbuf *m;

				जर ((m = sshbuf_new()) == रिक्त)
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
		जर (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			जर (!partial && !authenticated)
				authctxt->failures++;
			जर (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		जर (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	जर (!authctxt->valid)
		fatal_f("authenticated invalid user");
	जर (म_भेद(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = रिक्त;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	पर्यंत (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	पर्यंत (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		जर (त्रुटि_सं == EINTR)
			सुरूठेवा;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	जर (WIFEXITED(status)) {
		जर (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (दीर्घ)pmonitor->m_pid, WEXITSTATUS(status));
	} अन्यथा जर (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (दीर्घ)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (दीर्घ)pmonitor->m_pid);

	जर (pmonitor->m_recvfd >= 0)
		बंद(pmonitor->m_recvfd);
	जर (pmonitor->m_log_sendfd >= 0)
		बंद(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

स्थिर शून्य
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

स्थिर शून्य
monitor_child_handler(पूर्णांक sig)
{
	समाप्त(monitor_child_pid, sig);
}

शून्य
monitor_child_postauth(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	बंद(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(संक_इति, &monitor_child_handler);
	ssh_signal(संक_विघ्न, &monitor_child_handler);
#ifdef SIGXFSZ
	ssh_signal(SIGXFSZ, संक_छोड़ो);
#endif

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

	जर (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	साठी (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, रिक्त);
}

स्थिर पूर्णांक
monitor_read_log(संरचना monitor *pmonitor)
{
	संरचना sshbuf *logmsg;
	u_int len, level, forced;
	अक्षर *संदेश;
	u_char *p;
	पूर्णांक r;

	जर ((logmsg = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	/* Read length */
	जर ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	जर (atomicio(पठ, pmonitor->m_log_recvfd, p, 4) != 4) {
		जर (त्रुटि_सं == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			बंद(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			परत -1;
		}
		fatal_f("log fd read: %s", म_त्रुटि(त्रुटि_सं));
	}
	जर ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	जर (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	जर ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	जर (atomicio(पठ, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", म_त्रुटि(त्रुटि_सं));
	जर ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &संदेश, रिक्त)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	जर (log_level_name(level) == रिक्त)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", संदेश,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	मुक्त(संदेश);

	परत 0;
}

स्थिर पूर्णांक
monitor_read(संरचना ssh *ssh, संरचना monitor *pmonitor, संरचना mon_table *ent,
    संरचना mon_table **pent)
{
	संरचना sshbuf *m;
	पूर्णांक r, ret;
	u_char type;
	संरचना pollfd pfd[2];

	साठी (;;) {
		स_रखो(&pfd, 0, आकार(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		जर (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			जर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				सुरूठेवा;
			fatal_f("poll: %s", म_त्रुटि(त्रुटि_सं));
		}
		जर (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			सुरूठेवा;
		}
		जर (pfd[0].revents)
			थांबा;  /* Continues below */
	}

	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	जर ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	पर्यंत (ent->f != रिक्त) {
		जर (ent->type == type)
			थांबा;
		ent++;
	}

	जर (ent->f != रिक्त) {
		जर (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		जर (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		जर (pent != रिक्त)
			*pent = ent;

		परत ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	परत (-1);
}

/* allowed key state */
स्थिर पूर्णांक
monitor_allowed_किल्ली(स्थिरांक u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	जर (किल्ली_blob == रिक्त || किल्ली_bloblen != bloblen ||
	    timingsafe_bcmp(किल्ली_blob, blob, किल्ली_bloblen))
		परत (0);
	परत (1);
}

स्थिर शून्य
monitor_reset_किल्ली_state(शून्य)
{
	/* reset state */
	मुक्त(किल्ली_blob);
	मुक्त(hostbased_cuser);
	मुक्त(hostbased_chost);
	sshauthopt_free(किल्ली_opts);
	किल्ली_blob = रिक्त;
	किल्ली_bloblen = 0;
	किल्ली_blobtype = MM_NOKEY;
	किल्ली_opts = रिक्त;
	hostbased_cuser = रिक्त;
	hostbased_chost = रिक्त;
}

पूर्णांक
mm_answer_state(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *unused)
{
	संरचना sshbuf *m = रिक्त, *config = रिक्त, *hostkeys = रिक्त;
	संरचना sshbuf *opts = रिक्त, *confdata = रिक्त;
	पूर्णांक postauth;
	पूर्णांक r;

	debug_f("config len %zu", sshbuf_len(cfg));

	जर ((m = sshbuf_new()) == रिक्त ||
	    (config = sshbuf_new()) == रिक्त ||
	    (opts = sshbuf_new()) == रिक्त ||
	    (confdata = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	जर ((r = serialise_server_options(&options, &config)) != 0)
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
	जर ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	जर (postauth) {
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

	परत (0);
}

#ifdef WITH_OPENSSL
पूर्णांक
mm_answer_moduli(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	DH *dh;
	स्थिरांक BIGNUM *dh_p, *dh_g;
	पूर्णांक r;
	u_int min, want, max;

	जर ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	जर (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	जर (dh == रिक्त) {
		जर ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} अन्यथा {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, रिक्त, &dh_g);
		जर ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	परत (0);
}
#endif

पूर्णांक
mm_answer_setcompat(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	पूर्णांक r;

	debug3_f("entering");

	जर ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	परत (0);
}

पूर्णांक
mm_answer_sign(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	बाह्य पूर्णांक auth_sock;			/* XXX move to state struct? */
	संरचना sshkey *pubkey, *किल्ली;
	संरचना sshbuf *sigbuf = रिक्त;
	u_char *p = रिक्त, *signature = रिक्त;
	अक्षर *alg = रिक्त;
	माप_प्रकार datlen, siglen;
	पूर्णांक r, is_proof = 0, keyid;
	u_int compat;
	स्थिरांक अक्षर proof_req[] = "hostkeys-prove-00@openssh.com";
	स्थिर पूर्णांक nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	जर (!compat_set)
		fatal_f("state error: setcompat never called");

	जर ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	जर ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	जर (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		जर (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		जर ((किल्ली = get_hostkey_public_by_index(keyid, ssh)) == रिक्त)
			fatal_f("no hostkey for index %d", keyid);
		जर (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, आकार(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		जर (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(किल्ली), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		जर ((sigbuf = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
		जर ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(किल्ली, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		जर (datlen != sshbuf_len(sigbuf) ||
		    स_भेद(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	जर (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		स_नकल(session_id2, p, session_id2_len);
	}

	जर ((किल्ली = get_hostkey_by_index(keyid)) != रिक्त) {
		जर ((r = sshkey_sign(किल्ली, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, रिक्त, compat)) != 0)
			fatal_fr(r, "sign");
	} अन्यथा जर ((किल्ली = get_hostkey_public_by_index(keyid, ssh)) != रिक्त &&
	    auth_sock > 0) {
		जर ((r = ssh_agent_sign(auth_sock, किल्ली, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} अन्यथा
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	मुक्त(alg);
	मुक्त(p);
	मुक्त(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	परत (0);
}

#define PUTPW(b, id) \
	करा { \
		जर ((r = sshbuf_put_string(b, \
		    &pwent->id, आकार(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} पर्यंत (0)

शून्य
mm_encode_server_options(संरचना sshbuf *m)
{
	पूर्णांक r;
	संरचना sshbuf *config;

	जर ((config = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	जर ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
पूर्णांक
mm_answer_pwnamallow(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	संरचना passwd *pwent;
	पूर्णांक r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	जर (!compat_set)
		fatal_f("state error: setcompat never called");

	जर (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	जर ((r = sshbuf_get_cstring(m, &authctxt->user, रिक्त)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	जर (pwent == रिक्त) {
		invalid_user = 1;
		जर ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		जा out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	जर ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	जर ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	जर (options.refuse_connection) {
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
	जर (auth2_setup_methods_lists(authctxt) != 0) {
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
	जर (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	परत (0);
}

पूर्णांक mm_answer_auth2_read_banner(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	अक्षर *banner;
	पूर्णांक r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	जर ((r = sshbuf_put_cstring(m, banner != रिक्त ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	मुक्त(banner);

	परत (0);
}

पूर्णांक
mm_answer_authserv(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	पूर्णांक r;

	monitor_permit_authentications(1);

	जर ((r = sshbuf_get_cstring(m, &authctxt->service, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	जर (म_माप(authctxt->style) == 0) {
		मुक्त(authctxt->style);
		authctxt->style = रिक्त;
	}

	परत (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
स्थिर पूर्णांक
किल्ली_base_type_match(स्थिरांक अक्षर *method, स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक अक्षर *list)
{
	अक्षर *s, *l, *ol = xstrdup(list);
	पूर्णांक found = 0;

	l = ol;
	साठी ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		जर (sshkey_type_from_name(s) == किल्ली->type) {
			found = 1;
			थांबा;
		}
	}
	जर (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(किल्ली), list);
	}

	मुक्त(ol);
	परत found;
}

पूर्णांक
mm_answer_authpassword(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	स्थिर पूर्णांक call_मोजणी;
	अक्षर *passwd;
	पूर्णांक r, authenticated;
	माप_प्रकार plen;

	जर (!options.password_authentication)
		fatal_f("password authentication not enabled");
	जर ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	जर ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_मोजणी++;
	जर (plen == 0 && call_मोजणी == 1)
		auth_method = "none";
	अन्यथा
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	परत (authenticated);
}

#ifdef BSD_AUTH
पूर्णांक
mm_answer_bsdauthquery(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	अक्षर *name, *infotxt;
	u_int numprompts, *echo_on, success;
	अक्षर **prompts;
	पूर्णांक r;

	जर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	जर (success) {
		जर ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	जर (success) {
		मुक्त(name);
		मुक्त(infotxt);
		मुक्त(prompts);
		मुक्त(echo_on);
	}

	परत (0);
}

पूर्णांक
mm_answer_bsdauthrespond(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	अक्षर *response;
	पूर्णांक r, authok;

	जर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	जर (authctxt->as == रिक्त)
		fatal_f("no bsd auth session");

	जर ((r = sshbuf_get_cstring(m, &response, रिक्त)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = रिक्त;
	debug3_f("<%s> = <%d>", response, authok);
	मुक्त(response);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	परत (authok != 0);
}
#endif

#ifdef USE_PAM
पूर्णांक
mm_answer_pam_start(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	जर (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	जर (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	परत (0);
}

पूर्णांक
mm_answer_pam_account(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	u_int ret;
	पूर्णांक r;

	जर (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	जर ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	परत (ret);
}

स्थिर शून्य *sshpam_ctxt, *sshpam_authok;
बाह्य KbdintDevice sshpam_device;

पूर्णांक
mm_answer_pam_init_ctx(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	u_int ok = 0;
	पूर्णांक r;

	debug3_f("entering");
	जर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	जर (sshpam_ctxt != रिक्त)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = रिक्त;
	sshbuf_reset(m);
	जर (sshpam_ctxt != रिक्त) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	जर ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	परत (0);
}

पूर्णांक
mm_answer_pam_query(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	अक्षर *name = रिक्त, *info = रिक्त, **prompts = रिक्त;
	u_int i, अंक = 0, *echo_on = 0;
	पूर्णांक r, ret;

	debug3_f("entering");
	sshpam_authok = रिक्त;
	जर (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &अंक, &prompts, &echo_on);
	जर (ret == 0 && अंक == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	जर (अंक > 1 || name == रिक्त || info == रिक्त)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	मुक्त(name);
	मुक्त(info);
	साठी (i = 0; i < अंक; ++i) {
		जर ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(prompts[i]);
	}
	मुक्त(prompts);
	मुक्त(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	परत (0);
}

पूर्णांक
mm_answer_pam_respond(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	अक्षर **resp;
	u_int i, अंक;
	पूर्णांक r, ret;

	debug3_f("entering");
	जर (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	sshpam_authok = रिक्त;
	जर ((r = sshbuf_get_u32(m, &अंक)) != 0)
		fatal_fr(r, "buffer error");
	जर (अंक > PAM_MAX_अंक_संदेश) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    अंक, (अचिन्हित)PAM_MAX_अंक_संदेश);
	}
	जर (अंक > 0) {
		resp = xcalloc(अंक, आकार(अक्षर *));
		साठी (i = 0; i < अंक; ++i) {
			जर ((r = sshbuf_get_cstring(m, &(resp[i]), रिक्त)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, अंक, resp);
		साठी (i = 0; i < अंक; ++i)
			मुक्त(resp[i]);
		मुक्त(resp);
	} अन्यथा {
		ret = (sshpam_device.respond)(sshpam_ctxt, अंक, रिक्त);
	}
	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	जर (ret == 0)
		sshpam_authok = sshpam_ctxt;
	परत (0);
}

पूर्णांक
mm_answer_pam_free_ctx(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	पूर्णांक r = sshpam_authok != रिक्त && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	जर (sshpam_ctxt == रिक्त)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = रिक्त;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	परत r;
}
#endif

पूर्णांक
mm_answer_keyallowed(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	संरचना sshkey *किल्ली = रिक्त;
	अक्षर *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	पूर्णांक r, allowed = 0;
	संरचना sshauthopt *opts = रिक्त;

	debug3_f("entering");
	जर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, रिक्त)) != 0 ||
	    (r = sshkey_froms(m, &किल्ली)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	जर (किल्ली != रिक्त && authctxt->valid) {
		निवड (type) {
		स्थिती MM_USERKEY:
			auth_method = "publickey";
			जर (!options.pubkey_authentication)
				थांबा;
			जर (auth2_किल्ली_already_used(authctxt, किल्ली))
				थांबा;
			जर (!किल्ली_base_type_match(auth_method, किल्ली,
			    options.pubkey_accepted_algos))
				थांबा;
			allowed = user_किल्ली_allowed(ssh, authctxt->pw, किल्ली,
			    pubkey_auth_attempt, &opts);
			थांबा;
		स्थिती MM_HOSTKEY:
			auth_method = "hostbased";
			जर (!options.hostbased_authentication)
				थांबा;
			जर (auth2_किल्ली_already_used(authctxt, किल्ली))
				थांबा;
			जर (!किल्ली_base_type_match(auth_method, किल्ली,
			    options.hostbased_accepted_algos))
				थांबा;
			allowed = hostbased_किल्ली_allowed(ssh, authctxt->pw,
			    cuser, chost, किल्ली);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			थांबा;
		पूर्वनिर्धारित:
			fatal_f("unknown key type %u", type);
			थांबा;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (किल्ली == रिक्त || !authctxt->valid) ? "invalid" : sshkey_type(किल्ली),
	    allowed ? "allowed" : "not allowed");

	auth2_record_किल्ली(authctxt, 0, किल्ली);

	/* clear temporarily storage (used by verify) */
	monitor_reset_किल्ली_state();

	जर (allowed) {
		/* Save temporarily for comparison in verify */
		जर ((r = sshkey_to_blob(किल्ली, &किल्ली_blob, &किल्ली_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		किल्ली_blobtype = type;
		किल्ली_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} अन्यथा {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, रिक्त);
		मुक्त(cuser);
		मुक्त(chost);
	}
	sshkey_free(किल्ली);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	जर (opts != रिक्त && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	जर (!allowed)
		sshauthopt_free(opts);

	परत (0);
}

स्थिर पूर्णांक
monitor_valid_userblob(संरचना ssh *ssh, स्थिरांक u_char *data, u_int datalen)
{
	संरचना sshbuf *b;
	संरचना sshkey *hostkey = रिक्त;
	स्थिरांक u_char *p;
	अक्षर *userstyle, *cp;
	माप_प्रकार len;
	u_char type;
	पूर्णांक hostbound = 0, r, fail = 0;

	जर ((b = sshbuf_from(data, datalen)) == रिक्त)
		fatal_f("sshbuf_from");

	जर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	जर ((session_id2 == रिक्त) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	जर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	जर (type != SSH2_संदेश_USERAUTH_REQUEST)
		fail++;
	जर ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	जर (म_भेद(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	जर ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse method");
	जर (म_भेद("publickey", cp) != 0) {
		जर (म_भेद("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		अन्यथा
			fail++;
	}
	मुक्त(cp);
	जर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	जर (type == 0)
		fail++;
	जर ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	जर (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	जर (hostkey != रिक्त) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		जर (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	परत (fail == 0);
}

स्थिर पूर्णांक
monitor_valid_hostbasedblob(स्थिरांक u_char *data, u_int datalen,
    स्थिरांक अक्षर *cuser, स्थिरांक अक्षर *chost)
{
	संरचना sshbuf *b;
	स्थिरांक u_char *p;
	अक्षर *cp, *userstyle;
	माप_प्रकार len;
	पूर्णांक r, fail = 0;
	u_char type;

	जर ((b = sshbuf_from(data, datalen)) == रिक्त)
		fatal_f("sshbuf_new");
	जर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	जर ((session_id2 == रिक्त) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	जर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	जर (type != SSH2_संदेश_USERAUTH_REQUEST)
		fail++;
	जर ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	जर (म_भेद(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	जर ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse method");
	जर (म_भेद(cp, "hostbased") != 0)
		fail++;
	मुक्त(cp);
	जर ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	जर ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse host");
	जर (((len = म_माप(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	जर (म_भेद(cp, chost) != 0)
		fail++;
	मुक्त(cp);

	/* verify client user */
	जर ((r = sshbuf_get_cstring(b, &cp, रिक्त)) != 0)
		fatal_fr(r, "parse ruser");
	जर (म_भेद(cp, cuser) != 0)
		fail++;
	मुक्त(cp);

	जर (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	परत (fail == 0);
}

पूर्णांक
mm_answer_keyverify(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	संरचना sshkey *किल्ली;
	स्थिरांक u_char *signature, *data, *blob;
	अक्षर *sigalg = रिक्त, *fp = रिक्त;
	माप_प्रकार signaturelen, datalen, bloblen;
	पूर्णांक r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	पूर्णांक encoded_ret;
	संरचना sshkey_sig_details *sig_details = रिक्त;

	जर ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, रिक्त)) != 0)
		fatal_fr(r, "parse");

	जर (hostbased_cuser == रिक्त || hostbased_chost == रिक्त ||
	  !monitor_allowed_किल्ली(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	जर (*sigalg == '\0') {
		मुक्त(sigalg);
		sigalg = रिक्त;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	जर ((r = sshkey_from_blob(blob, bloblen, &किल्ली)) != 0)
		fatal_fr(r, "parse key");

	निवड (किल्ली_blobtype) {
	स्थिती MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		थांबा;
	स्थिती MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		थांबा;
	पूर्वनिर्धारित:
		valid_data = 0;
		थांबा;
	}
	जर (!valid_data)
		fatal_f("bad %s signature data blob",
		    किल्ली_blobtype == MM_USERKEY ? "userkey" :
		    (किल्ली_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	जर ((fp = sshkey_fingerprint(किल्ली, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(किल्ली, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(किल्ली), sigalg == रिक्त ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	जर (ret == 0 && किल्ली_blobtype == MM_USERKEY && sig_details != रिक्त) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !किल्ली_opts->no_require_user_presence;
		जर (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(किल्ली), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || किल्ली_opts->require_verify;
		जर (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(किल्ली), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_किल्ली(authctxt, ret == 0, किल्ली);

	जर (किल्ली_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, किल्ली_opts);
	monitor_reset_किल्ली_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	जर ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != रिक्त)) != 0)
		fatal_fr(r, "assemble");
	जर (sig_details != रिक्त) {
		जर ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	मुक्त(sigalg);
	मुक्त(fp);
	sshkey_free(किल्ली);

	परत ret == 0;
}

स्थिर शून्य
mm_record_login(संरचना ssh *ssh, Session *s, संरचना passwd *pw)
{
	socklen_t fromlen;
	संरचना sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	स_रखो(&from, 0, आकार(from));
	fromlen = आकार(from);
	जर (ssh_packet_connection_is_on_socket(ssh)) {
		जर (getpeername(ssh_packet_get_connection_in(ssh),
		    (संरचना sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (संरचना sockaddr *)&from, fromlen);
}

स्थिर शून्य
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (दीर्घ)s->pid);
	जर (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

पूर्णांक
mm_answer_pty(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	बाह्य संरचना monitor *pmonitor;
	Session *s;
	पूर्णांक r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	जर (s == रिक्त)
		जा error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, आकार(s->tty));
	जर (res == 0)
		जा error;
	pty_setowner(authctxt->pw, s->tty);

	जर ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	जर (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	बंद(0);

	/* send messages generated by record_login */
	जर ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	जर (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	जर ((fd0 = खोलो(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", म_त्रुटि(त्रुटि_सं));
	जर (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	बंद(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	परत (0);

 error:
	जर (s != रिक्त)
		mm_session_close(s);
	जर ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	परत (0);
}

पूर्णांक
mm_answer_pty_cleanup(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	Session *s;
	अक्षर *tty;
	पूर्णांक r;

	debug3_f("entering");

	जर ((r = sshbuf_get_cstring(m, &tty, रिक्त)) != 0)
		fatal_fr(r, "parse tty");
	जर ((s = session_by_tty(tty)) != रिक्त)
		mm_session_close(s);
	sshbuf_reset(m);
	मुक्त(tty);
	परत (0);
}

पूर्णांक
mm_answer_term(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *req)
{
	बाह्य संरचना monitor *pmonitor;
	पूर्णांक res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	जर (options.use_pam)
		sshpam_cleanup();
#endif

	पर्यंत (waitpid(pmonitor->m_pid, &status, 0) == -1)
		जर (त्रुटि_सं != EINTR)
			निकास(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	निकास(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
पूर्णांक
mm_answer_audit_event(संरचना ssh *ssh, पूर्णांक socket, संरचना sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	पूर्णांक r;

	debug3_f("entering");

	जर ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	निवड (event) {
	स्थिती SSH_AUTH_FAIL_PUBKEY:
	स्थिती SSH_AUTH_FAIL_HOSTBASED:
	स्थिती SSH_AUTH_FAIL_GSSAPI:
	स्थिती SSH_LOGIN_EXCEED_MAXTRIES:
	स्थिती SSH_LOGIN_मूळ_DENIED:
	स्थिती SSH_CONNECTION_CLOSE:
	स्थिती SSH_INVALID_USER:
		audit_event(ssh, event);
		थांबा;
	पूर्वनिर्धारित:
		fatal("Audit event type %d not permitted", event);
	}

	परत (0);
}

पूर्णांक
mm_answer_audit_command(संरचना ssh *ssh, पूर्णांक socket, संरचना sshbuf *m)
{
	अक्षर *cmd;
	पूर्णांक r;

	debug3_f("entering");
	जर ((r = sshbuf_get_cstring(m, &cmd, रिक्त)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	मुक्त(cmd);
	परत (0);
}
#endif /* SSH_AUDIT_EVENTS */

शून्य
monitor_clear_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = रिक्त;
}

शून्य
monitor_apply_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	संरचना kex *kex;
	पूर्णांक r;

	debug3_f("packet_set_state");
	जर ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = रिक्त;
	जर ((kex = ssh->kex) == रिक्त)
		fatal_f("internal error: ssh->kex == NULL");
	जर (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	जर (स_भेद(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_किल्ली=&get_hostkey_public_by_type;
	kex->load_host_private_किल्ली=&get_hostkey_private_by_type;
	kex->host_किल्ली_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

शून्य
mm_get_keystate(संरचना ssh *ssh, संरचना monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	जर ((child_state = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

स्थिर शून्य
monitor_openfds(संरचना monitor *mon, पूर्णांक do_logfds)
{
	पूर्णांक pair[2];
#ifdef SO_ZEROIZE
	पूर्णांक on = 1;
#endif

	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", म_त्रुटि(त्रुटि_सं));
#ifdef SO_ZEROIZE
	जर (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, आकार(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", म_त्रुटि(त्रुटि_सं));
	जर (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, आकार(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", म_त्रुटि(त्रुटि_सं));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	जर (do_logfds) {
		जर (pipe(pair) == -1)
			fatal_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
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

	mon = xcalloc(1, आकार(*mon));
	monitor_openfds(mon, 1);

	परत mon;
}

शून्य
monitor_reinit(संरचना monitor *mon)
{
	monitor_openfds(mon, 0);
}

पूर्णांक
monitor_auth_attempted(शून्य)
{
	परत auth_attempted;
}

पूर्णांक
monitor_invalid_user(शून्य)
{
	परत invalid_user;
}

#ifdef GSSAPI
पूर्णांक
mm_answer_gss_setup_ctx(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	माप_प्रकार len;
	u_char *p;
	पूर्णांक r;

	जर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	जर ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	मुक्त(goid.elements);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	परत (0);
}

पूर्णांक
mm_answer_gss_accept_ctx(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	पूर्णांक r;

	जर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	जर ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	मुक्त(in.मूल्य);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.मूल्य, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	जर (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	परत (0);
}

पूर्णांक
mm_answer_gss_checkmic(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	पूर्णांक r;

	जर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	जर ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	मुक्त(gssbuf.मूल्य);
	मुक्त(mic.मूल्य);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	जर (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	परत (0);
}

पूर्णांक
mm_answer_gss_userok(संरचना ssh *ssh, पूर्णांक sock, संरचना sshbuf *m)
{
	पूर्णांक r, authenticated;
	स्थिरांक अक्षर *displayname;

	जर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	जर ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	जर ((displayname = ssh_gssapi_displayname()) != रिक्त)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	परत (authenticated);
}
#endif /* GSSAPI */

