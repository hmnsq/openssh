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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>
#समावेश <sys/socket.h>
#समावेश <sys/tree.h>
#समावेश <sys/queue.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <paths.h>
#समावेश <poll.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/dh.h>
#पूर्ण_अगर

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "atomicio.h"
#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "dh.h"
#समावेश "auth-pam.h"
#समावेश "packet.h"
#समावेश "auth-options.h"
#समावेश "sshpty.h"
#समावेश "channels.h"
#समावेश "session.h"
#समावेश "sshlogin.h"
#समावेश "canohost.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "monitor.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "monitor_fdpass.h"
#समावेश "compat.h"
#समावेश "ssh2.h"
#समावेश "authfd.h"
#समावेश "match.h"
#समावेश "ssherr.h"
#समावेश "sk-api.h"
#समावेश "srclimit.h"

#अगर_घोषित GSSAPI
अटल Gssctxt *gsscontext = शून्य;
#पूर्ण_अगर

/* Imports */
बाह्य ServerOptions options;
बाह्य u_int utmp_len;
बाह्य काष्ठा sshbuf *cfg;
बाह्य काष्ठा sshbuf *loginmsg;
बाह्य काष्ठा include_list includes;
बाह्य काष्ठा sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
अटल काष्ठा sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

पूर्णांक mm_answer_moduli(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_setcompat(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_sign(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pwnamallow(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_auth2_read_banner(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_authserv(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_authpassword(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_bsdauthquery(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_bsdauthrespond(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_keyallowed(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_keyverify(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pty(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pty_cleanup(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_term(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_state(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);

#अगर_घोषित USE_PAM
पूर्णांक mm_answer_pam_start(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pam_account(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pam_init_ctx(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pam_query(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pam_respond(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_pam_free_ctx(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
#पूर्ण_अगर

#अगर_घोषित GSSAPI
पूर्णांक mm_answer_gss_setup_ctx(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_gss_accept_ctx(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_gss_userok(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_gss_checkmic(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
#पूर्ण_अगर

#अगर_घोषित SSH_AUDIT_EVENTS
पूर्णांक mm_answer_audit_event(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
पूर्णांक mm_answer_audit_command(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
#पूर्ण_अगर

अटल Authctxt *authctxt;

/* local state for key verify */
अटल u_char *कुंजी_blob = शून्य;
अटल माप_प्रकार कुंजी_bloblen = 0;
अटल u_int कुंजी_blobtype = MM_NOKEY;
अटल काष्ठा sshauthopt *कुंजी_opts = शून्य;
अटल अक्षर *hostbased_cuser = शून्य;
अटल अक्षर *hostbased_chost = शून्य;
अटल अक्षर *auth_method = "unknown";
अटल अक्षर *auth_submethod = शून्य;
अटल u_int session_id2_len = 0;
अटल u_char *session_id2 = शून्य;
अटल pid_t monitor_child_pid;
अटल पूर्णांक auth_attempted = 0;
अटल पूर्णांक invalid_user = 0;
अटल पूर्णांक compat_set = 0;

काष्ठा mon_table {
	क्रमागत monitor_reqtype type;
	पूर्णांक flags;
	पूर्णांक (*f)(काष्ठा ssh *, पूर्णांक, काष्ठा sshbuf *);
};

#घोषणा MON_ISAUTH	0x0004	/* Required for Authentication */
#घोषणा MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#घोषणा MON_ONCE	0x0010	/* Disable after calling */
#घोषणा MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#घोषणा MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#घोषणा MON_PERMIT	0x1000	/* Request is permitted */

अटल पूर्णांक monitor_read(काष्ठा ssh *, काष्ठा monitor *, काष्ठा mon_table *,
    काष्ठा mon_table **);
अटल पूर्णांक monitor_read_log(काष्ठा monitor *);

काष्ठा mon_table mon_dispatch_proto20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#अगर_घोषित WITH_OPENSSL
    {MONITOR_REQ_MODULI, MON_ONCE, mm_answer_moduli},
#पूर्ण_अगर
    {MONITOR_REQ_SETCOMPAT, MON_ONCE, mm_answer_setcompat},
    {MONITOR_REQ_SIGN, MON_ONCE, mm_answer_sign},
    {MONITOR_REQ_PWNAM, MON_ONCE, mm_answer_pwnamallow},
    {MONITOR_REQ_AUTHSERV, MON_ONCE, mm_answer_authserv},
    {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, mm_answer_auth2_read_banner},
    {MONITOR_REQ_AUTHPASSWORD, MON_AUTH, mm_answer_authpassword},
#अगर_घोषित USE_PAM
    {MONITOR_REQ_PAM_START, MON_ONCE, mm_answer_pam_start},
    {MONITOR_REQ_PAM_ACCOUNT, 0, mm_answer_pam_account},
    {MONITOR_REQ_PAM_INIT_CTX, MON_ONCE, mm_answer_pam_init_ctx},
    {MONITOR_REQ_PAM_QUERY, 0, mm_answer_pam_query},
    {MONITOR_REQ_PAM_RESPOND, MON_ONCE, mm_answer_pam_respond},
    {MONITOR_REQ_PAM_FREE_CTX, MON_ONCE|MON_AUTHDECIDE, mm_answer_pam_free_ctx},
#पूर्ण_अगर
#अगर_घोषित SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
#पूर्ण_अगर
#अगर_घोषित BSD_AUTH
    {MONITOR_REQ_BSDAUTHQUERY, MON_ISAUTH, mm_answer_bsdauthquery},
    {MONITOR_REQ_BSDAUTHRESPOND, MON_AUTH, mm_answer_bsdauthrespond},
#पूर्ण_अगर
    {MONITOR_REQ_KEYALLOWED, MON_ISAUTH, mm_answer_keyallowed},
    {MONITOR_REQ_KEYVERIFY, MON_AUTH, mm_answer_keyverify},
#अगर_घोषित GSSAPI
    {MONITOR_REQ_GSSSETUP, MON_ISAUTH, mm_answer_gss_setup_ctx},
    {MONITOR_REQ_GSSSTEP, 0, mm_answer_gss_accept_ctx},
    {MONITOR_REQ_GSSUSEROK, MON_ONCE|MON_AUTHDECIDE, mm_answer_gss_userok},
    {MONITOR_REQ_GSSCHECKMIC, MON_ONCE, mm_answer_gss_checkmic},
#पूर्ण_अगर
    {0, 0, शून्य}
};

काष्ठा mon_table mon_dispatch_postauth20[] = {
    {MONITOR_REQ_STATE, MON_ONCE, mm_answer_state},
#अगर_घोषित WITH_OPENSSL
    {MONITOR_REQ_MODULI, 0, mm_answer_moduli},
#पूर्ण_अगर
    {MONITOR_REQ_SIGN, 0, mm_answer_sign},
    {MONITOR_REQ_PTY, 0, mm_answer_pty},
    {MONITOR_REQ_PTYCLEANUP, 0, mm_answer_pty_cleanup},
    {MONITOR_REQ_TERM, 0, mm_answer_term},
#अगर_घोषित SSH_AUDIT_EVENTS
    {MONITOR_REQ_AUDIT_EVENT, MON_PERMIT, mm_answer_audit_event},
    {MONITOR_REQ_AUDIT_COMMAND, MON_PERMIT, mm_answer_audit_command},
#पूर्ण_अगर
    {0, 0, शून्य}
};

काष्ठा mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
अटल व्योम
monitor_permit(काष्ठा mon_table *ent, क्रमागत monitor_reqtype type, पूर्णांक permit)
{
	जबतक (ent->f != शून्य) {
		अगर (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			वापस;
		}
		ent++;
	}
}

अटल व्योम
monitor_permit_authentications(पूर्णांक permit)
{
	काष्ठा mon_table *ent = mon_dispatch;

	जबतक (ent->f != शून्य) {
		अगर (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

व्योम
monitor_child_preauth(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor)
{
	काष्ठा mon_table *ent;
	पूर्णांक status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	अगर (pmonitor->m_recvfd >= 0)
		बंद(pmonitor->m_recvfd);
	अगर (pmonitor->m_log_sendfd >= 0)
		बंद(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	स_रखो(authctxt, 0, माप(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	जबतक (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = शून्य;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		अगर ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		अगर (options.अंक_auth_methods != 0) {
			अगर (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		अगर (authenticated) {
			अगर (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			अगर (authctxt->pw->pw_uid == 0 &&
			    !auth_मूल_allowed(ssh, auth_method))
				authenticated = 0;
#अगर_घोषित USE_PAM
			/* PAM needs to perform account checks after auth */
			अगर (options.use_pam && authenticated) {
				काष्ठा sshbuf *m;

				अगर ((m = sshbuf_new()) == शून्य)
					fatal("%s: sshbuf_new failed",
					    __func__);
				mm_request_receive_expect(pmonitor->m_sendfd,
				    MONITOR_REQ_PAM_ACCOUNT, m);
				authenticated = mm_answer_pam_account(
				    ssh, pmonitor->m_sendfd, m);
				sshbuf_free(m);
			}
#पूर्ण_अगर
		}
		अगर (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			अगर (!partial && !authenticated)
				authctxt->failures++;
			अगर (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		अगर (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	अगर (!authctxt->valid)
		fatal_f("authenticated invalid user");
	अगर (म_भेद(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = शून्य;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	जबतक (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	जबतक (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		अगर (त्रुटि_सं == EINTR)
			जारी;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	अगर (WIFEXITED(status)) {
		अगर (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (दीर्घ)pmonitor->m_pid, WEXITSTATUS(status));
	} अन्यथा अगर (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (दीर्घ)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (दीर्घ)pmonitor->m_pid);

	अगर (pmonitor->m_recvfd >= 0)
		बंद(pmonitor->m_recvfd);
	अगर (pmonitor->m_log_sendfd >= 0)
		बंद(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

अटल व्योम
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

अटल व्योम
monitor_child_handler(पूर्णांक sig)
{
	समाप्त(monitor_child_pid, sig);
}

व्योम
monitor_child_postauth(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor)
{
	बंद(pmonitor->m_recvfd);
	pmonitor->m_recvfd = -1;

	monitor_set_child_handler(pmonitor->m_pid);
	ssh_signal(SIGHUP, &monitor_child_handler);
	ssh_signal(संक_इति, &monitor_child_handler);
	ssh_signal(संक_विघ्न, &monitor_child_handler);
#अगर_घोषित SIGXFSZ
	ssh_signal(SIGXFSZ, संक_छोड़ो);
#पूर्ण_अगर

	mon_dispatch = mon_dispatch_postauth20;

	/* Permit requests for moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_TERM, 1);

	अगर (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	क्रम (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, शून्य);
}

अटल पूर्णांक
monitor_read_log(काष्ठा monitor *pmonitor)
{
	काष्ठा sshbuf *logmsg;
	u_int len, level, forced;
	अक्षर *संदेश;
	u_char *p;
	पूर्णांक r;

	अगर ((logmsg = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");

	/* Read length */
	अगर ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	अगर (atomicio(पढ़ो, pmonitor->m_log_recvfd, p, 4) != 4) {
		अगर (त्रुटि_सं == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			बंद(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			वापस -1;
		}
		fatal_f("log fd read: %s", म_त्रुटि(त्रुटि_सं));
	}
	अगर ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	अगर (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	अगर ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	अगर (atomicio(पढ़ो, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", म_त्रुटि(त्रुटि_सं));
	अगर ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &संदेश, शून्य)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	अगर (log_level_name(level) == शून्य)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", संदेश,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	मुक्त(संदेश);

	वापस 0;
}

अटल पूर्णांक
monitor_read(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor, काष्ठा mon_table *ent,
    काष्ठा mon_table **pent)
{
	काष्ठा sshbuf *m;
	पूर्णांक r, ret;
	u_char type;
	काष्ठा pollfd pfd[2];

	क्रम (;;) {
		स_रखो(&pfd, 0, माप(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		अगर (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			अगर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				जारी;
			fatal_f("poll: %s", म_त्रुटि(त्रुटि_सं));
		}
		अगर (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			जारी;
		}
		अगर (pfd[0].revents)
			अवरोध;  /* Continues below */
	}

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	अगर ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	जबतक (ent->f != शून्य) {
		अगर (ent->type == type)
			अवरोध;
		ent++;
	}

	अगर (ent->f != शून्य) {
		अगर (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		अगर (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		अगर (pent != शून्य)
			*pent = ent;

		वापस ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	वापस (-1);
}

/* allowed key state */
अटल पूर्णांक
monitor_allowed_कुंजी(स्थिर u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	अगर (कुंजी_blob == शून्य || कुंजी_bloblen != bloblen ||
	    timingsafe_bcmp(कुंजी_blob, blob, कुंजी_bloblen))
		वापस (0);
	वापस (1);
}

अटल व्योम
monitor_reset_कुंजी_state(व्योम)
{
	/* reset state */
	मुक्त(कुंजी_blob);
	मुक्त(hostbased_cuser);
	मुक्त(hostbased_chost);
	sshauthopt_free(कुंजी_opts);
	कुंजी_blob = शून्य;
	कुंजी_bloblen = 0;
	कुंजी_blobtype = MM_NOKEY;
	कुंजी_opts = शून्य;
	hostbased_cuser = शून्य;
	hostbased_chost = शून्य;
}

पूर्णांक
mm_answer_state(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *unused)
{
	काष्ठा sshbuf *m = शून्य, *config = शून्य, *hostkeys = शून्य;
	काष्ठा sshbuf *opts = शून्य, *confdata = शून्य;
	पूर्णांक postauth;
	पूर्णांक r;

	debug_f("config len %zu", sshbuf_len(cfg));

	अगर ((m = sshbuf_new()) == शून्य ||
	    (config = sshbuf_new()) == शून्य ||
	    (opts = sshbuf_new()) == शून्य ||
	    (confdata = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	अगर ((r = serialise_server_options(&options, &config)) != 0)
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
	अगर ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	अगर (postauth) {
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

	वापस (0);
}

#अगर_घोषित WITH_OPENSSL
पूर्णांक
mm_answer_moduli(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	DH *dh;
	स्थिर BIGNUM *dh_p, *dh_g;
	पूर्णांक r;
	u_int min, want, max;

	अगर ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	अगर (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	अगर (dh == शून्य) {
		अगर ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} अन्यथा {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, शून्य, &dh_g);
		अगर ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	वापस (0);
}
#पूर्ण_अगर

पूर्णांक
mm_answer_setcompat(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	पूर्णांक r;

	debug3_f("entering");

	अगर ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	वापस (0);
}

पूर्णांक
mm_answer_sign(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	बाह्य पूर्णांक auth_sock;			/* XXX move to state struct? */
	काष्ठा sshkey *pubkey, *कुंजी;
	काष्ठा sshbuf *sigbuf = शून्य;
	u_char *p = शून्य, *signature = शून्य;
	अक्षर *alg = शून्य;
	माप_प्रकार datlen, siglen;
	पूर्णांक r, is_proof = 0, keyid;
	u_int compat;
	स्थिर अक्षर proof_req[] = "hostkeys-prove-00@openssh.com";
	अटल पूर्णांक nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	अगर (!compat_set)
		fatal_f("state error: setcompat never called");

	अगर ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	अगर ((keyid = get_hostkey_सूचकांक(pubkey, 1, ssh)) == -1)
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
	अगर (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		अगर (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		अगर ((कुंजी = get_hostkey_public_by_सूचकांक(keyid, ssh)) == शून्य)
			fatal_f("no hostkey for index %d", keyid);
		अगर (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, माप(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		अगर (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(कुंजी), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		अगर ((sigbuf = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new");
		अगर ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(कुंजी, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		अगर (datlen != sshbuf_len(sigbuf) ||
		    स_भेद(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	अगर (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		स_नकल(session_id2, p, session_id2_len);
	}

	अगर ((कुंजी = get_hostkey_by_सूचकांक(keyid)) != शून्य) {
		अगर ((r = sshkey_sign(कुंजी, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, शून्य, compat)) != 0)
			fatal_fr(r, "sign");
	} अन्यथा अगर ((कुंजी = get_hostkey_public_by_सूचकांक(keyid, ssh)) != शून्य &&
	    auth_sock > 0) {
		अगर ((r = ssh_agent_sign(auth_sock, कुंजी, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} अन्यथा
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	मुक्त(alg);
	मुक्त(p);
	मुक्त(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	वापस (0);
}

#घोषणा PUTPW(b, id) \
	करो { \
		अगर ((r = sshbuf_put_string(b, \
		    &pwent->id, माप(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} जबतक (0)

व्योम
mm_encode_server_options(काष्ठा sshbuf *m)
{
	पूर्णांक r;
	काष्ठा sshbuf *config;

	अगर ((config = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	अगर ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
पूर्णांक
mm_answer_pwnamallow(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	काष्ठा passwd *pwent;
	पूर्णांक r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	अगर (!compat_set)
		fatal_f("state error: setcompat never called");

	अगर (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	अगर ((r = sshbuf_get_cstring(m, &authctxt->user, शून्य)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	अगर (pwent == शून्य) {
		invalid_user = 1;
		अगर ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		जाओ out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	अगर ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#पूर्ण_अगर
	अगर ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
	    (r = sshbuf_put_cstring(m, "*")) != 0 ||
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_put_cstring(m, pwent->pw_gecos)) != 0 ||
#पूर्ण_अगर
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_put_cstring(m, pwent->pw_class)) != 0 ||
#पूर्ण_अगर
	    (r = sshbuf_put_cstring(m, pwent->pw_dir)) != 0 ||
	    (r = sshbuf_put_cstring(m, pwent->pw_shell)) != 0)
		fatal_fr(r, "assemble pw");

 out:
	ssh_packet_set_log_preamble(ssh, "%suser %s",
	    authctxt->valid ? "authenticating" : "invalid ", authctxt->user);

	अगर (options.refuse_connection) {
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
	अगर (auth2_setup_methods_lists(authctxt) != 0) {
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

#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#पूर्ण_अगर

	वापस (0);
}

पूर्णांक mm_answer_auth2_read_banner(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अक्षर *banner;
	पूर्णांक r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	अगर ((r = sshbuf_put_cstring(m, banner != शून्य ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	मुक्त(banner);

	वापस (0);
}

पूर्णांक
mm_answer_authserv(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	पूर्णांक r;

	monitor_permit_authentications(1);

	अगर ((r = sshbuf_get_cstring(m, &authctxt->service, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, शून्य)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	अगर (म_माप(authctxt->style) == 0) {
		मुक्त(authctxt->style);
		authctxt->style = शून्य;
	}

	वापस (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
अटल पूर्णांक
कुंजी_base_type_match(स्थिर अक्षर *method, स्थिर काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *list)
{
	अक्षर *s, *l, *ol = xstrdup(list);
	पूर्णांक found = 0;

	l = ol;
	क्रम ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		अगर (sshkey_type_from_name(s) == कुंजी->type) {
			found = 1;
			अवरोध;
		}
	}
	अगर (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(कुंजी), list);
	}

	मुक्त(ol);
	वापस found;
}

पूर्णांक
mm_answer_authpassword(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अटल पूर्णांक call_गिनती;
	अक्षर *passwd;
	पूर्णांक r, authenticated;
	माप_प्रकार plen;

	अगर (!options.password_authentication)
		fatal_f("password authentication not enabled");
	अगर ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#अगर_घोषित USE_PAM
	अगर ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#पूर्ण_अगर

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_गिनती++;
	अगर (plen == 0 && call_गिनती == 1)
		auth_method = "none";
	अन्यथा
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	वापस (authenticated);
}

#अगर_घोषित BSD_AUTH
पूर्णांक
mm_answer_bsdauthquery(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अक्षर *name, *infotxt;
	u_int numprompts, *echo_on, success;
	अक्षर **prompts;
	पूर्णांक r;

	अगर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	अगर (success) {
		अगर ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	अगर (success) {
		मुक्त(name);
		मुक्त(infotxt);
		मुक्त(prompts);
		मुक्त(echo_on);
	}

	वापस (0);
}

पूर्णांक
mm_answer_bsdauthrespond(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अक्षर *response;
	पूर्णांक r, authok;

	अगर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	अगर (authctxt->as == शून्य)
		fatal_f("no bsd auth session");

	अगर ((r = sshbuf_get_cstring(m, &response, शून्य)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = शून्य;
	debug3_f("<%s> = <%d>", response, authok);
	मुक्त(response);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	वापस (authok != 0);
}
#पूर्ण_अगर

#अगर_घोषित USE_PAM
पूर्णांक
mm_answer_pam_start(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अगर (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	अगर (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	वापस (0);
}

पूर्णांक
mm_answer_pam_account(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	u_int ret;
	पूर्णांक r;

	अगर (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	अगर ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	वापस (ret);
}

अटल व्योम *sshpam_ctxt, *sshpam_authok;
बाह्य KbdintDevice sshpam_device;

पूर्णांक
mm_answer_pam_init_ctx(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	u_int ok = 0;
	पूर्णांक r;

	debug3_f("entering");
	अगर (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	अगर (sshpam_ctxt != शून्य)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = शून्य;
	sshbuf_reset(m);
	अगर (sshpam_ctxt != शून्य) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	अगर ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	वापस (0);
}

पूर्णांक
mm_answer_pam_query(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अक्षर *name = शून्य, *info = शून्य, **prompts = शून्य;
	u_int i, अंक = 0, *echo_on = 0;
	पूर्णांक r, ret;

	debug3_f("entering");
	sshpam_authok = शून्य;
	अगर (sshpam_ctxt == शून्य)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &अंक, &prompts, &echo_on);
	अगर (ret == 0 && अंक == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	अगर (अंक > 1 || name == शून्य || info == शून्य)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, अंक)) != 0)
		fatal_fr(r, "buffer error");
	मुक्त(name);
	मुक्त(info);
	क्रम (i = 0; i < अंक; ++i) {
		अगर ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(prompts[i]);
	}
	मुक्त(prompts);
	मुक्त(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	वापस (0);
}

पूर्णांक
mm_answer_pam_respond(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	अक्षर **resp;
	u_int i, अंक;
	पूर्णांक r, ret;

	debug3_f("entering");
	अगर (sshpam_ctxt == शून्य)
		fatal_f("no context");
	sshpam_authok = शून्य;
	अगर ((r = sshbuf_get_u32(m, &अंक)) != 0)
		fatal_fr(r, "buffer error");
	अगर (अंक > PAM_MAX_अंक_संदेश) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    अंक, (अचिन्हित)PAM_MAX_अंक_संदेश);
	}
	अगर (अंक > 0) {
		resp = xcalloc(अंक, माप(अक्षर *));
		क्रम (i = 0; i < अंक; ++i) {
			अगर ((r = sshbuf_get_cstring(m, &(resp[i]), शून्य)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, अंक, resp);
		क्रम (i = 0; i < अंक; ++i)
			मुक्त(resp[i]);
		मुक्त(resp);
	} अन्यथा {
		ret = (sshpam_device.respond)(sshpam_ctxt, अंक, शून्य);
	}
	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	अगर (ret == 0)
		sshpam_authok = sshpam_ctxt;
	वापस (0);
}

पूर्णांक
mm_answer_pam_free_ctx(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	पूर्णांक r = sshpam_authok != शून्य && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	अगर (sshpam_ctxt == शून्य)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = शून्य;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	वापस r;
}
#पूर्ण_अगर

पूर्णांक
mm_answer_keyallowed(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	काष्ठा sshkey *कुंजी = शून्य;
	अक्षर *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	पूर्णांक r, allowed = 0;
	काष्ठा sshauthopt *opts = शून्य;

	debug3_f("entering");
	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, शून्य)) != 0 ||
	    (r = sshkey_froms(m, &कुंजी)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	अगर (कुंजी != शून्य && authctxt->valid) {
		चयन (type) {
		हाल MM_USERKEY:
			auth_method = "publickey";
			अगर (!options.pubkey_authentication)
				अवरोध;
			अगर (auth2_कुंजी_already_used(authctxt, कुंजी))
				अवरोध;
			अगर (!कुंजी_base_type_match(auth_method, कुंजी,
			    options.pubkey_accepted_algos))
				अवरोध;
			allowed = user_कुंजी_allowed(ssh, authctxt->pw, कुंजी,
			    pubkey_auth_attempt, &opts);
			अवरोध;
		हाल MM_HOSTKEY:
			auth_method = "hostbased";
			अगर (!options.hostbased_authentication)
				अवरोध;
			अगर (auth2_कुंजी_already_used(authctxt, कुंजी))
				अवरोध;
			अगर (!कुंजी_base_type_match(auth_method, कुंजी,
			    options.hostbased_accepted_algos))
				अवरोध;
			allowed = hostbased_कुंजी_allowed(ssh, authctxt->pw,
			    cuser, chost, कुंजी);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			अवरोध;
		शेष:
			fatal_f("unknown key type %u", type);
			अवरोध;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (कुंजी == शून्य || !authctxt->valid) ? "invalid" : sshkey_type(कुंजी),
	    allowed ? "allowed" : "not allowed");

	auth2_record_कुंजी(authctxt, 0, कुंजी);

	/* clear temporarily storage (used by verify) */
	monitor_reset_कुंजी_state();

	अगर (allowed) {
		/* Save temporarily for comparison in verify */
		अगर ((r = sshkey_to_blob(कुंजी, &कुंजी_blob, &कुंजी_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		कुंजी_blobtype = type;
		कुंजी_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} अन्यथा {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, शून्य);
		मुक्त(cuser);
		मुक्त(chost);
	}
	sshkey_free(कुंजी);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	अगर (opts != शून्य && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	अगर (!allowed)
		sshauthopt_free(opts);

	वापस (0);
}

अटल पूर्णांक
monitor_valid_userblob(काष्ठा ssh *ssh, स्थिर u_char *तथ्य, u_int datalen)
{
	काष्ठा sshbuf *b;
	काष्ठा sshkey *hostkey = शून्य;
	स्थिर u_char *p;
	अक्षर *userstyle, *cp;
	माप_प्रकार len;
	u_char type;
	पूर्णांक hostbound = 0, r, fail = 0;

	अगर ((b = sshbuf_from(तथ्य, datalen)) == शून्य)
		fatal_f("sshbuf_from");

	अगर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	अगर ((session_id2 == शून्य) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	अगर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != SSH2_संदेश_USERAUTH_REQUEST)
		fail++;
	अगर ((r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	अगर (म_भेद(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	अगर ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse method");
	अगर (म_भेद("publickey", cp) != 0) {
		अगर (म_भेद("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		अन्यथा
			fail++;
	}
	मुक्त(cp);
	अगर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	अगर (type == 0)
		fail++;
	अगर ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	अगर (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	अगर (hostkey != शून्य) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		अगर (get_hostkey_सूचकांक(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	वापस (fail == 0);
}

अटल पूर्णांक
monitor_valid_hostbasedblob(स्थिर u_char *तथ्य, u_int datalen,
    स्थिर अक्षर *cuser, स्थिर अक्षर *chost)
{
	काष्ठा sshbuf *b;
	स्थिर u_char *p;
	अक्षर *cp, *userstyle;
	माप_प्रकार len;
	पूर्णांक r, fail = 0;
	u_char type;

	अगर ((b = sshbuf_from(तथ्य, datalen)) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	अगर ((session_id2 == शून्य) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	अगर ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != SSH2_संदेश_USERAUTH_REQUEST)
		fail++;
	अगर ((r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	अगर (म_भेद(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	मुक्त(userstyle);
	मुक्त(cp);
	अगर ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse method");
	अगर (म_भेद(cp, "hostbased") != 0)
		fail++;
	मुक्त(cp);
	अगर ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	अगर ((r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse host");
	अगर (((len = म_माप(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	अगर (म_भेद(cp, chost) != 0)
		fail++;
	मुक्त(cp);

	/* verify client user */
	अगर ((r = sshbuf_get_cstring(b, &cp, शून्य)) != 0)
		fatal_fr(r, "parse ruser");
	अगर (म_भेद(cp, cuser) != 0)
		fail++;
	मुक्त(cp);

	अगर (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	वापस (fail == 0);
}

पूर्णांक
mm_answer_keyverify(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	काष्ठा sshkey *कुंजी;
	स्थिर u_char *signature, *तथ्य, *blob;
	अक्षर *sigalg = शून्य, *fp = शून्य;
	माप_प्रकार signaturelen, datalen, bloblen;
	पूर्णांक r, ret, req_presence = 0, req_verify = 0, valid_तथ्य = 0;
	पूर्णांक encoded_ret;
	काष्ठा sshkey_sig_details *sig_details = शून्य;

	अगर ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &तथ्य, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, शून्य)) != 0)
		fatal_fr(r, "parse");

	अगर (hostbased_cuser == शून्य || hostbased_chost == शून्य ||
	  !monitor_allowed_कुंजी(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	अगर (*sigalg == '\0') {
		मुक्त(sigalg);
		sigalg = शून्य;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	अगर ((r = sshkey_from_blob(blob, bloblen, &कुंजी)) != 0)
		fatal_fr(r, "parse key");

	चयन (कुंजी_blobtype) {
	हाल MM_USERKEY:
		valid_तथ्य = monitor_valid_userblob(ssh, तथ्य, datalen);
		auth_method = "publickey";
		अवरोध;
	हाल MM_HOSTKEY:
		valid_तथ्य = monitor_valid_hostbasedblob(तथ्य, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		अवरोध;
	शेष:
		valid_तथ्य = 0;
		अवरोध;
	}
	अगर (!valid_तथ्य)
		fatal_f("bad %s signature data blob",
		    कुंजी_blobtype == MM_USERKEY ? "userkey" :
		    (कुंजी_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	अगर ((fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(कुंजी, signature, signaturelen, तथ्य, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(कुंजी), sigalg == शून्य ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	अगर (ret == 0 && कुंजी_blobtype == MM_USERKEY && sig_details != शून्य) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !कुंजी_opts->no_require_user_presence;
		अगर (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(कुंजी), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || कुंजी_opts->require_verify;
		अगर (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(कुंजी), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_कुंजी(authctxt, ret == 0, कुंजी);

	अगर (कुंजी_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, कुंजी_opts);
	monitor_reset_कुंजी_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	अगर ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != शून्य)) != 0)
		fatal_fr(r, "assemble");
	अगर (sig_details != शून्य) {
		अगर ((r = sshbuf_put_u32(m, sig_details->sk_गणक)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	मुक्त(sigalg);
	मुक्त(fp);
	sshkey_free(कुंजी);

	वापस ret == 0;
}

अटल व्योम
mm_record_login(काष्ठा ssh *ssh, Session *s, काष्ठा passwd *pw)
{
	socklen_t fromlen;
	काष्ठा sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	स_रखो(&from, 0, माप(from));
	fromlen = माप(from);
	अगर (ssh_packet_connection_is_on_socket(ssh)) {
		अगर (getpeername(ssh_packet_get_connection_in(ssh),
		    (काष्ठा sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", म_त्रुटि(त्रुटि_सं));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (काष्ठा sockaddr *)&from, fromlen);
}

अटल व्योम
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (दीर्घ)s->pid);
	अगर (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

पूर्णांक
mm_answer_pty(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	बाह्य काष्ठा monitor *pmonitor;
	Session *s;
	पूर्णांक r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	अगर (s == शून्य)
		जाओ error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, माप(s->tty));
	अगर (res == 0)
		जाओ error;
	pty_setowner(authctxt->pw, s->tty);

	अगर ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	अगर (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	बंद(0);

	/* send messages generated by record_login */
	अगर ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	अगर (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	अगर ((fd0 = खोलो(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", म_त्रुटि(त्रुटि_सं));
	अगर (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	बंद(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	वापस (0);

 error:
	अगर (s != शून्य)
		mm_session_close(s);
	अगर ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	वापस (0);
}

पूर्णांक
mm_answer_pty_cleanup(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	Session *s;
	अक्षर *tty;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((r = sshbuf_get_cstring(m, &tty, शून्य)) != 0)
		fatal_fr(r, "parse tty");
	अगर ((s = session_by_tty(tty)) != शून्य)
		mm_session_close(s);
	sshbuf_reset(m);
	मुक्त(tty);
	वापस (0);
}

पूर्णांक
mm_answer_term(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *req)
{
	बाह्य काष्ठा monitor *pmonitor;
	पूर्णांक res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		sshpam_cleanup();
#पूर्ण_अगर

	जबतक (waitpid(pmonitor->m_pid, &status, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			निकास(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	निकास(res);
}

#अगर_घोषित SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
पूर्णांक
mm_answer_audit_event(काष्ठा ssh *ssh, पूर्णांक socket, काष्ठा sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	चयन (event) {
	हाल SSH_AUTH_FAIL_PUBKEY:
	हाल SSH_AUTH_FAIL_HOSTBASED:
	हाल SSH_AUTH_FAIL_GSSAPI:
	हाल SSH_LOGIN_EXCEED_MAXTRIES:
	हाल SSH_LOGIN_मूल_DENIED:
	हाल SSH_CONNECTION_CLOSE:
	हाल SSH_INVALID_USER:
		audit_event(ssh, event);
		अवरोध;
	शेष:
		fatal("Audit event type %d not permitted", event);
	}

	वापस (0);
}

पूर्णांक
mm_answer_audit_command(काष्ठा ssh *ssh, पूर्णांक socket, काष्ठा sshbuf *m)
{
	अक्षर *cmd;
	पूर्णांक r;

	debug3_f("entering");
	अगर ((r = sshbuf_get_cstring(m, &cmd, शून्य)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	मुक्त(cmd);
	वापस (0);
}
#पूर्ण_अगर /* SSH_AUDIT_EVENTS */

व्योम
monitor_clear_keystate(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = शून्य;
}

व्योम
monitor_apply_keystate(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor)
{
	काष्ठा kex *kex;
	पूर्णांक r;

	debug3_f("packet_set_state");
	अगर ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = शून्य;
	अगर ((kex = ssh->kex) == शून्य)
		fatal_f("internal error: ssh->kex == NULL");
	अगर (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	अगर (स_भेद(sshbuf_ptr(ssh->kex->session_id), session_id2,
	    session_id2_len) != 0)
		fatal_f("session ID mismatch");
	/* XXX set callbacks */
#अगर_घोषित WITH_OPENSSL
	kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
#पूर्ण_अगर
	kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	kex->load_host_public_कुंजी=&get_hostkey_public_by_type;
	kex->load_host_private_कुंजी=&get_hostkey_private_by_type;
	kex->host_कुंजी_सूचकांक=&get_hostkey_सूचकांक;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

व्योम
mm_get_keystate(काष्ठा ssh *ssh, काष्ठा monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	अगर ((child_state = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

अटल व्योम
monitor_openfds(काष्ठा monitor *mon, पूर्णांक do_logfds)
{
	पूर्णांक pair[2];
#अगर_घोषित SO_ZEROIZE
	पूर्णांक on = 1;
#पूर्ण_अगर

	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", म_त्रुटि(त्रुटि_सं));
#अगर_घोषित SO_ZEROIZE
	अगर (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, माप(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", म_त्रुटि(त्रुटि_सं));
	अगर (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, माप(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	अगर (do_logfds) {
		अगर (pipe(pair) == -1)
			fatal_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} अन्यथा
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

काष्ठा monitor *
monitor_init(व्योम)
{
	काष्ठा monitor *mon;

	mon = xcalloc(1, माप(*mon));
	monitor_openfds(mon, 1);

	वापस mon;
}

व्योम
monitor_reinit(काष्ठा monitor *mon)
{
	monitor_openfds(mon, 0);
}

पूर्णांक
monitor_auth_attempted(व्योम)
{
	वापस auth_attempted;
}

पूर्णांक
monitor_invalid_user(व्योम)
{
	वापस invalid_user;
}

#अगर_घोषित GSSAPI
पूर्णांक
mm_answer_gss_setup_ctx(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	माप_प्रकार len;
	u_char *p;
	पूर्णांक r;

	अगर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	अगर ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.लंबाई = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	मुक्त(goid.elements);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	वापस (0);
}

पूर्णांक
mm_answer_gss_accept_ctx(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	gss_बफर_desc in;
	gss_बफर_desc out = GSS_C_EMPTY_बफर;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	पूर्णांक r;

	अगर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	अगर ((r = ssh_gssapi_get_बफर_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	मुक्त(in.मूल्य);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.मूल्य, out.लंबाई)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_बफर(&minor, &out);

	अगर (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	वापस (0);
}

पूर्णांक
mm_answer_gss_checkmic(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	gss_बफर_desc gssbuf, mic;
	OM_uint32 ret;
	पूर्णांक r;

	अगर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	अगर ((r = ssh_gssapi_get_बफर_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_बफर_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	मुक्त(gssbuf.मूल्य);
	मुक्त(mic.मूल्य);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	अगर (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	वापस (0);
}

पूर्णांक
mm_answer_gss_userok(काष्ठा ssh *ssh, पूर्णांक sock, काष्ठा sshbuf *m)
{
	पूर्णांक r, authenticated;
	स्थिर अक्षर *displayname;

	अगर (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	अगर ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	अगर ((displayname = ssh_gssapi_displayname()) != शून्य)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	वापस (authenticated);
}
#पूर्ण_अगर /* GSSAPI */

