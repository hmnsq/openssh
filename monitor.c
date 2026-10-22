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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/tree.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/dh.h>
#endif

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "auth-pam.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "session.h"
#அந்தர்பாவ "sshlogin.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "monitor.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "monitor_fdpass.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "srclimit.h"

#ifdef GSSAPI
நிலையான Gssctxt *gsscontext = வெற்று;
#endif

/* Imports */
வெளி ServerOptions options;
வெளி u_int utmp_len;
வெளி கட்டமைப்பு sshbuf *cfg;
வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி கட்டமைப்பு include_list includes;
வெளி கட்டமைப்பு sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
நிலையான கட்டமைப்பு sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

முழு mm_answer_moduli(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_setcompat(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_sign(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pwnamallow(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_auth2_read_banner(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_authserv(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_authpassword(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_bsdauthquery(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_bsdauthrespond(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_keyallowed(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_keyverify(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pty(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pty_cleanup(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_term(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_state(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);

#ifdef USE_PAM
முழு mm_answer_pam_start(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pam_account(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pam_init_ctx(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pam_query(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pam_respond(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_pam_free_ctx(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
#endif

#ifdef GSSAPI
முழு mm_answer_gss_setup_ctx(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_gss_accept_ctx(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_gss_userok(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_gss_checkmic(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
முழு mm_answer_audit_event(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
முழு mm_answer_audit_command(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
#endif

நிலையான Authctxt *authctxt;

/* local state for key verify */
நிலையான u_char *சாவி_blob = வெற்று;
நிலையான size_t சாவி_bloblen = 0;
நிலையான u_int சாவி_blobtype = MM_NOKEY;
நிலையான கட்டமைப்பு sshauthopt *சாவி_opts = வெற்று;
நிலையான எழுத்து *hostbased_cuser = வெற்று;
நிலையான எழுத்து *hostbased_chost = வெற்று;
நிலையான எழுத்து *auth_method = "unknown";
நிலையான எழுத்து *auth_submethod = வெற்று;
நிலையான u_int session_id2_len = 0;
நிலையான u_char *session_id2 = வெற்று;
நிலையான pid_t monitor_child_pid;
நிலையான முழு auth_attempted = 0;
நிலையான முழு invalid_user = 0;
நிலையான முழு compat_set = 0;

கட்டமைப்பு mon_table {
	எண்ணிக்கை monitor_reqtype type;
	முழு flags;
	முழு (*f)(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

நிலையான முழு monitor_read(கட்டமைப்பு ssh *, கட்டமைப்பு monitor *, கட்டமைப்பு mon_table *,
    கட்டமைப்பு mon_table **);
நிலையான முழு monitor_read_log(கட்டமைப்பு monitor *);

கட்டமைப்பு mon_table mon_dispatch_proto20[] = {
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
    {0, 0, வெற்று}
};

கட்டமைப்பு mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, வெற்று}
};

கட்டமைப்பு mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
நிலையான வெறுமை
monitor_permit(கட்டமைப்பு mon_table *ent, எண்ணிக்கை monitor_reqtype type, முழு permit)
{
	போது (ent->f != வெற்று) {
		எனில் (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			திரும்பு;
		}
		ent++;
	}
}

நிலையான வெறுமை
monitor_permit_authentications(முழு permit)
{
	கட்டமைப்பு mon_table *ent = mon_dispatch;

	போது (ent->f != வெற்று) {
		எனில் (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

வெறுமை
monitor_child_preauth(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor)
{
	கட்டமைப்பு mon_table *ent;
	முழு status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	எனில் (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	எனில் (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, அளவு(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	போது (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = வெற்று;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		எனில் ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		எனில் (options.இலக்கம்_auth_methods != 0) {
			எனில் (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		எனில் (authenticated) {
			எனில் (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			எனில் (authctxt->pw->pw_uid == 0 &&
			    !auth_வேர்_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			எனில் (options.use_pam && authenticated) {
				கட்டமைப்பு sshbuf *m;

				எனில் ((m = sshbuf_new()) == வெற்று)
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
		எனில் (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			எனில் (!partial && !authenticated)
				authctxt->failures++;
			எனில் (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		எனில் (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	எனில் (!authctxt->valid)
		fatal_f("authenticated invalid user");
	எனில் (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = வெற்று;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	போது (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	போது (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		எனில் (errno == EINTR)
			தொடர்;
		fatal_f("waitpid: %s", strerror(errno));
	}
	எனில் (WIFEXITED(status)) {
		எனில் (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} இல்லையெனில் எனில் (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	எனில் (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	எனில் (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

நிலையான வெறுமை
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

நிலையான வெறுமை
monitor_child_handler(முழு sig)
{
	kill(monitor_child_pid, sig);
}

வெறுமை
monitor_child_postauth(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor)
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

	எனில் (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	க்கு (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, வெற்று);
}

நிலையான முழு
monitor_read_log(கட்டமைப்பு monitor *pmonitor)
{
	கட்டமைப்பு sshbuf *logmsg;
	u_int len, level, forced;
	எழுத்து *செய்தி;
	u_char *p;
	முழு r;

	எனில் ((logmsg = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");

	/* Read length */
	எனில் ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	எனில் (atomicio(பட, pmonitor->m_log_recvfd, p, 4) != 4) {
		எனில் (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			திரும்பு -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	எனில் ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	எனில் (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	எனில் ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	எனில் (atomicio(பட, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	எனில் ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &செய்தி, வெற்று)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	எனில் (log_level_name(level) == வெற்று)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", செய்தி,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	விடுவி(செய்தி);

	திரும்பு 0;
}

நிலையான முழு
monitor_read(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor, கட்டமைப்பு mon_table *ent,
    கட்டமைப்பு mon_table **pent)
{
	கட்டமைப்பு sshbuf *m;
	முழு r, ret;
	u_char type;
	கட்டமைப்பு pollfd pfd[2];

	க்கு (;;) {
		memset(&pfd, 0, அளவு(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		எனில் (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			எனில் (errno == EINTR || errno == EAGAIN)
				தொடர்;
			fatal_f("poll: %s", strerror(errno));
		}
		எனில் (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			தொடர்;
		}
		எனில் (pfd[0].revents)
			நிறுத்து;  /* Continues below */
	}

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	எனில் ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	போது (ent->f != வெற்று) {
		எனில் (ent->type == type)
			நிறுத்து;
		ent++;
	}

	எனில் (ent->f != வெற்று) {
		எனில் (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		எனில் (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		எனில் (pent != வெற்று)
			*pent = ent;

		திரும்பு ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	திரும்பு (-1);
}

/* allowed key state */
நிலையான முழு
monitor_allowed_சாவி(மாறிலி u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	எனில் (சாவி_blob == வெற்று || சாவி_bloblen != bloblen ||
	    timingsafe_bcmp(சாவி_blob, blob, சாவி_bloblen))
		திரும்பு (0);
	திரும்பு (1);
}

நிலையான வெறுமை
monitor_reset_சாவி_state(வெறுமை)
{
	/* reset state */
	விடுவி(சாவி_blob);
	விடுவி(hostbased_cuser);
	விடுவி(hostbased_chost);
	sshauthopt_free(சாவி_opts);
	சாவி_blob = வெற்று;
	சாவி_bloblen = 0;
	சாவி_blobtype = MM_NOKEY;
	சாவி_opts = வெற்று;
	hostbased_cuser = வெற்று;
	hostbased_chost = வெற்று;
}

முழு
mm_answer_state(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *unused)
{
	கட்டமைப்பு sshbuf *m = வெற்று, *config = வெற்று, *hostkeys = வெற்று;
	கட்டமைப்பு sshbuf *opts = வெற்று, *confdata = வெற்று;
	முழு postauth;
	முழு r;

	debug_f("config len %zu", sshbuf_len(cfg));

	எனில் ((m = sshbuf_new()) == வெற்று ||
	    (config = sshbuf_new()) == வெற்று ||
	    (opts = sshbuf_new()) == வெற்று ||
	    (confdata = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	எனில் ((r = serialise_server_options(&options, &config)) != 0)
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
	எனில் ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	எனில் (postauth) {
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

	திரும்பு (0);
}

#ifdef WITH_OPENSSL
முழு
mm_answer_moduli(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	DH *dh;
	மாறிலி BIGNUM *dh_p, *dh_g;
	முழு r;
	u_int min, want, max;

	எனில் ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	எனில் (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	எனில் (dh == வெற்று) {
		எனில் ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} இல்லையெனில் {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, வெற்று, &dh_g);
		எனில் ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	திரும்பு (0);
}
#endif

முழு
mm_answer_setcompat(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	முழு r;

	debug3_f("entering");

	எனில் ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	திரும்பு (0);
}

முழு
mm_answer_sign(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	வெளி முழு auth_sock;			/* XXX move to state struct? */
	கட்டமைப்பு sshkey *pubkey, *சாவி;
	கட்டமைப்பு sshbuf *sigbuf = வெற்று;
	u_char *p = வெற்று, *signature = வெற்று;
	எழுத்து *alg = வெற்று;
	size_t datlen, siglen;
	முழு r, is_proof = 0, keyid;
	u_int compat;
	மாறிலி எழுத்து proof_req[] = "hostkeys-prove-00@openssh.com";
	நிலையான முழு nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	எனில் (!compat_set)
		fatal_f("state error: setcompat never called");

	எனில் ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	எனில் ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	எனில் (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		எனில் (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		எனில் ((சாவி = get_hostkey_public_by_index(keyid, ssh)) == வெற்று)
			fatal_f("no hostkey for index %d", keyid);
		எனில் (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, அளவு(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		எனில் (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(சாவி), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		எனில் ((sigbuf = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new");
		எனில் ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(சாவி, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		எனில் (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	எனில் (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	எனில் ((சாவி = get_hostkey_by_index(keyid)) != வெற்று) {
		எனில் ((r = sshkey_sign(சாவி, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, வெற்று, compat)) != 0)
			fatal_fr(r, "sign");
	} இல்லையெனில் எனில் ((சாவி = get_hostkey_public_by_index(keyid, ssh)) != வெற்று &&
	    auth_sock > 0) {
		எனில் ((r = ssh_agent_sign(auth_sock, சாவி, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} இல்லையெனில்
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	விடுவி(alg);
	விடுவி(p);
	விடுவி(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	திரும்பு (0);
}

#define PUTPW(b, id) \
	செய் { \
		எனில் ((r = sshbuf_put_string(b, \
		    &pwent->id, அளவு(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} போது (0)

வெறுமை
mm_encode_server_options(கட்டமைப்பு sshbuf *m)
{
	முழு r;
	கட்டமைப்பு sshbuf *config;

	எனில் ((config = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	எனில் ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
முழு
mm_answer_pwnamallow(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	கட்டமைப்பு passwd *pwent;
	முழு r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	எனில் (!compat_set)
		fatal_f("state error: setcompat never called");

	எனில் (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	எனில் ((r = sshbuf_get_cstring(m, &authctxt->user, வெற்று)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	எனில் (pwent == வெற்று) {
		invalid_user = 1;
		எனில் ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		செல் out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	எனில் ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	எனில் ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	எனில் (options.refuse_connection) {
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
	எனில் (auth2_setup_methods_lists(authctxt) != 0) {
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
	எனில் (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	திரும்பு (0);
}

முழு mm_answer_auth2_read_banner(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எழுத்து *banner;
	முழு r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	எனில் ((r = sshbuf_put_cstring(m, banner != வெற்று ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	விடுவி(banner);

	திரும்பு (0);
}

முழு
mm_answer_authserv(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	முழு r;

	monitor_permit_authentications(1);

	எனில் ((r = sshbuf_get_cstring(m, &authctxt->service, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, வெற்று)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	எனில் (strlen(authctxt->style) == 0) {
		விடுவி(authctxt->style);
		authctxt->style = வெற்று;
	}

	திரும்பு (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
நிலையான முழு
சாவி_base_type_match(மாறிலி எழுத்து *method, மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *list)
{
	எழுத்து *s, *l, *ol = xstrdup(list);
	முழு found = 0;

	l = ol;
	க்கு ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		எனில் (sshkey_type_from_name(s) == சாவி->type) {
			found = 1;
			நிறுத்து;
		}
	}
	எனில் (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(சாவி), list);
	}

	விடுவி(ol);
	திரும்பு found;
}

முழு
mm_answer_authpassword(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	நிலையான முழு call_மொத்தம்;
	எழுத்து *passwd;
	முழு r, authenticated;
	size_t plen;

	எனில் (!options.password_authentication)
		fatal_f("password authentication not enabled");
	எனில் ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	எனில் ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_மொத்தம்++;
	எனில் (plen == 0 && call_மொத்தம் == 1)
		auth_method = "none";
	இல்லையெனில்
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	திரும்பு (authenticated);
}

#ifdef BSD_AUTH
முழு
mm_answer_bsdauthquery(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எழுத்து *name, *infotxt;
	u_int numprompts, *echo_on, success;
	எழுத்து **prompts;
	முழு r;

	எனில் (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	எனில் (success) {
		எனில் ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	எனில் (success) {
		விடுவி(name);
		விடுவி(infotxt);
		விடுவி(prompts);
		விடுவி(echo_on);
	}

	திரும்பு (0);
}

முழு
mm_answer_bsdauthrespond(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எழுத்து *response;
	முழு r, authok;

	எனில் (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	எனில் (authctxt->as == வெற்று)
		fatal_f("no bsd auth session");

	எனில் ((r = sshbuf_get_cstring(m, &response, வெற்று)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = வெற்று;
	debug3_f("<%s> = <%d>", response, authok);
	விடுவி(response);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	திரும்பு (authok != 0);
}
#endif

#ifdef USE_PAM
முழு
mm_answer_pam_start(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எனில் (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	எனில் (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	திரும்பு (0);
}

முழு
mm_answer_pam_account(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	u_int ret;
	முழு r;

	எனில் (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	எனில் ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	திரும்பு (ret);
}

நிலையான வெறுமை *sshpam_ctxt, *sshpam_authok;
வெளி KbdintDevice sshpam_device;

முழு
mm_answer_pam_init_ctx(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	u_int ok = 0;
	முழு r;

	debug3_f("entering");
	எனில் (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	எனில் (sshpam_ctxt != வெற்று)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = வெற்று;
	sshbuf_reset(m);
	எனில் (sshpam_ctxt != வெற்று) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	எனில் ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	திரும்பு (0);
}

முழு
mm_answer_pam_query(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எழுத்து *name = வெற்று, *info = வெற்று, **prompts = வெற்று;
	u_int i, இலக்கம் = 0, *echo_on = 0;
	முழு r, ret;

	debug3_f("entering");
	sshpam_authok = வெற்று;
	எனில் (sshpam_ctxt == வெற்று)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &இலக்கம், &prompts, &echo_on);
	எனில் (ret == 0 && இலக்கம் == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	எனில் (இலக்கம் > 1 || name == வெற்று || info == வெற்று)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, இலக்கம்)) != 0)
		fatal_fr(r, "buffer error");
	விடுவி(name);
	விடுவி(info);
	க்கு (i = 0; i < இலக்கம்; ++i) {
		எனில் ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		விடுவி(prompts[i]);
	}
	விடுவி(prompts);
	விடுவி(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	திரும்பு (0);
}

முழு
mm_answer_pam_respond(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	எழுத்து **resp;
	u_int i, இலக்கம்;
	முழு r, ret;

	debug3_f("entering");
	எனில் (sshpam_ctxt == வெற்று)
		fatal_f("no context");
	sshpam_authok = வெற்று;
	எனில் ((r = sshbuf_get_u32(m, &இலக்கம்)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (இலக்கம் > PAM_MAX_இலக்கம்_செய்தி) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    இலக்கம், (unsigned)PAM_MAX_இலக்கம்_செய்தி);
	}
	எனில் (இலக்கம் > 0) {
		resp = xcalloc(இலக்கம், அளவு(எழுத்து *));
		க்கு (i = 0; i < இலக்கம்; ++i) {
			எனில் ((r = sshbuf_get_cstring(m, &(resp[i]), வெற்று)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, இலக்கம், resp);
		க்கு (i = 0; i < இலக்கம்; ++i)
			விடுவி(resp[i]);
		விடுவி(resp);
	} இல்லையெனில் {
		ret = (sshpam_device.respond)(sshpam_ctxt, இலக்கம், வெற்று);
	}
	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	எனில் (ret == 0)
		sshpam_authok = sshpam_ctxt;
	திரும்பு (0);
}

முழு
mm_answer_pam_free_ctx(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	முழு r = sshpam_authok != வெற்று && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	எனில் (sshpam_ctxt == வெற்று)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = வெற்று;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	திரும்பு r;
}
#endif

முழு
mm_answer_keyallowed(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	எழுத்து *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	முழு r, allowed = 0;
	கட்டமைப்பு sshauthopt *opts = வெற்று;

	debug3_f("entering");
	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, வெற்று)) != 0 ||
	    (r = sshkey_froms(m, &சாவி)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	எனில் (சாவி != வெற்று && authctxt->valid) {
		தேர்வு (type) {
		நிலை MM_USERKEY:
			auth_method = "publickey";
			எனில் (!options.pubkey_authentication)
				நிறுத்து;
			எனில் (auth2_சாவி_already_used(authctxt, சாவி))
				நிறுத்து;
			எனில் (!சாவி_base_type_match(auth_method, சாவி,
			    options.pubkey_accepted_algos))
				நிறுத்து;
			allowed = user_சாவி_allowed(ssh, authctxt->pw, சாவி,
			    pubkey_auth_attempt, &opts);
			நிறுத்து;
		நிலை MM_HOSTKEY:
			auth_method = "hostbased";
			எனில் (!options.hostbased_authentication)
				நிறுத்து;
			எனில் (auth2_சாவி_already_used(authctxt, சாவி))
				நிறுத்து;
			எனில் (!சாவி_base_type_match(auth_method, சாவி,
			    options.hostbased_accepted_algos))
				நிறுத்து;
			allowed = hostbased_சாவி_allowed(ssh, authctxt->pw,
			    cuser, chost, சாவி);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			நிறுத்து;
		இயல்பு:
			fatal_f("unknown key type %u", type);
			நிறுத்து;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (சாவி == வெற்று || !authctxt->valid) ? "invalid" : sshkey_type(சாவி),
	    allowed ? "allowed" : "not allowed");

	auth2_record_சாவி(authctxt, 0, சாவி);

	/* clear temporarily storage (used by verify) */
	monitor_reset_சாவி_state();

	எனில் (allowed) {
		/* Save temporarily for comparison in verify */
		எனில் ((r = sshkey_to_blob(சாவி, &சாவி_blob, &சாவி_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		சாவி_blobtype = type;
		சாவி_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} இல்லையெனில் {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, வெற்று);
		விடுவி(cuser);
		விடுவி(chost);
	}
	sshkey_free(சாவி);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	எனில் (opts != வெற்று && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	எனில் (!allowed)
		sshauthopt_free(opts);

	திரும்பு (0);
}

நிலையான முழு
monitor_valid_userblob(கட்டமைப்பு ssh *ssh, மாறிலி u_char *data, u_int datalen)
{
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு sshkey *hostkey = வெற்று;
	மாறிலி u_char *p;
	எழுத்து *userstyle, *cp;
	size_t len;
	u_char type;
	முழு hostbound = 0, r, fail = 0;

	எனில் ((b = sshbuf_from(data, datalen)) == வெற்று)
		fatal_f("sshbuf_from");

	எனில் ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	எனில் ((session_id2 == வெற்று) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	எனில் ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != SSH2_செய்தி_USERAUTH_REQUEST)
		fail++;
	எனில் ((r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	எனில் (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	விடுவி(userstyle);
	விடுவி(cp);
	எனில் ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse method");
	எனில் (strcmp("publickey", cp) != 0) {
		எனில் (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		இல்லையெனில்
			fail++;
	}
	விடுவி(cp);
	எனில் ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	எனில் (type == 0)
		fail++;
	எனில் ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	எனில் (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	எனில் (hostkey != வெற்று) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		எனில் (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	திரும்பு (fail == 0);
}

நிலையான முழு
monitor_valid_hostbasedblob(மாறிலி u_char *data, u_int datalen,
    மாறிலி எழுத்து *cuser, மாறிலி எழுத்து *chost)
{
	கட்டமைப்பு sshbuf *b;
	மாறிலி u_char *p;
	எழுத்து *cp, *userstyle;
	size_t len;
	முழு r, fail = 0;
	u_char type;

	எனில் ((b = sshbuf_from(data, datalen)) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	எனில் ((session_id2 == வெற்று) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	எனில் ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != SSH2_செய்தி_USERAUTH_REQUEST)
		fail++;
	எனில் ((r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	எனில் (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	விடுவி(userstyle);
	விடுவி(cp);
	எனில் ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse method");
	எனில் (strcmp(cp, "hostbased") != 0)
		fail++;
	விடுவி(cp);
	எனில் ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	எனில் ((r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse host");
	எனில் (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	எனில் (strcmp(cp, chost) != 0)
		fail++;
	விடுவி(cp);

	/* verify client user */
	எனில் ((r = sshbuf_get_cstring(b, &cp, வெற்று)) != 0)
		fatal_fr(r, "parse ruser");
	எனில் (strcmp(cp, cuser) != 0)
		fail++;
	விடுவி(cp);

	எனில் (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	திரும்பு (fail == 0);
}

முழு
mm_answer_keyverify(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	கட்டமைப்பு sshkey *சாவி;
	மாறிலி u_char *signature, *data, *blob;
	எழுத்து *sigalg = வெற்று, *fp = வெற்று;
	size_t signaturelen, datalen, bloblen;
	முழு r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	முழு encoded_ret;
	கட்டமைப்பு sshkey_sig_details *sig_details = வெற்று;

	எனில் ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, வெற்று)) != 0)
		fatal_fr(r, "parse");

	எனில் (hostbased_cuser == வெற்று || hostbased_chost == வெற்று ||
	  !monitor_allowed_சாவி(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	எனில் (*sigalg == '\0') {
		விடுவி(sigalg);
		sigalg = வெற்று;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	எனில் ((r = sshkey_from_blob(blob, bloblen, &சாவி)) != 0)
		fatal_fr(r, "parse key");

	தேர்வு (சாவி_blobtype) {
	நிலை MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		நிறுத்து;
	நிலை MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		நிறுத்து;
	இயல்பு:
		valid_data = 0;
		நிறுத்து;
	}
	எனில் (!valid_data)
		fatal_f("bad %s signature data blob",
		    சாவி_blobtype == MM_USERKEY ? "userkey" :
		    (சாவி_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	எனில் ((fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(சாவி, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(சாவி), sigalg == வெற்று ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	எனில் (ret == 0 && சாவி_blobtype == MM_USERKEY && sig_details != வெற்று) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !சாவி_opts->no_require_user_presence;
		எனில் (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(சாவி), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || சாவி_opts->require_verify;
		எனில் (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(சாவி), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_சாவி(authctxt, ret == 0, சாவி);

	எனில் (சாவி_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, சாவி_opts);
	monitor_reset_சாவி_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	எனில் ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != வெற்று)) != 0)
		fatal_fr(r, "assemble");
	எனில் (sig_details != வெற்று) {
		எனில் ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	விடுவி(sigalg);
	விடுவி(fp);
	sshkey_free(சாவி);

	திரும்பு ret == 0;
}

நிலையான வெறுமை
mm_record_login(கட்டமைப்பு ssh *ssh, Session *s, கட்டமைப்பு passwd *pw)
{
	socklen_t fromlen;
	கட்டமைப்பு sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, அளவு(from));
	fromlen = அளவு(from);
	எனில் (ssh_packet_connection_is_on_socket(ssh)) {
		எனில் (getpeername(ssh_packet_get_connection_in(ssh),
		    (கட்டமைப்பு sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (கட்டமைப்பு sockaddr *)&from, fromlen);
}

நிலையான வெறுமை
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	எனில் (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

முழு
mm_answer_pty(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	வெளி கட்டமைப்பு monitor *pmonitor;
	Session *s;
	முழு r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	எனில் (s == வெற்று)
		செல் error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, அளவு(s->tty));
	எனில் (res == 0)
		செல் error;
	pty_setowner(authctxt->pw, s->tty);

	எனில் ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	எனில் (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	எனில் ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	எனில் (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	எனில் ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	எனில் (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	திரும்பு (0);

 error:
	எனில் (s != வெற்று)
		mm_session_close(s);
	எனில் ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	திரும்பு (0);
}

முழு
mm_answer_pty_cleanup(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	Session *s;
	எழுத்து *tty;
	முழு r;

	debug3_f("entering");

	எனில் ((r = sshbuf_get_cstring(m, &tty, வெற்று)) != 0)
		fatal_fr(r, "parse tty");
	எனில் ((s = session_by_tty(tty)) != வெற்று)
		mm_session_close(s);
	sshbuf_reset(m);
	விடுவி(tty);
	திரும்பு (0);
}

முழு
mm_answer_term(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *req)
{
	வெளி கட்டமைப்பு monitor *pmonitor;
	முழு res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	எனில் (options.use_pam)
		sshpam_cleanup();
#endif

	போது (waitpid(pmonitor->m_pid, &status, 0) == -1)
		எனில் (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
முழு
mm_answer_audit_event(கட்டமைப்பு ssh *ssh, முழு socket, கட்டமைப்பு sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	முழு r;

	debug3_f("entering");

	எனில் ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	தேர்வு (event) {
	நிலை SSH_AUTH_FAIL_PUBKEY:
	நிலை SSH_AUTH_FAIL_HOSTBASED:
	நிலை SSH_AUTH_FAIL_GSSAPI:
	நிலை SSH_LOGIN_EXCEED_MAXTRIES:
	நிலை SSH_LOGIN_வேர்_DENIED:
	நிலை SSH_CONNECTION_CLOSE:
	நிலை SSH_INVALID_USER:
		audit_event(ssh, event);
		நிறுத்து;
	இயல்பு:
		fatal("Audit event type %d not permitted", event);
	}

	திரும்பு (0);
}

முழு
mm_answer_audit_command(கட்டமைப்பு ssh *ssh, முழு socket, கட்டமைப்பு sshbuf *m)
{
	எழுத்து *cmd;
	முழு r;

	debug3_f("entering");
	எனில் ((r = sshbuf_get_cstring(m, &cmd, வெற்று)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	விடுவி(cmd);
	திரும்பு (0);
}
#endif /* SSH_AUDIT_EVENTS */

வெறுமை
monitor_clear_keystate(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = வெற்று;
}

வெறுமை
monitor_apply_keystate(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor)
{
	கட்டமைப்பு kex *kex;
	முழு r;

	debug3_f("packet_set_state");
	எனில் ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = வெற்று;
	எனில் ((kex = ssh->kex) == வெற்று)
		fatal_f("internal error: ssh->kex == NULL");
	எனில் (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	எனில் (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_சாவி=&get_hostkey_public_by_type;
	kex->load_host_private_சாவி=&get_hostkey_private_by_type;
	kex->host_சாவி_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

வெறுமை
mm_get_keystate(கட்டமைப்பு ssh *ssh, கட்டமைப்பு monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	எனில் ((child_state = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

நிலையான வெறுமை
monitor_openfds(கட்டமைப்பு monitor *mon, முழு do_logfds)
{
	முழு pair[2];
#ifdef SO_ZEROIZE
	முழு on = 1;
#endif

	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	எனில் (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, அளவு(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	எனில் (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, அளவு(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	எனில் (do_logfds) {
		எனில் (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} இல்லையெனில்
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

கட்டமைப்பு monitor *
monitor_init(வெறுமை)
{
	கட்டமைப்பு monitor *mon;

	mon = xcalloc(1, அளவு(*mon));
	monitor_openfds(mon, 1);

	திரும்பு mon;
}

வெறுமை
monitor_reinit(கட்டமைப்பு monitor *mon)
{
	monitor_openfds(mon, 0);
}

முழு
monitor_auth_attempted(வெறுமை)
{
	திரும்பு auth_attempted;
}

முழு
monitor_invalid_user(வெறுமை)
{
	திரும்பு invalid_user;
}

#ifdef GSSAPI
முழு
mm_answer_gss_setup_ctx(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	முழு r;

	எனில் (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	எனில் ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	விடுவி(goid.elements);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	திரும்பு (0);
}

முழு
mm_answer_gss_accept_ctx(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	முழு r;

	எனில் (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	எனில் ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	விடுவி(in.மதிப்பு);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.மதிப்பு, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	எனில் (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	திரும்பு (0);
}

முழு
mm_answer_gss_checkmic(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	முழு r;

	எனில் (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	எனில் ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	விடுவி(gssbuf.மதிப்பு);
	விடுவி(mic.மதிப்பு);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	எனில் (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	திரும்பு (0);
}

முழு
mm_answer_gss_userok(கட்டமைப்பு ssh *ssh, முழு sock, கட்டமைப்பு sshbuf *m)
{
	முழு r, authenticated;
	மாறிலி எழுத்து *displayname;

	எனில் (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	எனில் ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	எனில் ((displayname = ssh_gssapi_displayname()) != வெற்று)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	திரும்பு (authenticated);
}
#endif /* GSSAPI */

