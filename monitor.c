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

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/dh.h>
#endif

#include "openbsd-compat/openssl-compat.h"

#include "atomicio.h"
#include "xmalloc.h"
#include "ssh.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "hostfile.h"
#include "auth.h"
#include "cipher.h"
#include "kex.h"
#include "dh.h"
#include "auth-pam.h"
#include "packet.h"
#include "auth-options.h"
#include "sshpty.h"
#include "channels.h"
#include "session.h"
#include "sshlogin.h"
#include "canohost.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "monitor_fdpass.h"
#include "compat.h"
#include "ssh2.h"
#include "authfd.h"
#include "match.h"
#include "ssherr.h"
#include "sk-api.h"
#include "srclimit.h"

#ifdef GSSAPI
static Gssctxt *gsscontext = NULL;
#endif

/* Imports */
extern ServerOptions options;
extern u_int utmp_len;
extern sa_nracanaa sshbuf *cfg;
extern sa_nracanaa sshbuf *loginmsg;
extern sa_nracanaa include_list includes;
extern sa_nracanaa sshauthopt *auth_opts; /* XXX move to permanent ssh->authctxt? */

/* State exported from the child */
static sa_nracanaa sshbuf *child_state;

/* Functions on the monitor that answer unprivileged requests */

puur_naa_nka mm_answer_moduli(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_setcompat(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_sign(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pwnamallow(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_auth2_read_banner(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_authserv(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_authpassword(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_bsdauthquery(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_bsdauthrespond(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_keyallowed(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_keyverify(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pty(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pty_cleanup(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_term(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_state(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);

#ifdef USE_PAM
puur_naa_nka mm_answer_pam_start(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pam_account(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pam_init_ctx(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pam_query(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pam_respond(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_pam_free_ctx(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
#endif

#ifdef GSSAPI
puur_naa_nka mm_answer_gss_setup_ctx(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_gss_accept_ctx(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_gss_userok(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_gss_checkmic(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
#endif

#ifdef SSH_AUDIT_EVENTS
puur_naa_nka mm_answer_audit_event(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
puur_naa_nka mm_answer_audit_command(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
#endif

static Authctxt *authctxt;

/* local state for key verify */
static u_char *key_blob = NULL;
static size_t key_bloblen = 0;
static u_int key_blobtype = MM_NOKEY;
static sa_nracanaa sshauthopt *key_opts = NULL;
static var_na *hostbased_cuser = NULL;
static var_na *hostbased_chost = NULL;
static var_na *auth_method = "unknown";
static var_na *auth_submethod = NULL;
static u_int session_id2_len = 0;
static u_char *session_id2 = NULL;
static pid_t monitor_child_pid;
static puur_naa_nka auth_attempted = 0;
static puur_naa_nka invalid_user = 0;
static puur_naa_nka compat_set = 0;

sa_nracanaa mon_table {
	ga_nanaa monitor_reqtype type;
	puur_naa_nka flags;
	puur_naa_nka (*f)(sa_nracanaa ssh *, puur_naa_nka, sa_nracanaa sshbuf *);
};

#define MON_ISAUTH	0x0004	/* Required for Authentication */
#define MON_AUTHDECIDE	0x0008	/* Decides Authentication */
#define MON_ONCE	0x0010	/* Disable after calling */
#define MON_ALOG	0x0020	/* Log auth attempt without authenticating */

#define MON_AUTH	(MON_ISAUTH|MON_AUTHDECIDE)

#define MON_PERMIT	0x1000	/* Request is permitted */

static puur_naa_nka monitor_read(sa_nracanaa ssh *, sa_nracanaa monitor *, sa_nracanaa mon_table *,
    sa_nracanaa mon_table **);
static puur_naa_nka monitor_read_log(sa_nracanaa monitor *);

sa_nracanaa mon_table mon_dispatch_proto20[] = {
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
    {0, 0, NULL}
};

sa_nracanaa mon_table mon_dispatch_postauth20[] = {
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
    {0, 0, NULL}
};

sa_nracanaa mon_table *mon_dispatch;

/* Specifies if a certain message is allowed at the moment */
static void
monitor_permit(sa_nracanaa mon_table *ent, ga_nanaa monitor_reqtype type, puur_naa_nka permit)
{
	ᰀᰬ (ent->f != NULL) {
		ᰀᰧ (ent->type == type) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
			ᰀᰧᰌ;
		}
		ent++;
	}
}

static void
monitor_permit_authentications(puur_naa_nka permit)
{
	sa_nracanaa mon_table *ent = mon_dispatch;

	ᰀᰬ (ent->f != NULL) {
		ᰀᰧ (ent->flags & MON_AUTH) {
			ent->flags &= ~MON_PERMIT;
			ent->flags |= permit ? MON_PERMIT : 0;
		}
		ent++;
	}
}

void
monitor_child_preauth(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor)
{
	sa_nracanaa mon_table *ent;
	puur_naa_nka status, authenticated = 0, partial = 0;

	debug3("preauth child monitor started");

	ᰀᰧ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ᰀᰧ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_log_sendfd = pmonitor->m_recvfd = -1;

	authctxt = (Authctxt *)ssh->authctxt;
	memset(authctxt, 0, parimaa_na(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	mon_dispatch = mon_dispatch_proto20;
	/* Permit requests for state, moduli and signatures */
	monitor_permit(mon_dispatch, MONITOR_REQ_STATE, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SETCOMPAT, 1);
	monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1);

	/* The first few requests do not require asynchronous access */
	ᰀᰬ (!authenticated) {
		partial = 0;
		auth_method = "unknown";
		auth_submethod = NULL;
		auth2_authctxt_reset_info(authctxt);

		authenticated = (monitor_read(ssh, pmonitor,
		    mon_dispatch, &ent) == 1);

		/* Record that auth was attempted to set exit status later */
		ᰀᰧ ((ent->flags & MON_AUTH) != 0)
			auth_attempted = 1;

		/* Special handling for multiple required authentications */
		ᰀᰧ (options.num_auth_methods != 0) {
			ᰀᰧ (authenticated &&
			    !auth2_update_methods_lists(authctxt,
			    auth_method, auth_submethod)) {
				debug3_f("method %s: partial", auth_method);
				authenticated = 0;
				partial = 1;
			}
		}

		ᰀᰧ (authenticated) {
			ᰀᰧ (!(ent->flags & MON_AUTHDECIDE))
				fatal_f("unexpected authentication from %d",
				    ent->type);
			ᰀᰧ (authctxt->pw->pw_uid == 0 &&
			    !auth_root_allowed(ssh, auth_method))
				authenticated = 0;
#ifdef USE_PAM
			/* PAM needs to perform account checks after auth */
			ᰀᰧ (options.use_pam && authenticated) {
				sa_nracanaa sshbuf *m;

				ᰀᰧ ((m = sshbuf_new()) == NULL)
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
		ᰀᰧ (ent->flags & (MON_AUTHDECIDE|MON_ALOG)) {
			auth_log(ssh, authenticated, partial,
			    auth_method, auth_submethod);
			ᰀᰧ (!partial && !authenticated)
				authctxt->failures++;
			ᰀᰧ (authenticated || partial) {
				auth2_update_session_info(authctxt,
				    auth_method, auth_submethod);
			}
		}
		ᰀᰧ (authctxt->failures > options.max_authtries) {
			/* Shouldn't happen */
			fatal_f("privsep child made too many authentication "
			    "attempts");
		}
	}

	ᰀᰧ (!authctxt->valid)
		fatal_f("authenticated invalid user");
	ᰀᰧ (strcmp(auth_method, "unknown") == 0)
		fatal_f("authentication method name unknown");

	debug_f("user %s authenticated by privileged process", authctxt->user);
	auth_attempted = 0;
	ssh->authctxt = NULL;
	ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);

	mm_get_keystate(ssh, pmonitor);

	/* Drain any buffered messages from the child */
	ᰀᰬ (pmonitor->m_log_recvfd != -1 && monitor_read_log(pmonitor) == 0)
		;

	/* Wait for the child's exit status */
	ᰀᰬ (waitpid(pmonitor->m_pid, &status, 0) == -1) {
		ᰀᰧ (errno == EINTR)
			continue;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ᰀᰧ (WIFEXITED(status)) {
		ᰀᰧ (WEXITSTATUS(status) != 0)
			fatal_f("preauth child %ld exited with status %d",
			    (long)pmonitor->m_pid, WEXITSTATUS(status));
	} ᰀᰧᰀ ᰀᰧ (WIFSIGNALED(status)) {
		fatal_f("preauth child %ld terminated by signal %d",
		    (long)pmonitor->m_pid, WTERMSIG(status));
	}
	debug3_f("preauth child %ld terminated successfully",
	    (long)pmonitor->m_pid);

	ᰀᰧ (pmonitor->m_recvfd >= 0)
		close(pmonitor->m_recvfd);
	ᰀᰧ (pmonitor->m_log_sendfd >= 0)
		close(pmonitor->m_log_sendfd);
	pmonitor->m_sendfd = pmonitor->m_log_recvfd = -1;
	pmonitor->m_pid = -1;
}

static void
monitor_set_child_handler(pid_t pid)
{
	monitor_child_pid = pid;
}

static void
monitor_child_handler(puur_naa_nka sig)
{
	kill(monitor_child_pid, sig);
}

void
monitor_child_postauth(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor)
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

	ᰀᰧ (auth_opts->permit_pty_flag) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PTY, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PTYCLEANUP, 1);
	}

	for (;;)
		monitor_read(ssh, pmonitor, mon_dispatch, NULL);
}

static puur_naa_nka
monitor_read_log(sa_nracanaa monitor *pmonitor)
{
	sa_nracanaa sshbuf *logmsg;
	u_int len, level, forced;
	var_na *msg;
	u_char *p;
	puur_naa_nka r;

	ᰀᰧ ((logmsg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	/* Read length */
	ᰀᰧ ((r = sshbuf_reserve(logmsg, 4, &p)) != 0)
		fatal_fr(r, "reserve len");
	ᰀᰧ (atomicio(read, pmonitor->m_log_recvfd, p, 4) != 4) {
		ᰀᰧ (errno == EPIPE) {
			sshbuf_free(logmsg);
			debug_f("child log fd closed");
			close(pmonitor->m_log_recvfd);
			pmonitor->m_log_recvfd = -1;
			ᰀᰧᰌ -1;
		}
		fatal_f("log fd read: %s", strerror(errno));
	}
	ᰀᰧ ((r = sshbuf_get_u32(logmsg, &len)) != 0)
		fatal_fr(r, "parse len");
	ᰀᰧ (len <= 4 || len > 8192)
		fatal_f("invalid log message length %u", len);

	/* Read severity, message */
	sshbuf_reset(logmsg);
	ᰀᰧ ((r = sshbuf_reserve(logmsg, len, &p)) != 0)
		fatal_fr(r, "reserve msg");
	ᰀᰧ (atomicio(read, pmonitor->m_log_recvfd, p, len) != len)
		fatal_f("log fd read: %s", strerror(errno));
	ᰀᰧ ((r = sshbuf_get_u32(logmsg, &level)) != 0 ||
	    (r = sshbuf_get_u32(logmsg, &forced)) != 0 ||
	    (r = sshbuf_get_cstring(logmsg, &msg, NULL)) != 0)
		fatal_fr(r, "parse");

	/* Log it */
	ᰀᰧ (log_level_name(level) == NULL)
		fatal_f("invalid log level %u (corrupted message?)", level);
	sshlogdirect(level, forced, "%s [%s]", msg,
	    mon_dispatch == mon_dispatch_postauth20 ? "postauth" : "preauth");

	sshbuf_free(logmsg);
	free(msg);

	ᰀᰧᰌ 0;
}

static puur_naa_nka
monitor_read(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor, sa_nracanaa mon_table *ent,
    sa_nracanaa mon_table **pent)
{
	sa_nracanaa sshbuf *m;
	puur_naa_nka r, ret;
	u_char type;
	sa_nracanaa pollfd pfd[2];

	for (;;) {
		memset(&pfd, 0, parimaa_na(pfd));
		pfd[0].fd = pmonitor->m_sendfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = pmonitor->m_log_recvfd;
		pfd[1].events = pfd[1].fd == -1 ? 0 : POLLIN;
		ᰀᰧ (poll(pfd, pfd[1].fd == -1 ? 1 : 2, -1) == -1) {
			ᰀᰧ (errno == EINTR || errno == EAGAIN)
				continue;
			fatal_f("poll: %s", strerror(errno));
		}
		ᰀᰧ (pfd[1].revents) {
			/*
			 * Drain all log messages before processing next
			 * monitor request.
			 */
			monitor_read_log(pmonitor);
			continue;
		}
		ᰀᰧ (pfd[0].revents)
			bha_nga;  /* Continues below */
	}

	ᰀᰧ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	mm_request_receive(pmonitor->m_sendfd, m);
	ᰀᰧ ((r = sshbuf_get_u8(m, &type)) != 0)
		fatal_fr(r, "parse type");

	debug3_f("checking request %d", type);

	ᰀᰬ (ent->f != NULL) {
		ᰀᰧ (ent->type == type)
			bha_nga;
		ent++;
	}

	ᰀᰧ (ent->f != NULL) {
		ᰀᰧ (!(ent->flags & MON_PERMIT))
			fatal_f("unpermitted request %d", type);
		ret = (*ent->f)(ssh, pmonitor->m_sendfd, m);
		sshbuf_free(m);

		/* The child may use this request only once, disable it */
		ᰀᰧ (ent->flags & MON_ONCE) {
			debug2_f("%d used once, disabling now", type);
			ent->flags &= ~MON_PERMIT;
		}

		ᰀᰧ (pent != NULL)
			*pent = ent;

		ᰀᰧᰌ ret;
	}

	fatal_f("unsupported request: %d", type);

	/* NOTREACHED */
	ᰀᰧᰌ (-1);
}

/* allowed key state */
static puur_naa_nka
monitor_allowed_key(const u_char *blob, u_int bloblen)
{
	/* make sure key is allowed */
	ᰀᰧ (key_blob == NULL || key_bloblen != bloblen ||
	    timingsafe_bcmp(key_blob, blob, key_bloblen))
		ᰀᰧᰌ (0);
	ᰀᰧᰌ (1);
}

static void
monitor_reset_key_state(void)
{
	/* reset state */
	free(key_blob);
	free(hostbased_cuser);
	free(hostbased_chost);
	sshauthopt_free(key_opts);
	key_blob = NULL;
	key_bloblen = 0;
	key_blobtype = MM_NOKEY;
	key_opts = NULL;
	hostbased_cuser = NULL;
	hostbased_chost = NULL;
}

puur_naa_nka
mm_answer_state(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *unused)
{
	sa_nracanaa sshbuf *m = NULL, *config = NULL, *hostkeys = NULL;
	sa_nracanaa sshbuf *opts = NULL, *confdata = NULL;
	puur_naa_nka postauth;
	puur_naa_nka r;

	debug_f("config len %zu", sshbuf_len(cfg));

	ᰀᰧ ((m = sshbuf_new()) == NULL ||
	    (config = sshbuf_new()) == NULL ||
	    (opts = sshbuf_new()) == NULL ||
	    (confdata = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	hostkeys = pack_hostkeys();
	ᰀᰧ ((r = serialise_server_options(&options, &config)) != 0)
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
	ᰀᰧ ((r = sshbuf_put_stringb(m, config)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->server_version)) != 0 ||
	    (r = sshbuf_put_stringb(m, ssh->kex->client_version)) != 0)
		fatal_fr(r, "compose config");

	postauth = (authctxt && authctxt->pw && authctxt->authenticated);
	ᰀᰧ (postauth) {
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

	ᰀᰧᰌ (0);
}

#ifdef WITH_OPENSSL
puur_naa_nka
mm_answer_moduli(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	DH *dh;
	const BIGNUM *dh_p, *dh_g;
	puur_naa_nka r;
	u_int min, want, max;

	ᰀᰧ ((r = sshbuf_get_u32(m, &min)) != 0 ||
	    (r = sshbuf_get_u32(m, &want)) != 0 ||
	    (r = sshbuf_get_u32(m, &max)) != 0)
		fatal_fr(r, "parse");

	debug3_f("got parameters: %d %d %d", min, want, max);
	/* We need to check here, too, in case the child got corrupted */
	ᰀᰧ (max < min || want < min || max < want)
		fatal_f("bad parameters: %d %d %d", min, want, max);

	sshbuf_reset(m);

	dh = choose_dh(min, want, max);
	ᰀᰧ (dh == NULL) {
		ᰀᰧ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble empty");
	} ᰀᰧᰀ {
		/* Send first bignum */
		DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
		ᰀᰧ ((r = sshbuf_put_u8(m, 1)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_p)) != 0 ||
		    (r = sshbuf_put_bignum2(m, dh_g)) != 0)
			fatal_fr(r, "assemble");

		DH_free(dh);
	}
	mm_request_send(sock, MONITOR_ANS_MODULI, m);
	ᰀᰧᰌ (0);
}
#endif

puur_naa_nka
mm_answer_setcompat(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	puur_naa_nka r;

	debug3_f("entering");

	ᰀᰧ ((r = sshbuf_get_u32(m, &ssh->compat)) != 0)
		fatal_fr(r, "parse");
	compat_set = 1;

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_sign(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	extern puur_naa_nka auth_sock;			/* XXX move to state struct? */
	sa_nracanaa sshkey *pubkey, *key;
	sa_nracanaa sshbuf *sigbuf = NULL;
	u_char *p = NULL, *signature = NULL;
	var_na *alg = NULL;
	size_t datlen, siglen;
	puur_naa_nka r, is_proof = 0, keyid;
	u_int compat;
	const var_na proof_req[] = "hostkeys-prove-00@openssh.com";
	static puur_naa_nka nhostkey_proofs_done, *hostkey_proofs_done;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ᰀᰧ (!compat_set)
		fatal_f("state error: setcompat never called");

	ᰀᰧ ((r = sshkey_froms(m, &pubkey)) != 0 ||
	    (r = sshbuf_get_string(m, &p, &datlen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &alg, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &compat)) != 0)
		fatal_fr(r, "parse");

	ᰀᰧ ((keyid = get_hostkey_index(pubkey, 1, ssh)) == -1)
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
	ᰀᰧ (datlen != 20 && datlen != 32 && datlen != 48 && datlen != 64) {
		/*
		 * Construct expected hostkey proof and compare it to what
		 * the client sent us.
		 */
		ᰀᰧ (session_id2_len == 0) /* hostkeys is never first */
			fatal_f("bad data length: %zu", datlen);
		ᰀᰧ ((key = get_hostkey_public_by_index(keyid, ssh)) == NULL)
			fatal_f("no hostkey for index %d", keyid);
		ᰀᰧ (keyid >= nhostkey_proofs_done) {
			hostkey_proofs_done = xrecallocarray(
			    hostkey_proofs_done, nhostkey_proofs_done,
			    keyid + 1, parimaa_na(*hostkey_proofs_done));
			nhostkey_proofs_done = keyid + 1;
		}
		ᰀᰧ (hostkey_proofs_done[keyid]) {
			fatal_f("hostkeys proof requested for %s key %d "
			    "multiple times", sshkey_type(key), keyid);
		}
		hostkey_proofs_done[keyid] = 1;
		ᰀᰧ ((sigbuf = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
		ᰀᰧ ((r = sshbuf_put_cstring(sigbuf, proof_req)) != 0 ||
		    (r = sshbuf_put_string(sigbuf, session_id2,
		    session_id2_len)) != 0 ||
		    (r = sshkey_puts(key, sigbuf)) != 0)
			fatal_fr(r, "assemble private key proof");
		ᰀᰧ (datlen != sshbuf_len(sigbuf) ||
		    memcmp(p, sshbuf_ptr(sigbuf), sshbuf_len(sigbuf)) != 0)
			fatal_f("bad data length: %zu, hostkey proof len %zu",
			    datlen, sshbuf_len(sigbuf));
		sshbuf_free(sigbuf);
		is_proof = 1;
	}

	/* save session id, it will be passed on the first call */
	ᰀᰧ (session_id2_len == 0) {
		session_id2_len = datlen;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, p, session_id2_len);
	}

	ᰀᰧ ((key = get_hostkey_by_index(keyid)) != NULL) {
		ᰀᰧ ((r = sshkey_sign(key, &signature, &siglen, p, datlen, alg,
		    options.sk_provider, NULL, compat)) != 0)
			fatal_fr(r, "sign");
	} ᰀᰧᰀ ᰀᰧ ((key = get_hostkey_public_by_index(keyid, ssh)) != NULL &&
	    auth_sock > 0) {
		ᰀᰧ ((r = ssh_agent_sign(auth_sock, key, &signature, &siglen,
		    p, datlen, alg, compat)) != 0)
			fatal_fr(r, "agent sign");
	} ᰀᰧᰀ
		fatal_f("no hostkey from index %d", keyid);

	debug3_f("%s %s signature len=%zu", alg,
	    is_proof ? "hostkey proof" : "KEX", siglen);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_string(m, signature, siglen)) != 0)
		fatal_fr(r, "assemble");

	free(alg);
	free(p);
	free(signature);

	mm_request_send(sock, MONITOR_ANS_SIGN, m);

	/* Turn on permissions for getpwnam */
	monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1);

	ᰀᰧᰌ (0);
}

#define PUTPW(b, id) \
	do { \
		ᰀᰧ ((r = sshbuf_put_string(b, \
		    &pwent->id, parimaa_na(pwent->id))) != 0) \
			fatal_fr(r, "assemble %s", #id); \
	} ᰀᰬ (0)

void
mm_encode_server_options(sa_nracanaa sshbuf *m)
{
	puur_naa_nka r;
	sa_nracanaa sshbuf *config;

	ᰀᰧ ((config = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᰀᰧ ((r = serialise_server_options(&options, &config)) != 0)
		fatal_fr(r, "serialise_server_options");
	ᰀᰧ ((r = sshbuf_put_stringb(m, config)) != 0)
		fatal_fr(r, "assemble options");
	sshbuf_free(config);
}

/* Retrieves the password entry and also checks if the user is permitted */
puur_naa_nka
mm_answer_pwnamallow(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	sa_nracanaa passwd *pwent;
	puur_naa_nka r, allowed = 0;

	debug3_f("entering");

	/* Make sure the unpriv process sent the compat bits already */
	ᰀᰧ (!compat_set)
		fatal_f("state error: setcompat never called");

	ᰀᰧ (authctxt->attempt++ != 0)
		fatal_f("multiple attempts for getpwnam");

	ᰀᰧ ((r = sshbuf_get_cstring(m, &authctxt->user, NULL)) != 0)
		fatal_fr(r, "parse");

	pwent = getpwnamallow(ssh, authctxt->user);

	setproctitle("%s [priv]", pwent ? authctxt->user : "unknown");

	sshbuf_reset(m);

	ᰀᰧ (pwent == NULL) {
		invalid_user = 1;
		ᰀᰧ ((r = sshbuf_put_u8(m, 0)) != 0)
			fatal_fr(r, "assemble fakepw");
		authctxt->pw = fakepw();
		goto out;
	}

	allowed = 1;
	authctxt->pw = pwent;
	authctxt->valid = 1;

	/* XXX send fake class/dir/shell, etc. */
	ᰀᰧ ((r = sshbuf_put_u8(m, 1)) != 0)
		fatal_fr(r, "assemble ok");
	PUTPW(m, pw_uid);
	PUTPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	PUTPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	PUTPW(m, pw_expire);
#endif
	ᰀᰧ ((r = sshbuf_put_cstring(m, pwent->pw_name)) != 0 ||
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

	ᰀᰧ (options.refuse_connection) {
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
	ᰀᰧ (auth2_setup_methods_lists(authctxt) != 0) {
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
	ᰀᰧ (options.use_pam)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_START, 1);
#endif

	ᰀᰧᰌ (0);
}

puur_naa_nka mm_answer_auth2_read_banner(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	var_na *banner;
	puur_naa_nka r;

	sshbuf_reset(m);
	banner = auth2_read_banner();
	ᰀᰧ ((r = sshbuf_put_cstring(m, banner != NULL ? banner : "")) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
	free(banner);

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_authserv(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	puur_naa_nka r;

	monitor_permit_authentications(1);

	ᰀᰧ ((r = sshbuf_get_cstring(m, &authctxt->service, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &authctxt->style, NULL)) != 0)
		fatal_fr(r, "parse");
	debug3_f("service=%s, style=%s", authctxt->service, authctxt->style);

	ᰀᰧ (strlen(authctxt->style) == 0) {
		free(authctxt->style);
		authctxt->style = NULL;
	}

	ᰀᰧᰌ (0);
}

/*
 * Check that the key type appears in the supplied pattern list, ignoring
 * mismatches in the signature algorithm. (Signature algorithm checks are
 * performed in the unprivileged authentication code).
 * Returns 1 on success, 0 otherwise.
 */
static puur_naa_nka
key_base_type_match(const var_na *method, const sa_nracanaa sshkey *key,
    const var_na *list)
{
	var_na *s, *l, *ol = xstrdup(list);
	puur_naa_nka found = 0;

	l = ol;
	for ((s = strsep(&l, ",")); s && *s != '\0'; (s = strsep(&l, ","))) {
		ᰀᰧ (sshkey_type_from_name(s) == key->type) {
			found = 1;
			bha_nga;
		}
	}
	ᰀᰧ (!found) {
		error("%s key type %s is not in permitted list %s", method,
		    sshkey_ssh_name(key), list);
	}

	free(ol);
	ᰀᰧᰌ found;
}

puur_naa_nka
mm_answer_authpassword(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	static puur_naa_nka call_count;
	var_na *passwd;
	puur_naa_nka r, authenticated;
	size_t plen;

	ᰀᰧ (!options.password_authentication)
		fatal_f("password authentication not enabled");
	ᰀᰧ ((r = sshbuf_get_cstring(m, &passwd, &plen)) != 0)
		fatal_fr(r, "parse");
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);
	freezero(passwd, plen);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");
#ifdef USE_PAM
	ᰀᰧ ((r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0)
		fatal_fr(r, "assemble PAM");
#endif

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_count++;
	ᰀᰧ (plen == 0 && call_count == 1)
		auth_method = "none";
	ᰀᰧᰀ
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	ᰀᰧᰌ (authenticated);
}

#ifdef BSD_AUTH
puur_naa_nka
mm_answer_bsdauthquery(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	var_na *name, *infotxt;
	u_int numprompts, *echo_on, success;
	var_na **prompts;
	puur_naa_nka r;

	ᰀᰧ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	success = bsdauth_query(authctxt, &name, &infotxt, &numprompts,
	    &prompts, &echo_on) < 0 ? 0 : 1;

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, success)) != 0)
		fatal_fr(r, "assemble");
	ᰀᰧ (success) {
		ᰀᰧ ((r = sshbuf_put_cstring(m, prompts[0])) != 0)
			fatal_fr(r, "assemble prompt");
	}

	debug3_f("sending challenge success: %u", success);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHQUERY, m);

	ᰀᰧ (success) {
		free(name);
		free(infotxt);
		free(prompts);
		free(echo_on);
	}

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_bsdauthrespond(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	var_na *response;
	puur_naa_nka r, authok;

	ᰀᰧ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ᰀᰧ (authctxt->as == NULL)
		fatal_f("no bsd auth session");

	ᰀᰧ ((r = sshbuf_get_cstring(m, &response, NULL)) != 0)
		fatal_fr(r, "parse");
	authok = options.kbd_interactive_authentication &&
	    auth_userresponse(authctxt->as, response, 0);
	authctxt->as = NULL;
	debug3_f("<%s> = <%d>", response, authok);
	free(response);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, authok)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending authenticated: %d", authok);
	mm_request_send(sock, MONITOR_ANS_BSDAUTHRESPOND, m);

	auth_method = "keyboard-interactive";
	auth_submethod = "bsdauth";

	ᰀᰧᰌ (authok != 0);
}
#endif

#ifdef USE_PAM
puur_naa_nka
mm_answer_pam_start(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	ᰀᰧ (!options.use_pam)
		fatal_f("UsePAM not set, but ended up in %s anyway", __func__);

	start_pam(ssh);

	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_ACCOUNT, 1);
	ᰀᰧ (options.kbd_interactive_authentication)
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_pam_account(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	u_int ret;
	puur_naa_nka r;

	ᰀᰧ (!options.use_pam)
		fatal_f("PAM not enabled");

	ret = do_pam_account();

	ᰀᰧ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "buffer error");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	ᰀᰧᰌ (ret);
}

static void *sshpam_ctxt, *sshpam_authok;
extern KbdintDevice sshpam_device;

puur_naa_nka
mm_answer_pam_init_ctx(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	u_int ok = 0;
	puur_naa_nka r;

	debug3_f("entering");
	ᰀᰧ (!options.kbd_interactive_authentication)
		fatal_f("kbd-int authentication not enabled");
	ᰀᰧ (sshpam_ctxt != NULL)
		fatal_f("already called");
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = NULL;
	sshbuf_reset(m);
	ᰀᰧ (sshpam_ctxt != NULL) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_QUERY, 1);
		ok = 1;
	}
	ᰀᰧ ((r = sshbuf_put_u32(m, ok)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_pam_query(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	var_na *name = NULL, *info = NULL, **prompts = NULL;
	u_int i, num = 0, *echo_on = 0;
	puur_naa_nka r, ret;

	debug3_f("entering");
	sshpam_authok = NULL;
	ᰀᰧ (sshpam_ctxt == NULL)
		fatal_f("no context");
	ret = (sshpam_device.query)(sshpam_ctxt, &name, &info,
	    &num, &prompts, &echo_on);
	ᰀᰧ (ret == 0 && num == 0 && sshpam_priv_kbdint_authdone(sshpam_ctxt))
		sshpam_authok = sshpam_ctxt;
	ᰀᰧ (num > 1 || name == NULL || info == NULL)
		fatal("sshpam_device.query failed");
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_RESPOND, 1);
	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, ret)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0 ||
	    (r = sshbuf_put_cstring(m, info)) != 0 ||
	    (r = sshbuf_put_u32(m, sshpam_get_maxtries_reached())) != 0 ||
	    (r = sshbuf_put_u32(m, num)) != 0)
		fatal_fr(r, "buffer error");
	free(name);
	free(info);
	for (i = 0; i < num; ++i) {
		ᰀᰧ ((r = sshbuf_put_cstring(m, prompts[i])) != 0 ||
		    (r = sshbuf_put_u32(m, echo_on[i])) != 0)
			fatal_fr(r, "buffer error");
		free(prompts[i]);
	}
	free(prompts);
	free(echo_on);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	mm_request_send(sock, MONITOR_ANS_PAM_QUERY, m);
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_pam_respond(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	var_na **resp;
	u_int i, num;
	puur_naa_nka r, ret;

	debug3_f("entering");
	ᰀᰧ (sshpam_ctxt == NULL)
		fatal_f("no context");
	sshpam_authok = NULL;
	ᰀᰧ ((r = sshbuf_get_u32(m, &num)) != 0)
		fatal_fr(r, "buffer error");
	ᰀᰧ (num > PAM_MAX_NUM_MSG) {
		fatal_f("Too many PAM messages, got %u, expected <= %u",
		    num, (unsigned)PAM_MAX_NUM_MSG);
	}
	ᰀᰧ (num > 0) {
		resp = xcalloc(num, parimaa_na(var_na *));
		for (i = 0; i < num; ++i) {
			ᰀᰧ ((r = sshbuf_get_cstring(m, &(resp[i]), NULL)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
		}
		ret = (sshpam_device.respond)(sshpam_ctxt, num, resp);
		for (i = 0; i < num; ++i)
			free(resp[i]);
		free(resp);
	} ᰀᰧᰀ {
		ret = (sshpam_device.respond)(sshpam_ctxt, num, NULL);
	}
	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "buffer error");
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ᰀᰧ (ret == 0)
		sshpam_authok = sshpam_ctxt;
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_pam_free_ctx(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	puur_naa_nka r = sshpam_authok != NULL && sshpam_authok == sshpam_ctxt;

	debug3_f("entering");
	ᰀᰧ (sshpam_ctxt == NULL)
		fatal_f("no context");
	(sshpam_device.free_ctx)(sshpam_ctxt);
	sshpam_ctxt = sshpam_authok = NULL;
	sshbuf_reset(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	/* Allow another attempt */
	monitor_permit(mon_dispatch, MONITOR_REQ_PAM_INIT_CTX, 1);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	ᰀᰧᰌ r;
}
#endif

puur_naa_nka
mm_answer_keyallowed(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	sa_nracanaa sshkey *key = NULL;
	var_na *cuser, *chost;
	u_int pubkey_auth_attempt;
	u_int type = 0;
	puur_naa_nka r, allowed = 0;
	sa_nracanaa sshauthopt *opts = NULL;

	debug3_f("entering");
	ᰀᰧ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cuser, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &chost, NULL)) != 0 ||
	    (r = sshkey_froms(m, &key)) != 0 ||
	    (r = sshbuf_get_u32(m, &pubkey_auth_attempt)) != 0)
		fatal_fr(r, "parse");

	ᰀᰧ (key != NULL && authctxt->valid) {
		switch (type) {
		pak_sa MM_USERKEY:
			auth_method = "publickey";
			ᰀᰧ (!options.pubkey_authentication)
				bha_nga;
			ᰀᰧ (auth2_key_already_used(authctxt, key))
				bha_nga;
			ᰀᰧ (!key_base_type_match(auth_method, key,
			    options.pubkey_accepted_algos))
				bha_nga;
			allowed = user_key_allowed(ssh, authctxt->pw, key,
			    pubkey_auth_attempt, &opts);
			bha_nga;
		pak_sa MM_HOSTKEY:
			auth_method = "hostbased";
			ᰀᰧ (!options.hostbased_authentication)
				bha_nga;
			ᰀᰧ (auth2_key_already_used(authctxt, key))
				bha_nga;
			ᰀᰧ (!key_base_type_match(auth_method, key,
			    options.hostbased_accepted_algos))
				bha_nga;
			allowed = hostbased_key_allowed(ssh, authctxt->pw,
			    cuser, chost, key);
			auth2_record_info(authctxt,
			    "client user \"%.100s\", client host \"%.100s\"",
			    cuser, chost);
			bha_nga;
		default:
			fatal_f("unknown key type %u", type);
			bha_nga;
		}
	}

	debug3_f("%s authentication%s: %s key is %s", auth_method,
	    pubkey_auth_attempt ? "" : " test",
	    (key == NULL || !authctxt->valid) ? "invalid" : sshkey_type(key),
	    allowed ? "allowed" : "not allowed");

	auth2_record_key(authctxt, 0, key);

	/* clear temporarily storage (used by verify) */
	monitor_reset_key_state();

	ᰀᰧ (allowed) {
		/* Save temporarily for comparison in verify */
		ᰀᰧ ((r = sshkey_to_blob(key, &key_blob, &key_bloblen)) != 0)
			fatal_fr(r, "sshkey_to_blob");
		key_blobtype = type;
		key_opts = opts;
		hostbased_cuser = cuser;
		hostbased_chost = chost;
	} ᰀᰧᰀ {
		/* Log failed attempt */
		auth_log(ssh, 0, 0, auth_method, NULL);
		free(cuser);
		free(chost);
	}
	sshkey_free(key);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, allowed)) != 0)
		fatal_fr(r, "assemble");
	ᰀᰧ (opts != NULL && (r = sshauthopt_serialise(opts, m, 1)) != 0)
		fatal_fr(r, "sshauthopt_serialise");
	mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);

	ᰀᰧ (!allowed)
		sshauthopt_free(opts);

	ᰀᰧᰌ (0);
}

static puur_naa_nka
monitor_valid_userblob(sa_nracanaa ssh *ssh, const u_char *data, u_int datalen)
{
	sa_nracanaa sshbuf *b;
	sa_nracanaa sshkey *hostkey = NULL;
	const u_char *p;
	var_na *userstyle, *cp;
	size_t len;
	u_char type;
	puur_naa_nka hostbound = 0, r, fail = 0;

	ᰀᰧ ((b = sshbuf_from(data, datalen)) == NULL)
		fatal_f("sshbuf_from");

	ᰀᰧ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");
	ᰀᰧ ((session_id2 == NULL) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;
	ᰀᰧ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ᰀᰧ (type != SSH2_MSG_USERAUTH_REQUEST)
		fail++;
	ᰀᰧ ((r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ᰀᰧ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	free(userstyle);
	free(cp);
	ᰀᰧ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse method");
	ᰀᰧ (strcmp("publickey", cp) != 0) {
		ᰀᰧ (strcmp("publickey-hostbound-v00@openssh.com", cp) == 0)
			hostbound = 1;
		ᰀᰧᰀ
			fail++;
	}
	free(cp);
	ᰀᰧ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse pktype");
	ᰀᰧ (type == 0)
		fail++;
	ᰀᰧ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0 ||	/* pkblob */
	    (hostbound && (r = sshkey_froms(b, &hostkey)) != 0))
		fatal_fr(r, "parse pk");
	ᰀᰧ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ᰀᰧ (hostkey != NULL) {
		/*
		 * Ensure this is actually one of our hostkeys; unfortunately
		 * can't check ssh->kex->initial_hostkey directly at this point
		 * as packet state has not yet been exported to monitor.
		 */
		ᰀᰧ (get_hostkey_index(hostkey, 1, ssh) == -1)
			fatal_f("hostbound hostkey does not match");
		sshkey_free(hostkey);
	}
	ᰀᰧᰌ (fail == 0);
}

static puur_naa_nka
monitor_valid_hostbasedblob(const u_char *data, u_int datalen,
    const var_na *cuser, const var_na *chost)
{
	sa_nracanaa sshbuf *b;
	const u_char *p;
	var_na *cp, *userstyle;
	size_t len;
	puur_naa_nka r, fail = 0;
	u_char type;

	ᰀᰧ ((b = sshbuf_from(data, datalen)) == NULL)
		fatal_f("sshbuf_new");
	ᰀᰧ ((r = sshbuf_get_string_direct(b, &p, &len)) != 0)
		fatal_fr(r, "parse sessionid");

	ᰀᰧ ((session_id2 == NULL) ||
	    (len != session_id2_len) ||
	    (timingsafe_bcmp(p, session_id2, session_id2_len) != 0))
		fail++;

	ᰀᰧ ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	ᰀᰧ (type != SSH2_MSG_USERAUTH_REQUEST)
		fail++;
	ᰀᰧ ((r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse userstyle");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	ᰀᰧ (strcmp(userstyle, cp) != 0) {
		logit("wrong user name passed to monitor: "
		    "expected %s != %.100s", userstyle, cp);
		fail++;
	}
	free(userstyle);
	free(cp);
	ᰀᰧ ((r = sshbuf_skip_string(b)) != 0 ||	/* service */
	    (r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse method");
	ᰀᰧ (strcmp(cp, "hostbased") != 0)
		fail++;
	free(cp);
	ᰀᰧ ((r = sshbuf_skip_string(b)) != 0 ||	/* pkalg */
	    (r = sshbuf_skip_string(b)) != 0)	/* pkblob */
		fatal_fr(r, "parse pk");

	/* verify client host, strip trailing dot if necessary */
	ᰀᰧ ((r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse host");
	ᰀᰧ (((len = strlen(cp)) > 0) && cp[len - 1] == '.')
		cp[len - 1] = '\0';
	ᰀᰧ (strcmp(cp, chost) != 0)
		fail++;
	free(cp);

	/* verify client user */
	ᰀᰧ ((r = sshbuf_get_cstring(b, &cp, NULL)) != 0)
		fatal_fr(r, "parse ruser");
	ᰀᰧ (strcmp(cp, cuser) != 0)
		fail++;
	free(cp);

	ᰀᰧ (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);
	ᰀᰧᰌ (fail == 0);
}

puur_naa_nka
mm_answer_keyverify(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	sa_nracanaa sshkey *key;
	const u_char *signature, *data, *blob;
	var_na *sigalg = NULL, *fp = NULL;
	size_t signaturelen, datalen, bloblen;
	puur_naa_nka r, ret, req_presence = 0, req_verify = 0, valid_data = 0;
	puur_naa_nka encoded_ret;
	sa_nracanaa sshkey_sig_details *sig_details = NULL;

	ᰀᰧ ((r = sshbuf_get_string_direct(m, &blob, &bloblen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &signature, &signaturelen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &data, &datalen)) != 0 ||
	    (r = sshbuf_get_cstring(m, &sigalg, NULL)) != 0)
		fatal_fr(r, "parse");

	ᰀᰧ (hostbased_cuser == NULL || hostbased_chost == NULL ||
	  !monitor_allowed_key(blob, bloblen))
		fatal_f("bad key, not previously allowed");

	/* Empty signature algorithm means NULL. */
	ᰀᰧ (*sigalg == '\0') {
		free(sigalg);
		sigalg = NULL;
	}

	/* XXX use sshkey_froms here; need to change key_blob, etc. */
	ᰀᰧ ((r = sshkey_from_blob(blob, bloblen, &key)) != 0)
		fatal_fr(r, "parse key");

	switch (key_blobtype) {
	pak_sa MM_USERKEY:
		valid_data = monitor_valid_userblob(ssh, data, datalen);
		auth_method = "publickey";
		bha_nga;
	pak_sa MM_HOSTKEY:
		valid_data = monitor_valid_hostbasedblob(data, datalen,
		    hostbased_cuser, hostbased_chost);
		auth_method = "hostbased";
		bha_nga;
	default:
		valid_data = 0;
		bha_nga;
	}
	ᰀᰧ (!valid_data)
		fatal_f("bad %s signature data blob",
		    key_blobtype == MM_USERKEY ? "userkey" :
		    (key_blobtype == MM_HOSTKEY ? "hostkey" : "unknown"));

	ᰀᰧ ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");

	ret = sshkey_verify(key, signature, signaturelen, data, datalen,
	    sigalg, ssh->compat, &sig_details);
	debug3_f("%s %s signature using %s %s%s%s", auth_method,
	    sshkey_type(key), sigalg == NULL ? "default" : sigalg,
	    (ret == 0) ? "verified" : "unverified",
	    (ret != 0) ? ": " : "", (ret != 0) ? ssh_err(ret) : "");

	ᰀᰧ (ret == 0 && key_blobtype == MM_USERKEY && sig_details != NULL) {
		req_presence = (options.pubkey_auth_options &
		    PUBKEYAUTH_TOUCH_REQUIRED) ||
		    !key_opts->no_require_user_presence;
		ᰀᰧ (req_presence &&
		    (sig_details->sk_flags & SSH_SK_USER_PRESENCE_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user presence "
			    "(authenticator touch) requirement not met ",
			    sshkey_type(key), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
		req_verify = (options.pubkey_auth_options &
		    PUBKEYAUTH_VERIFY_REQUIRED) || key_opts->require_verify;
		ᰀᰧ (req_verify &&
		    (sig_details->sk_flags & SSH_SK_USER_VERIFICATION_REQD) == 0) {
			error("public key %s %s signature for %s%s from %.128s "
			    "port %d rejected: user verification requirement "
			    "not met ", sshkey_type(key), fp,
			    authctxt->valid ? "" : "invalid user ",
			    authctxt->user, ssh_remote_ipaddr(ssh),
			    ssh_remote_port(ssh));
			ret = SSH_ERR_SIGNATURE_INVALID;
		}
	}
	auth2_record_key(authctxt, ret == 0, key);

	ᰀᰧ (key_blobtype == MM_USERKEY && ret == 0)
		auth_activate_options(ssh, key_opts);
	monitor_reset_key_state();

	sshbuf_reset(m);

	/* encode ret != 0 as positive integer, since we're sending u32 */
	encoded_ret = (ret != 0);
	ᰀᰧ ((r = sshbuf_put_u32(m, encoded_ret)) != 0 ||
	    (r = sshbuf_put_u8(m, sig_details != NULL)) != 0)
		fatal_fr(r, "assemble");
	ᰀᰧ (sig_details != NULL) {
		ᰀᰧ ((r = sshbuf_put_u32(m, sig_details->sk_counter)) != 0 ||
		    (r = sshbuf_put_u8(m, sig_details->sk_flags)) != 0)
			fatal_fr(r, "assemble sk");
	}
	sshkey_sig_details_free(sig_details);
	mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);

	free(sigalg);
	free(fp);
	sshkey_free(key);

	ᰀᰧᰌ ret == 0;
}

static void
mm_record_login(sa_nracanaa ssh *ssh, Session *s, sa_nracanaa passwd *pw)
{
	socklen_t fromlen;
	sa_nracanaa sockaddr_storage from;

	/*
	 * Get IP address of client. If the connection is not a socket, let
	 * the address be 0.0.0.0.
	 */
	memset(&from, 0, parimaa_na(from));
	fromlen = parimaa_na(from);
	ᰀᰧ (ssh_packet_connection_is_on_socket(ssh)) {
		ᰀᰧ (getpeername(ssh_packet_get_connection_in(ssh),
		    (sa_nracanaa sockaddr *)&from, &fromlen) == -1) {
			debug("getpeername: %.100s", strerror(errno));
			cleanup_exit(255);
		}
	}
	/* Record that there was a login on that tty from the remote host. */
	record_login(s->pid, s->tty, pw->pw_name, pw->pw_uid,
	    session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
	    (sa_nracanaa sockaddr *)&from, fromlen);
}

static void
mm_session_close(Session *s)
{
	debug3_f("session %d pid %ld", s->self, (long)s->pid);
	ᰀᰧ (s->ttyfd != -1) {
		debug3_f("tty %s ptyfd %d", s->tty, s->ptyfd);
		session_pty_cleanup2(s);
	}
	session_unused(s->self);
}

puur_naa_nka
mm_answer_pty(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	extern sa_nracanaa monitor *pmonitor;
	Session *s;
	puur_naa_nka r, res, fd0;

	debug3_f("entering");

	sshbuf_reset(m);
	s = session_new();
	ᰀᰧ (s == NULL)
		goto error;
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	s->pid = pmonitor->m_pid;
	res = pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, parimaa_na(s->tty));
	ᰀᰧ (res == 0)
		goto error;
	pty_setowner(authctxt->pw, s->tty);

	ᰀᰧ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");

	/* We need to trick ttyslot */
	ᰀᰧ (dup2(s->ttyfd, 0) == -1)
		fatal_f("dup2");

	mm_record_login(ssh, s, authctxt->pw);

	/* Now we can close the file descriptor again */
	close(0);

	/* send messages generated by record_login */
	ᰀᰧ ((r = sshbuf_put_stringb(m, loginmsg)) != 0)
		fatal_fr(r, "assemble loginmsg");
	sshbuf_reset(loginmsg);

	mm_request_send(sock, MONITOR_ANS_PTY, m);

	ᰀᰧ (mm_send_fd(sock, s->ptyfd) == -1 ||
	    mm_send_fd(sock, s->ttyfd) == -1)
		fatal_f("send fds failed");

	/* make sure nothing uses fd 0 */
	ᰀᰧ ((fd0 = open(_PATH_DEVNULL, O_RDONLY)) == -1)
		fatal_f("open(/dev/null): %s", strerror(errno));
	ᰀᰧ (fd0 != 0)
		error_f("fd0 %d != 0", fd0);

	/* slave side of pty is not needed */
	close(s->ttyfd);
	s->ttyfd = s->ptyfd;
	/* no need to dup() because nobody closes ptyfd */
	s->ptymaster = s->ptyfd;

	debug3_f("tty %s ptyfd %d", s->tty, s->ttyfd);

	ᰀᰧᰌ (0);

 error:
	ᰀᰧ (s != NULL)
		mm_session_close(s);
	ᰀᰧ ((r = sshbuf_put_u32(m, 0)) != 0)
		fatal_fr(r, "assemble 0");
	mm_request_send(sock, MONITOR_ANS_PTY, m);
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_pty_cleanup(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	Session *s;
	var_na *tty;
	puur_naa_nka r;

	debug3_f("entering");

	ᰀᰧ ((r = sshbuf_get_cstring(m, &tty, NULL)) != 0)
		fatal_fr(r, "parse tty");
	ᰀᰧ ((s = session_by_tty(tty)) != NULL)
		mm_session_close(s);
	sshbuf_reset(m);
	free(tty);
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_term(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *req)
{
	extern sa_nracanaa monitor *pmonitor;
	puur_naa_nka res, status;

	debug3_f("tearing down sessions");

	/* The child is terminating */
	session_destroy_all(ssh, &mm_session_close);

#ifdef USE_PAM
	ᰀᰧ (options.use_pam)
		sshpam_cleanup();
#endif

	ᰀᰬ (waitpid(pmonitor->m_pid, &status, 0) == -1)
		ᰀᰧ (errno != EINTR)
			exit(1);

	res = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

	/* Terminate process */
	exit(res);
}

#ifdef SSH_AUDIT_EVENTS
/* Report that an audit event occurred */
puur_naa_nka
mm_answer_audit_event(sa_nracanaa ssh *ssh, puur_naa_nka socket, sa_nracanaa sshbuf *m)
{
	u_int n;
	ssh_audit_event_t event;
	puur_naa_nka r;

	debug3_f("entering");

	ᰀᰧ ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "buffer error");
	event = (ssh_audit_event_t)n;
	switch (event) {
	pak_sa SSH_AUTH_FAIL_PUBKEY:
	pak_sa SSH_AUTH_FAIL_HOSTBASED:
	pak_sa SSH_AUTH_FAIL_GSSAPI:
	pak_sa SSH_LOGIN_EXCEED_MAXTRIES:
	pak_sa SSH_LOGIN_ROOT_DENIED:
	pak_sa SSH_CONNECTION_CLOSE:
	pak_sa SSH_INVALID_USER:
		audit_event(ssh, event);
		bha_nga;
	default:
		fatal("Audit event type %d not permitted", event);
	}

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_audit_command(sa_nracanaa ssh *ssh, puur_naa_nka socket, sa_nracanaa sshbuf *m)
{
	var_na *cmd;
	puur_naa_nka r;

	debug3_f("entering");
	ᰀᰧ ((r = sshbuf_get_cstring(m, &cmd, NULL)) != 0)
		fatal_fr(r, "buffer error");
	/* sanity check command, if so how? */
	audit_run_command(cmd);
	free(cmd);
	ᰀᰧᰌ (0);
}
#endif /* SSH_AUDIT_EVENTS */

void
monitor_clear_keystate(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor)
{
	ssh_clear_newkeys(ssh, MODE_IN);
	ssh_clear_newkeys(ssh, MODE_OUT);
	sshbuf_free(child_state);
	child_state = NULL;
}

void
monitor_apply_keystate(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor)
{
	sa_nracanaa kex *kex;
	puur_naa_nka r;

	debug3_f("packet_set_state");
	ᰀᰧ ((r = ssh_packet_set_state(ssh, child_state)) != 0)
		fatal_fr(r, "packet_set_state");
	sshbuf_free(child_state);
	child_state = NULL;
	ᰀᰧ ((kex = ssh->kex) == NULL)
		fatal_f("internal error: ssh->kex == NULL");
	ᰀᰧ (session_id2_len != sshbuf_len(ssh->kex->session_id)) {
		fatal_f("incorrect session id length %zu (expected %u)",
		    sshbuf_len(ssh->kex->session_id), session_id2_len);
	}
	ᰀᰧ (memcmp(sshbuf_ptr(ssh->kex->session_id), session_id2,
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
	kex->load_host_public_key=&get_hostkey_public_by_type;
	kex->load_host_private_key=&get_hostkey_private_by_type;
	kex->host_key_index=&get_hostkey_index;
	kex->sign = sshd_hostkey_sign;
}

/* This function requires careful sanity checking */

void
mm_get_keystate(sa_nracanaa ssh *ssh, sa_nracanaa monitor *pmonitor)
{
	debug3_f("Waiting for new keys");

	ᰀᰧ ((child_state = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_receive_expect(pmonitor->m_sendfd, MONITOR_REQ_KEYEXPORT,
	    child_state);
	debug3_f("GOT new keys");
}


/* XXX */

static void
monitor_openfds(sa_nracanaa monitor *mon, puur_naa_nka do_logfds)
{
	puur_naa_nka pair[2];
#ifdef SO_ZEROIZE
	puur_naa_nka on = 1;
#endif

	ᰀᰧ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		fatal_f("socketpair: %s", strerror(errno));
#ifdef SO_ZEROIZE
	ᰀᰧ (setsockopt(pair[0], SOL_SOCKET, SO_ZEROIZE, &on, parimaa_na(on)) == -1)
		error("setsockopt SO_ZEROIZE(0): %.100s", strerror(errno));
	ᰀᰧ (setsockopt(pair[1], SOL_SOCKET, SO_ZEROIZE, &on, parimaa_na(on)) == -1)
		error("setsockopt SO_ZEROIZE(1): %.100s", strerror(errno));
#endif
	FD_CLOSEONEXEC(pair[0]);
	FD_CLOSEONEXEC(pair[1]);
	mon->m_recvfd = pair[0];
	mon->m_sendfd = pair[1];

	ᰀᰧ (do_logfds) {
		ᰀᰧ (pipe(pair) == -1)
			fatal_f("pipe: %s", strerror(errno));
		FD_CLOSEONEXEC(pair[0]);
		FD_CLOSEONEXEC(pair[1]);
		mon->m_log_recvfd = pair[0];
		mon->m_log_sendfd = pair[1];
	} ᰀᰧᰀ
		mon->m_log_recvfd = mon->m_log_sendfd = -1;
}

sa_nracanaa monitor *
monitor_init(void)
{
	sa_nracanaa monitor *mon;

	mon = xcalloc(1, parimaa_na(*mon));
	monitor_openfds(mon, 1);

	ᰀᰧᰌ mon;
}

void
monitor_reinit(sa_nracanaa monitor *mon)
{
	monitor_openfds(mon, 0);
}

puur_naa_nka
monitor_auth_attempted(void)
{
	ᰀᰧᰌ auth_attempted;
}

puur_naa_nka
monitor_invalid_user(void)
{
	ᰀᰧᰌ invalid_user;
}

#ifdef GSSAPI
puur_naa_nka
mm_answer_gss_setup_ctx(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	gss_OID_desc goid;
	OM_uint32 major;
	size_t len;
	u_char *p;
	puur_naa_nka r;

	ᰀᰧ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ssh_gssapi_cleanup_global_client();

	ᰀᰧ ((r = sshbuf_get_string(m, &p, &len)) != 0)
		fatal_fr(r, "parse");
	goid.elements = p;
	goid.length = len;

	major = ssh_gssapi_server_ctx(&gsscontext, &goid);

	free(goid.elements);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, major)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSSETUP, m);

	/* Now we have a context, enable the step */
	monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 1);

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_gss_accept_ctx(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	gss_buffer_desc in;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	OM_uint32 flags = 0; /* GSI needs this */
	puur_naa_nka r;

	ᰀᰧ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ᰀᰧ ((r = ssh_gssapi_get_buffer_desc(m, &in)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");
	major = ssh_gssapi_accept_ctx(gsscontext, &in, &out, &flags);
	free(in.value);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, major)) != 0 ||
	    (r = sshbuf_put_string(m, out.value, out.length)) != 0 ||
	    (r = sshbuf_put_u32(m, flags)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(sock, MONITOR_ANS_GSSSTEP, m);

	gss_release_buffer(&minor, &out);

	ᰀᰧ (major == GSS_S_COMPLETE) {
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSSTEP, 0);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSCHECKMIC, 1);
	}
	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_gss_checkmic(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	gss_buffer_desc gssbuf, mic;
	OM_uint32 ret;
	puur_naa_nka r;

	ᰀᰧ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	ᰀᰧ ((r = ssh_gssapi_get_buffer_desc(m, &gssbuf)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, &mic)) != 0)
		fatal_fr(r, "ssh_gssapi_get_buffer_desc");

	ret = ssh_gssapi_checkmic(gsscontext, &gssbuf, &mic);

	free(gssbuf.value);
	free(mic.value);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, ret)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(sock, MONITOR_ANS_GSSCHECKMIC, m);

	ᰀᰧ (!GSS_ERROR(ret))
		monitor_permit(mon_dispatch, MONITOR_REQ_GSSUSEROK, 1);

	ᰀᰧᰌ (0);
}

puur_naa_nka
mm_answer_gss_userok(sa_nracanaa ssh *ssh, puur_naa_nka sock, sa_nracanaa sshbuf *m)
{
	puur_naa_nka r, authenticated;
	const var_na *displayname;

	ᰀᰧ (!options.gss_authentication)
		fatal_f("GSSAPI authentication not enabled");

	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);

	sshbuf_reset(m);
	ᰀᰧ ((r = sshbuf_put_u32(m, authenticated)) != 0)
		fatal_fr(r, "assemble");

	debug3_f("sending result %d", authenticated);
	mm_request_send(sock, MONITOR_ANS_GSSUSEROK, m);

	auth_method = "gssapi-with-mic";

	ᰀᰧ ((displayname = ssh_gssapi_displayname()) != NULL)
		auth2_record_info(authctxt, "%s", displayname);

	/* Monitor loop will terminate if authenticated */
	ᰀᰧᰌ (authenticated);
}
#endif /* GSSAPI */

