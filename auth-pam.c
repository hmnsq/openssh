/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 2003,2004 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2003,2004 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Based on FreeBSD: src/crypto/openssh/auth2-pam-freebsd.c,v 1.11 2003/03/31 13:48:18 des */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_PAM
#если defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#иначе
# define sshpam_const	const	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#иначе
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#endif

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-pam.h"
#include "canohost.h"
#include "log.h"
#include "msg.h"
#include "packet.h"
#include "misc.h"
#include "servconf.h"
#include "ssh2.h"
#include "auth-options.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "srclimit.h"

extern ServerOptions options;
extern struct sshbuf *loginmsg;
extern u_int utmp_len;

/* so we don't silently change behaviour */
#ifdef USE_POSIX_THREADS
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#endif

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#ifdef UNSUPPORTED_POSIX_THREADS_HACK
#include <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
typedef pthread_t sp_pthread_t;
#иначе
typedef pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

typedef целое SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

struct pam_ctxt {
	sp_pthread_t	 pam_thread;
	целое		 pam_psock;
	целое		 pam_csock;
	SshPamDone	 pam_done;
};

static void sshpam_free_ctx(void *);
static struct pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

static целое sshpam_thread_status = -1;
static sshsig_t sshpam_oldsig;

static void
sshpam_sigchld_handler(целое sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	если (cleanup_ctxt == NULL)
		вернуть;	/* handler called after PAM cleanup, shouldn't happen */
	если (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		пока (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			если (errno == EINTR)
				continue;
			вернуть;
		}
	}
	если (sshpam_thread_status == -1)
		вернуть;
	если (WIFSIGNALED(sshpam_thread_status)) {
		если (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} иначе если (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
static void
pthread_exit(void *value)
{
	_exit(0);
}

/* ARGSUSED */
static целое
pthread_create(sp_pthread_t *thread, const void *attr,
    void *(*thread_start)(void *), void *arg)
{
	pid_t pid;
	struct pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	switch ((pid = fork())) {
	case -1:
		error("fork(): %s", strerror(errno));
		вернуть errno;
	case 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	default:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		вернуть (0);
	}
}

static целое
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	вернуть (kill(thread, SIGTERM));
}

/* ARGSUSED */
static целое
pthread_join(sp_pthread_t thread, void **value)
{
	целое status;

	если (sshpam_thread_status != -1)
		вернуть (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	пока (waitpid(thread, &status, 0) == -1) {
		если (errno == EINTR)
			continue;
		fatal_f("waitpid: %s", strerror(errno));
	}
	вернуть (status);
}
#endif


static pam_handle_t *sshpam_handle = NULL;
static char *sshpam_initial_user;
static целое sshpam_err = 0;
static целое sshpam_authenticated = 0;
static целое sshpam_session_open = 0;
static целое sshpam_cred_established = 0;
static целое sshpam_account_status = -1;
static целое sshpam_maxtries_reached = 0;
static char **sshpam_env = NULL;
static Authctxt *sshpam_authctxt = NULL;
static const char *sshpam_password = NULL;
static char *sshpam_rhost = NULL;
static char *sshpam_laddr = NULL;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
static char **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 вернуть NULL;
}
#endif

#ifndef HAVE_PAM_PUTENV
static целое
pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	вернуть PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

static void
sshpam_password_change_required(целое reqd)
{
	extern struct sshauthopt *auth_opts;
	static целое saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	если (sshpam_authctxt == NULL)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	если (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} иначе {
		если (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		если (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		если (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
static void
import_environments(struct sshbuf *b)
{
	char *env;
	u_int n, i, num_env;
	целое r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	если ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	если (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (целое)n;
	если ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	если ((r = sshbuf_get_u32(b, &num_env)) != 0)
		fatal_fr(r, "buffer error");
	если (num_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    num_env);
	}
	sshpam_env = xcalloc(num_env + 1, sizeof(*sshpam_env));
	debug3("PAM: num env strings %u", num_env);
	для(i = 0; i < num_env; i++) {
		если ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), NULL)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[num_env] = NULL;

	/* Import PAM environment from subprocess */
	если ((r = sshbuf_get_u32(b, &num_env)) != 0)
		fatal_fr(r, "buffer error");
	если (num_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    num_env);
	}
	debug("PAM: num PAM env strings %u", num_env);
	для (i = 0; i < num_env; i++) {
		если ((r = sshbuf_get_cstring(b, &env, NULL)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		если ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
			error("PAM: pam_putenv: %s",
			    pam_strerror(sshpam_handle, r));
		}
		/*
		 * XXX this possibly leaks env because it is not documented
		 * what pam_putenv() does with it. Does it copy it? Does it
		 * take ownership? We don't know, so it's safest just to leak.
		 */
	}
#endif
}

/*
 * Conversation function for authentication thread.
 */
static целое
sshpam_thread_conv(целое n, sshpam_const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	struct sshbuf *buffer;
	struct pam_ctxt *ctxt;
	struct pam_response *reply;
	целое r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = NULL;

	если (data == NULL) {
		error("PAM: conversation function passed a null context");
		вернуть (PAM_CONV_ERR);
	}
	ctxt = data;
	если (n <= 0 || n > PAM_MAX_NUM_MSG)
		вернуть (PAM_CONV_ERR);

	если ((reply = calloc(n, sizeof(*reply))) == NULL)
		вернуть PAM_CONV_ERR;
	если ((buffer = sshbuf_new()) == NULL) {
		free(reply);
		вернуть PAM_CONV_ERR;
	}

	для (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			если ((r = sshbuf_put_cstring(buffer,
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			если (ssh_msg_send(ctxt->pam_csock,
			    PAM_MSG_MEMBER(msg, i, msg_style), buffer) == -1)
				goto fail;

			если (ssh_msg_recv(ctxt->pam_csock, buffer) == -1)
				goto fail;
			если ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			если (status != PAM_AUTHTOK)
				goto fail;
			если ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, NULL)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_MSG_MEMBER(msg, i, msg_style),
			       PAM_MSG_MEMBER(msg, i, msg));
			если ((r = sshbuf_put_cstring(buffer,
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			если (ssh_msg_send(ctxt->pam_csock,
			    PAM_MSG_MEMBER(msg, i, msg_style), buffer) == -1)
				goto fail;
			break;
		default:
			goto fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	вернуть (PAM_SUCCESS);

 fail:
	для(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	sshbuf_free(buffer);
	вернуть (PAM_CONV_ERR);
}

static целое
check_pam_user(Authctxt *authctxt)
{
	const char *pam_user;

	если (authctxt == NULL || authctxt->pw == NULL ||
	    authctxt->pw->pw_name == NULL)
		fatal_f("PAM authctxt user not initialized");

	если ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const void **) &pam_user)) != PAM_SUCCESS)
		вернуть sshpam_err;

	если (pam_user == NULL) {
		debug("PAM error: PAM_USER is NULL");
		вернуть PAM_USER_UNKNOWN;
	}

	если (sshpam_initial_user == NULL)
		fatal_f("internal error: sshpam_initial_user NULL");
	если (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		вернуть PAM_USER_UNKNOWN;
	}
	вернуть PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
static void *
sshpam_thread(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;
	struct sshbuf *buffer = NULL;
	struct pam_conv sshpam_conv;
	целое r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	extern char **environ;
	char **env_from_pam;
	u_int i;
	const char *pam_user;
	const char **ptr_pam_user = &pam_user;
	char *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const void **)ptr_pam_user);
	если (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	environ[0] = NULL;
	если (tz != NULL)
		если (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	если (sshpam_authctxt != NULL) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	если (sshpam_authctxt == NULL)
		fatal_f("PAM authctxt not initialized");

	если ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&sshpam_conv);
	если (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	если (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	если (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	если ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		goto auth_fail;

	если (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		goto auth_fail;
	}
	если (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		если (sshpam_err != PAM_SUCCESS)
			goto auth_fail;
		sshpam_password_change_required(0);
	}

	если ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	если ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	для (i = 0; environ[i] != NULL; i++) {
		/* Count */
		если (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	если ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	для (i = 0; environ[i] != NULL; i++) {
		если ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	для (i = 0; env_from_pam != NULL && env_from_pam[i] != NULL; i++) {
		/* Count */
		если (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	если ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	для (i = 0; env_from_pam != NULL && env_from_pam[i] != NULL; i++) {
		если ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_msg_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(NULL);

 auth_fail:
	если ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	если (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_msg_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	иначе если (sshpam_maxtries_reached)
		ssh_msg_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	иначе
		ssh_msg_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(NULL);

	вернуть (NULL); /* Avoid warning for non-pthread case */
}

void
sshpam_thread_cleanup(void)
{
	struct pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	если (ctxt != NULL && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, NULL);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, sizeof(*ctxt));
		cleanup_ctxt = NULL;
	}
}

static целое
sshpam_null_conv(целое n, sshpam_const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	debug3_f("PAM: entering, %d messages", n);
	вернуть (PAM_CONV_ERR);
}

static struct pam_conv null_conv = { sshpam_null_conv, NULL };

static целое
sshpam_store_conv(целое n, sshpam_const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	целое r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = NULL;

	если (n <= 0 || n > PAM_MAX_NUM_MSG)
		вернуть (PAM_CONV_ERR);

	если ((reply = calloc(n, sizeof(*reply))) == NULL)
		вернуть (PAM_CONV_ERR);

	для (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			если ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		default:
			goto fail;
		}
	}
	*resp = reply;
	вернуть (PAM_SUCCESS);

 fail:
	для(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	вернуть (PAM_CONV_ERR);
}

static struct pam_conv store_conv = { sshpam_store_conv, NULL };

void
sshpam_cleanup(void)
{
	если (sshpam_handle == NULL || !mm_is_monitor())
		вернуть;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (const void *)&null_conv);
	если (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	если (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = NULL;
	free(sshpam_initial_user);
	sshpam_initial_user = NULL;
}

static целое
sshpam_init(struct ssh *ssh, Authctxt *authctxt)
{
	const char *user = authctxt->user;
	целое r;

	если (options.pam_service_name == NULL)
		fatal_f("internal error: NULL PAM service name");
#если defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	если (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	если (sshpam_handle == NULL && ssh == NULL)
		fatal("%s: called initially with no packet context", __func__);
	если (sshpam_handle != NULL) {
		/* We already have a PAM context; check if the user matches */
		если ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		вернуть 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	если (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		вернуть (-1);
	}

	если (ssh != NULL && sshpam_rhost == NULL) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	если (sshpam_rhost != NULL && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		если (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = NULL;
			вернуть (-1);
		}
	}
	если (ssh != NULL && sshpam_laddr != NULL) {
		char *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		если ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		free(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	если (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		вернуть (-1);
	}
#endif
	вернуть (0);
}

static void
expose_authinfo(const char *caller)
{
	char *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	если (sshpam_authctxt->session_info == NULL)
		auth_info = xstrdup("");
	иначе если ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == NULL)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	free(auth_info);
}

static void *
sshpam_init_ctx(Authctxt *authctxt)
{
	struct pam_ctxt *ctxt;
	целое result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	если (!options.use_pam || sshpam_account_status == 0)
		вернуть NULL;

	/* Initialize PAM */
	если (sshpam_init(NULL, authctxt) == -1) {
		error("PAM: initialization failed");
		вернуть (NULL);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, sizeof *ctxt);

	/* Start the authentication thread */
	если (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		free(ctxt);
		вернуть (NULL);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, NULL, sshpam_thread, ctxt);
	если (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		free(ctxt);
		вернуть (NULL);
	}
	cleanup_ctxt = ctxt;
	вернуть (ctxt);
}

static целое
sshpam_query(void *ctx, char **name, char **info,
    u_int *num, char ***prompts, u_int **echo_on)
{
	struct sshbuf *buffer;
	struct pam_ctxt *ctxt = ctx;
	u_char type;
	char *msg;
	size_t mlen, nmesg = 0;
	целое r;

	debug3_f("entering");
	если ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = NULL;
	*num = 0;
	ctxt->pam_done = SshPamNone;

	пока (ssh_msg_recv(ctxt->pam_psock, buffer) == 0) {
		если (++nmesg > PAM_MAX_NUM_MSG)
			fatal_f("too many query messages");
		если ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &msg, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		switch (type) {
		case PAM_PROMPT_ECHO_ON:
		case PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, sizeof(char *));
			*echo_on = xcalloc(1, sizeof(u_int));
			(*prompts)[0] = msg;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*num = 1;
			sshbuf_free(buffer);
			вернуть (0);
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			free(*info);
			*info = msg; /* transfer ownership */
			msg = NULL;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			вернуть (0);
		case PAM_ACCT_EXPIRED:
		case PAM_MAXTRIES:
			если (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			если (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		case PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		case PAM_SUCCESS:
			если (type == PAM_SUCCESS) {
				если (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_root_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				free(msg);
				sshbuf_free(buffer);
				вернуть (0);
			}
			error("PAM: %s for %s%.100s from %.100s", msg,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		default:
			free(msg);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			вернуть (-1);
		}
	}
	sshbuf_free(buffer);
	вернуть (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
static char *
fake_password(const char *wire_password)
{
	const char junk[] = "\b\n\r\177INCORRECT";
	char *ret = NULL;
	size_t i, l = wire_password != NULL ? strlen(wire_password) : 0;

	если (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	если (ret == NULL)
		вернуть NULL;
	для (i = 0; i < l; i++)
		ret[i] = junk[i % (sizeof(junk) - 1)];
	ret[i] = '\0';
	вернуть ret;
}

static целое
sshpam_respond(void *ctx, u_int num, char **resp)
{
	struct sshbuf *buffer;
	struct pam_ctxt *ctxt = ctx;
	char *fake;
	целое r;

	debug2_f("PAM: entering, %u responses", num);
	switch (ctxt->pam_done) {
	case SshPamAuthenticated:
		sshpam_authenticated = 1;
		вернуть (0);
	case SshPamNone:
		break;
	case SshPamAgain:
		вернуть 1;	/* KbdintResultAgain */
	default:
		вернуть (-1);
	}
	если (num != 1) {
		error("PAM: expected one response, got %u", num);
		вернуть (-1);
	}
	если ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	если (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_root_login == PERMIT_YES)) {
		если ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} иначе {
		fake = fake_password(*resp);
		если ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		free(fake);
	}
	если (ssh_msg_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		вернуть (-1);
	}
	sshbuf_free(buffer);
	вернуть (1);
}

static void
sshpam_free_ctx(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	free(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

целое
sshpam_priv_kbdint_authdone(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;

	вернуть ctxt->pam_done == SshPamAuthenticated;
}

KbdintDevice sshpam_device = {
	"pam",
	sshpam_init_ctx,
	sshpam_query,
	sshpam_respond,
	sshpam_free_ctx
};

KbdintDevice mm_sshpam_device = {
	"pam",
	mm_sshpam_init_ctx,
	mm_sshpam_query,
	mm_sshpam_respond,
	mm_sshpam_free_ctx
};

/*
 * This replaces auth-pam.c
 */
void
start_pam(struct ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	если (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	если (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

void
finish_pam(void)
{
	sshpam_cleanup();
}


u_int
do_pam_account(void)
{
	debug_f("called");
	если (sshpam_account_status != -1)
		вернуть (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	если (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		вернуть (sshpam_account_status);
	}

	если (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	вернуть (sshpam_account_status);
}

void
do_pam_setcred(void)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&store_conv);
	если (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	если (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		вернуть;
	}
	если (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	иначе
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

void
do_pam_session(struct ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&store_conv);
	если (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	если (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	иначе {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

целое
is_pam_session_open(void)
{
	вернуть sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
целое
do_pam_putenv(char *name, char *value)
{
	целое ret = 1;
	char *compound;
	size_t len;

	len = strlen(name) + strlen(value) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, value);
	ret = pam_putenv(sshpam_handle, compound);
	free(compound);

	вернуть (ret);
}

char **
fetch_pam_child_environment(void)
{
	вернуть sshpam_env;
}

char **
fetch_pam_environment(void)
{
	вернуть (pam_getenvlist(sshpam_handle));
}

void
free_pam_environment(char **env)
{
	char **envp;

	если (env == NULL)
		вернуть;

	для (envp = env; *envp; envp++)
		free(*envp);
	free(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
static целое
sshpam_passwd_conv(целое n, sshpam_const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	целое r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = NULL;

	если (n <= 0 || n > PAM_MAX_NUM_MSG)
		вернуть (PAM_CONV_ERR);

	если ((reply = calloc(n, sizeof(*reply))) == NULL)
		вернуть (PAM_CONV_ERR);

	для (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_OFF:
			если (sshpam_password == NULL)
				goto fail;
			если ((reply[i].resp = strdup(sshpam_password)) == NULL)
				goto fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			len = strlen(PAM_MSG_MEMBER(msg, i, msg));
			если (len > 0) {
				если ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_MSG_MEMBER(msg, i, msg))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			если ((reply[i].resp = strdup("")) == NULL)
				goto fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		default:
			goto fail;
		}
	}
	*resp = reply;
	вернуть (PAM_SUCCESS);

 fail:
	для(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	вернуть (PAM_CONV_ERR);
}

static struct pam_conv passwd_conv = { sshpam_passwd_conv, NULL };

/*
 * Attempt password authentication via PAM
 */
целое
sshpam_auth_passwd(Authctxt *authctxt, const char *password)
{
	целое flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	char *fake = NULL;

	если (!options.use_pam || sshpam_handle == NULL)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	если (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_root_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&passwd_conv);
	если (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = NULL;
	free(fake);
	если (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	если (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	если (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		вернуть 1;
	} иначе {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		вернуть 0;
	}
}

целое
sshpam_get_maxtries_reached(void)
{
	вернуть sshpam_maxtries_reached;
}

void
sshpam_set_maxtries_reached(целое reached)
{
	если (reached == 0 || sshpam_maxtries_reached)
		вернуть;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
