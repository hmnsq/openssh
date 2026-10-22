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
#ᨀᨘ defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ᨀᨘᨁ
# define sshpam_const	const	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#ᨀᨘᨁ
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
extern sa_nracanaa sshbuf *loginmsg;
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
#ᨀᨘᨁ
typedef pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

typedef puur_naa_nka SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

sa_nracanaa pam_ctxt {
	sp_pthread_t	 pam_thread;
	puur_naa_nka		 pam_psock;
	puur_naa_nka		 pam_csock;
	SshPamDone	 pam_done;
};

static void sshpam_free_ctx(void *);
static sa_nracanaa pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

static puur_naa_nka sshpam_thread_status = -1;
static sshsig_t sshpam_oldsig;

static void
sshpam_sigchld_handler(puur_naa_nka sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ᨀᨘ (cleanup_ctxt == NULL)
		ᨀᨘᨒ;	/* handler called after PAM cleanup, shouldn't happen */
	ᨀᨘ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ᨀᨛ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			ᨀᨘ (errno == EINTR)
				continue;
			ᨀᨘᨒ;
		}
	}
	ᨀᨘ (sshpam_thread_status == -1)
		ᨀᨘᨒ;
	ᨀᨘ (WIFSIGNALED(sshpam_thread_status)) {
		ᨀᨘ (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} ᨀᨘᨁ ᨀᨘ (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
static void
pthread_exit(void *value)
{
	_exit(0);
}

/* ARGSUSED */
static puur_naa_nka
pthread_create(sp_pthread_t *thread, const void *attr,
    void *(*thread_start)(void *), void *arg)
{
	pid_t pid;
	sa_nracanaa pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	switch ((pid = fork())) {
	pak_sa -1:
		error("fork(): %s", strerror(errno));
		ᨀᨘᨒ errno;
	pak_sa 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	default:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		ᨀᨘᨒ (0);
	}
}

static puur_naa_nka
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ᨀᨘᨒ (kill(thread, SIGTERM));
}

/* ARGSUSED */
static puur_naa_nka
pthread_join(sp_pthread_t thread, void **value)
{
	puur_naa_nka status;

	ᨀᨘ (sshpam_thread_status != -1)
		ᨀᨘᨒ (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ᨀᨛ (waitpid(thread, &status, 0) == -1) {
		ᨀᨘ (errno == EINTR)
			continue;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ᨀᨘᨒ (status);
}
#endif


static pam_handle_t *sshpam_handle = NULL;
static var_na *sshpam_initial_user;
static puur_naa_nka sshpam_err = 0;
static puur_naa_nka sshpam_authenticated = 0;
static puur_naa_nka sshpam_session_open = 0;
static puur_naa_nka sshpam_cred_established = 0;
static puur_naa_nka sshpam_account_status = -1;
static puur_naa_nka sshpam_maxtries_reached = 0;
static var_na **sshpam_env = NULL;
static Authctxt *sshpam_authctxt = NULL;
static const var_na *sshpam_password = NULL;
static var_na *sshpam_rhost = NULL;
static var_na *sshpam_laddr = NULL;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
static var_na **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 ᨀᨘᨒ NULL;
}
#endif

#ifndef HAVE_PAM_PUTENV
static puur_naa_nka
pam_putenv(pam_handle_t *pamh, const var_na *name_value)
{
	ᨀᨘᨒ PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

static void
sshpam_password_change_required(puur_naa_nka reqd)
{
	extern sa_nracanaa sshauthopt *auth_opts;
	static puur_naa_nka saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ᨀᨘ (sshpam_authctxt == NULL)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ᨀᨘ (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ᨀᨘᨁ {
		ᨀᨘ (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		ᨀᨘ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ᨀᨘ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
static void
import_environments(sa_nracanaa sshbuf *b)
{
	var_na *env;
	u_int n, i, num_env;
	puur_naa_nka r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	ᨀᨘ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ᨀᨘ (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (puur_naa_nka)n;
	ᨀᨘ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ᨀᨘ ((r = sshbuf_get_u32(b, &num_env)) != 0)
		fatal_fr(r, "buffer error");
	ᨀᨘ (num_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    num_env);
	}
	sshpam_env = xcalloc(num_env + 1, parimaa_na(*sshpam_env));
	debug3("PAM: num env strings %u", num_env);
	for(i = 0; i < num_env; i++) {
		ᨀᨘ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), NULL)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[num_env] = NULL;

	/* Import PAM environment from subprocess */
	ᨀᨘ ((r = sshbuf_get_u32(b, &num_env)) != 0)
		fatal_fr(r, "buffer error");
	ᨀᨘ (num_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    num_env);
	}
	debug("PAM: num PAM env strings %u", num_env);
	for (i = 0; i < num_env; i++) {
		ᨀᨘ ((r = sshbuf_get_cstring(b, &env, NULL)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ᨀᨘ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
static puur_naa_nka
sshpam_thread_conv(puur_naa_nka n, sshpam_const sa_nracanaa pam_message **msg,
    sa_nracanaa pam_response **resp, void *data)
{
	sa_nracanaa sshbuf *buffer;
	sa_nracanaa pam_ctxt *ctxt;
	sa_nracanaa pam_response *reply;
	puur_naa_nka r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = NULL;

	ᨀᨘ (data == NULL) {
		error("PAM: conversation function passed a null context");
		ᨀᨘᨒ (PAM_CONV_ERR);
	}
	ctxt = data;
	ᨀᨘ (n <= 0 || n > PAM_MAX_NUM_MSG)
		ᨀᨘᨒ (PAM_CONV_ERR);

	ᨀᨘ ((reply = calloc(n, parimaa_na(*reply))) == NULL)
		ᨀᨘᨒ PAM_CONV_ERR;
	ᨀᨘ ((buffer = sshbuf_new()) == NULL) {
		free(reply);
		ᨀᨘᨒ PAM_CONV_ERR;
	}

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		pak_sa PAM_PROMPT_ECHO_OFF:
		pak_sa PAM_PROMPT_ECHO_ON:
			ᨀᨘ ((r = sshbuf_put_cstring(buffer,
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ᨀᨘ (ssh_msg_send(ctxt->pam_csock,
			    PAM_MSG_MEMBER(msg, i, msg_style), buffer) == -1)
				goto fail;

			ᨀᨘ (ssh_msg_recv(ctxt->pam_csock, buffer) == -1)
				goto fail;
			ᨀᨘ ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ᨀᨘ (status != PAM_AUTHTOK)
				goto fail;
			ᨀᨘ ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, NULL)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			bha_nga;
		pak_sa PAM_ERROR_MSG:
		pak_sa PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_MSG_MEMBER(msg, i, msg_style),
			       PAM_MSG_MEMBER(msg, i, msg));
			ᨀᨘ ((r = sshbuf_put_cstring(buffer,
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ᨀᨘ (ssh_msg_send(ctxt->pam_csock,
			    PAM_MSG_MEMBER(msg, i, msg_style), buffer) == -1)
				goto fail;
			bha_nga;
		default:
			goto fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	ᨀᨘᨒ (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	sshbuf_free(buffer);
	ᨀᨘᨒ (PAM_CONV_ERR);
}

static puur_naa_nka
check_pam_user(Authctxt *authctxt)
{
	const var_na *pam_user;

	ᨀᨘ (authctxt == NULL || authctxt->pw == NULL ||
	    authctxt->pw->pw_name == NULL)
		fatal_f("PAM authctxt user not initialized");

	ᨀᨘ ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const void **) &pam_user)) != PAM_SUCCESS)
		ᨀᨘᨒ sshpam_err;

	ᨀᨘ (pam_user == NULL) {
		debug("PAM error: PAM_USER is NULL");
		ᨀᨘᨒ PAM_USER_UNKNOWN;
	}

	ᨀᨘ (sshpam_initial_user == NULL)
		fatal_f("internal error: sshpam_initial_user NULL");
	ᨀᨘ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		ᨀᨘᨒ PAM_USER_UNKNOWN;
	}
	ᨀᨘᨒ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
static void *
sshpam_thread(void *ctxtp)
{
	sa_nracanaa pam_ctxt *ctxt = ctxtp;
	sa_nracanaa sshbuf *buffer = NULL;
	sa_nracanaa pam_conv sshpam_conv;
	puur_naa_nka r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	extern var_na **environ;
	var_na **env_from_pam;
	u_int i;
	const var_na *pam_user;
	const var_na **ptr_pam_user = &pam_user;
	var_na *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const void **)ptr_pam_user);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	environ[0] = NULL;
	ᨀᨘ (tz != NULL)
		ᨀᨘ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ᨀᨘ (sshpam_authctxt != NULL) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ᨀᨘ (sshpam_authctxt == NULL)
		fatal_f("PAM authctxt not initialized");

	ᨀᨘ ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&sshpam_conv);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ᨀᨘ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	ᨀᨘ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		goto auth_fail;

	ᨀᨘ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		goto auth_fail;
	}
	ᨀᨘ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ᨀᨘ (sshpam_err != PAM_SUCCESS)
			goto auth_fail;
		sshpam_password_change_required(0);
	}

	ᨀᨘ ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	ᨀᨘ ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	for (i = 0; environ[i] != NULL; i++) {
		/* Count */
		ᨀᨘ (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	ᨀᨘ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	for (i = 0; environ[i] != NULL; i++) {
		ᨀᨘ ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	for (i = 0; env_from_pam != NULL && env_from_pam[i] != NULL; i++) {
		/* Count */
		ᨀᨘ (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	ᨀᨘ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	for (i = 0; env_from_pam != NULL && env_from_pam[i] != NULL; i++) {
		ᨀᨘ ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_msg_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(NULL);

 auth_fail:
	ᨀᨘ ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ᨀᨘ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_msg_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	ᨀᨘᨁ ᨀᨘ (sshpam_maxtries_reached)
		ssh_msg_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	ᨀᨘᨁ
		ssh_msg_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(NULL);

	ᨀᨘᨒ (NULL); /* Avoid warning for non-pthread case */
}

void
sshpam_thread_cleanup(void)
{
	sa_nracanaa pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ᨀᨘ (ctxt != NULL && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, NULL);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, parimaa_na(*ctxt));
		cleanup_ctxt = NULL;
	}
}

static puur_naa_nka
sshpam_null_conv(puur_naa_nka n, sshpam_const sa_nracanaa pam_message **msg,
    sa_nracanaa pam_response **resp, void *data)
{
	debug3_f("PAM: entering, %d messages", n);
	ᨀᨘᨒ (PAM_CONV_ERR);
}

static sa_nracanaa pam_conv null_conv = { sshpam_null_conv, NULL };

static puur_naa_nka
sshpam_store_conv(puur_naa_nka n, sshpam_const sa_nracanaa pam_message **msg,
    sa_nracanaa pam_response **resp, void *data)
{
	sa_nracanaa pam_response *reply;
	puur_naa_nka r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = NULL;

	ᨀᨘ (n <= 0 || n > PAM_MAX_NUM_MSG)
		ᨀᨘᨒ (PAM_CONV_ERR);

	ᨀᨘ ((reply = calloc(n, parimaa_na(*reply))) == NULL)
		ᨀᨘᨒ (PAM_CONV_ERR);

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		pak_sa PAM_ERROR_MSG:
		pak_sa PAM_TEXT_INFO:
			ᨀᨘ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_MSG_MEMBER(msg, i, msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			bha_nga;
		default:
			goto fail;
		}
	}
	*resp = reply;
	ᨀᨘᨒ (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	ᨀᨘᨒ (PAM_CONV_ERR);
}

static sa_nracanaa pam_conv store_conv = { sshpam_store_conv, NULL };

void
sshpam_cleanup(void)
{
	ᨀᨘ (sshpam_handle == NULL || !mm_is_monitor())
		ᨀᨘᨒ;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (const void *)&null_conv);
	ᨀᨘ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ᨀᨘ (sshpam_cred_established) {
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

static puur_naa_nka
sshpam_init(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	const var_na *user = authctxt->user;
	puur_naa_nka r;

	ᨀᨘ (options.pam_service_name == NULL)
		fatal_f("internal error: NULL PAM service name");
#ᨀᨘ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	ᨀᨘ (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	ᨀᨘ (sshpam_handle == NULL && ssh == NULL)
		fatal("%s: called initially with no packet context", __func__);
	ᨀᨘ (sshpam_handle != NULL) {
		/* We already have a PAM context; check if the user matches */
		ᨀᨘ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		ᨀᨘᨒ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ᨀᨘ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		ᨀᨘᨒ (-1);
	}

	ᨀᨘ (ssh != NULL && sshpam_rhost == NULL) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	ᨀᨘ (sshpam_rhost != NULL && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ᨀᨘ (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = NULL;
			ᨀᨘᨒ (-1);
		}
	}
	ᨀᨘ (ssh != NULL && sshpam_laddr != NULL) {
		var_na *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		ᨀᨘ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
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
	ᨀᨘ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		ᨀᨘᨒ (-1);
	}
#endif
	ᨀᨘᨒ (0);
}

static void
expose_authinfo(const var_na *caller)
{
	var_na *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ᨀᨘ (sshpam_authctxt->session_info == NULL)
		auth_info = xstrdup("");
	ᨀᨘᨁ ᨀᨘ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == NULL)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	free(auth_info);
}

static void *
sshpam_init_ctx(Authctxt *authctxt)
{
	sa_nracanaa pam_ctxt *ctxt;
	puur_naa_nka result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ᨀᨘ (!options.use_pam || sshpam_account_status == 0)
		ᨀᨘᨒ NULL;

	/* Initialize PAM */
	ᨀᨘ (sshpam_init(NULL, authctxt) == -1) {
		error("PAM: initialization failed");
		ᨀᨘᨒ (NULL);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, parimaa_na *ctxt);

	/* Start the authentication thread */
	ᨀᨘ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		free(ctxt);
		ᨀᨘᨒ (NULL);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, NULL, sshpam_thread, ctxt);
	ᨀᨘ (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		free(ctxt);
		ᨀᨘᨒ (NULL);
	}
	cleanup_ctxt = ctxt;
	ᨀᨘᨒ (ctxt);
}

static puur_naa_nka
sshpam_query(void *ctx, var_na **name, var_na **info,
    u_int *num, var_na ***prompts, u_int **echo_on)
{
	sa_nracanaa sshbuf *buffer;
	sa_nracanaa pam_ctxt *ctxt = ctx;
	u_char type;
	var_na *msg;
	size_t mlen, nmesg = 0;
	puur_naa_nka r;

	debug3_f("entering");
	ᨀᨘ ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = NULL;
	*num = 0;
	ctxt->pam_done = SshPamNone;

	ᨀᨛ (ssh_msg_recv(ctxt->pam_psock, buffer) == 0) {
		ᨀᨘ (++nmesg > PAM_MAX_NUM_MSG)
			fatal_f("too many query messages");
		ᨀᨘ ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &msg, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		switch (type) {
		pak_sa PAM_PROMPT_ECHO_ON:
		pak_sa PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, parimaa_na(var_na *));
			*echo_on = xcalloc(1, parimaa_na(u_int));
			(*prompts)[0] = msg;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*num = 1;
			sshbuf_free(buffer);
			ᨀᨘᨒ (0);
		pak_sa PAM_ERROR_MSG:
		pak_sa PAM_TEXT_INFO:
			free(*info);
			*info = msg; /* transfer ownership */
			msg = NULL;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			ᨀᨘᨒ (0);
		pak_sa PAM_ACCT_EXPIRED:
		pak_sa PAM_MAXTRIES:
			ᨀᨘ (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			ᨀᨘ (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		pak_sa PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		pak_sa PAM_SUCCESS:
			ᨀᨘ (type == PAM_SUCCESS) {
				ᨀᨘ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_root_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				free(msg);
				sshbuf_free(buffer);
				ᨀᨘᨒ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", msg,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		default:
			free(msg);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			ᨀᨘᨒ (-1);
		}
	}
	sshbuf_free(buffer);
	ᨀᨘᨒ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
static var_na *
fake_password(const var_na *wire_password)
{
	const var_na junk[] = "\b\n\r\177INCORRECT";
	var_na *ret = NULL;
	size_t i, l = wire_password != NULL ? strlen(wire_password) : 0;

	ᨀᨘ (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	ᨀᨘ (ret == NULL)
		ᨀᨘᨒ NULL;
	for (i = 0; i < l; i++)
		ret[i] = junk[i % (parimaa_na(junk) - 1)];
	ret[i] = '\0';
	ᨀᨘᨒ ret;
}

static puur_naa_nka
sshpam_respond(void *ctx, u_int num, var_na **resp)
{
	sa_nracanaa sshbuf *buffer;
	sa_nracanaa pam_ctxt *ctxt = ctx;
	var_na *fake;
	puur_naa_nka r;

	debug2_f("PAM: entering, %u responses", num);
	switch (ctxt->pam_done) {
	pak_sa SshPamAuthenticated:
		sshpam_authenticated = 1;
		ᨀᨘᨒ (0);
	pak_sa SshPamNone:
		bha_nga;
	pak_sa SshPamAgain:
		ᨀᨘᨒ 1;	/* KbdintResultAgain */
	default:
		ᨀᨘᨒ (-1);
	}
	ᨀᨘ (num != 1) {
		error("PAM: expected one response, got %u", num);
		ᨀᨘᨒ (-1);
	}
	ᨀᨘ ((buffer = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᨀᨘ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_root_login == PERMIT_YES)) {
		ᨀᨘ ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ᨀᨘᨁ {
		fake = fake_password(*resp);
		ᨀᨘ ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		free(fake);
	}
	ᨀᨘ (ssh_msg_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		ᨀᨘᨒ (-1);
	}
	sshbuf_free(buffer);
	ᨀᨘᨒ (1);
}

static void
sshpam_free_ctx(void *ctxtp)
{
	sa_nracanaa pam_ctxt *ctxt = ctxtp;

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

puur_naa_nka
sshpam_priv_kbdint_authdone(void *ctxtp)
{
	sa_nracanaa pam_ctxt *ctxt = ctxtp;

	ᨀᨘᨒ ctxt->pam_done == SshPamAuthenticated;
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
start_pam(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ᨀᨘ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ᨀᨘ (sshpam_init(ssh, authctxt) == -1)
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
	ᨀᨘ (sshpam_account_status != -1)
		ᨀᨘᨒ (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ᨀᨘ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		ᨀᨘᨒ (sshpam_account_status);
	}

	ᨀᨘ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	ᨀᨘᨒ (sshpam_account_status);
}

void
do_pam_setcred(void)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&store_conv);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ᨀᨘ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		ᨀᨘᨒ;
	}
	ᨀᨘ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ᨀᨘᨁ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

void
do_pam_session(sa_nracanaa ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&store_conv);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ᨀᨘ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ᨀᨘᨁ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

puur_naa_nka
is_pam_session_open(void)
{
	ᨀᨘᨒ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
puur_naa_nka
do_pam_putenv(var_na *name, var_na *value)
{
	puur_naa_nka ret = 1;
	var_na *compound;
	size_t len;

	len = strlen(name) + strlen(value) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, value);
	ret = pam_putenv(sshpam_handle, compound);
	free(compound);

	ᨀᨘᨒ (ret);
}

var_na **
fetch_pam_child_environment(void)
{
	ᨀᨘᨒ sshpam_env;
}

var_na **
fetch_pam_environment(void)
{
	ᨀᨘᨒ (pam_getenvlist(sshpam_handle));
}

void
free_pam_environment(var_na **env)
{
	var_na **envp;

	ᨀᨘ (env == NULL)
		ᨀᨘᨒ;

	for (envp = env; *envp; envp++)
		free(*envp);
	free(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
static puur_naa_nka
sshpam_passwd_conv(puur_naa_nka n, sshpam_const sa_nracanaa pam_message **msg,
    sa_nracanaa pam_response **resp, void *data)
{
	sa_nracanaa pam_response *reply;
	puur_naa_nka r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = NULL;

	ᨀᨘ (n <= 0 || n > PAM_MAX_NUM_MSG)
		ᨀᨘᨒ (PAM_CONV_ERR);

	ᨀᨘ ((reply = calloc(n, parimaa_na(*reply))) == NULL)
		ᨀᨘᨒ (PAM_CONV_ERR);

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		pak_sa PAM_PROMPT_ECHO_OFF:
			ᨀᨘ (sshpam_password == NULL)
				goto fail;
			ᨀᨘ ((reply[i].resp = strdup(sshpam_password)) == NULL)
				goto fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			bha_nga;
		pak_sa PAM_ERROR_MSG:
		pak_sa PAM_TEXT_INFO:
			len = strlen(PAM_MSG_MEMBER(msg, i, msg));
			ᨀᨘ (len > 0) {
				ᨀᨘ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_MSG_MEMBER(msg, i, msg))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ᨀᨘ ((reply[i].resp = strdup("")) == NULL)
				goto fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			bha_nga;
		default:
			goto fail;
		}
	}
	*resp = reply;
	ᨀᨘᨒ (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	ᨀᨘᨒ (PAM_CONV_ERR);
}

static sa_nracanaa pam_conv passwd_conv = { sshpam_passwd_conv, NULL };

/*
 * Attempt password authentication via PAM
 */
puur_naa_nka
sshpam_auth_passwd(Authctxt *authctxt, const var_na *password)
{
	puur_naa_nka flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	var_na *fake = NULL;

	ᨀᨘ (!options.use_pam || sshpam_handle == NULL)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ᨀᨘ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_root_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (const void *)&passwd_conv);
	ᨀᨘ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = NULL;
	free(fake);
	ᨀᨘ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ᨀᨘ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ᨀᨘ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		ᨀᨘᨒ 1;
	} ᨀᨘᨁ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		ᨀᨘᨒ 0;
	}
}

puur_naa_nka
sshpam_get_maxtries_reached(void)
{
	ᨀᨘᨒ sshpam_maxtries_reached;
}

void
sshpam_set_maxtries_reached(puur_naa_nka reached)
{
	ᨀᨘ (reached == 0 || sshpam_maxtries_reached)
		ᨀᨘᨒ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
