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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/wait.h>

#شامل <errno.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#ifdef USE_PAM
#اگر defined(HAVE_SECURITY_PAM_APPL_H)
#شامل <security/pam_appl.h>
#وگرنهاگر defined (HAVE_PAM_PAM_APPL_H)
#شامل <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#وگرنه
# define sshpam_const	ثابت	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_پیام_MEMBER(پیام, n, member) ((*(پیام))[(n)].member)
#وگرنه
# define PAM_پیام_MEMBER(پیام, n, member) ((پیام)[(n)]->member)
#endif

#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-pam.h"
#شامل "canohost.h"
#شامل "log.h"
#شامل "msg.h"
#شامل "packet.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "ssh2.h"
#شامل "auth-options.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "srclimit.h"

بیرونی ServerOptions options;
بیرونی ساختار sshbuf *loginmsg;
بیرونی u_int utmp_len;

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
#شامل <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
تعریفنوع pthread_t sp_pthread_t;
#وگرنه
تعریفنوع pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

تعریفنوع صحیح SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

ساختار pam_ctxt {
	sp_pthread_t	 pam_thread;
	صحیح		 pam_psock;
	صحیح		 pam_csock;
	SshPamDone	 pam_done;
};

ایستا تهی sshpam_free_ctx(تهی *);
ایستا ساختار pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

ایستا صحیح sshpam_thread_status = -1;
ایستا sshsig_t sshpam_oldsig;

ایستا تهی
sshpam_sigchld_handler(صحیح sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	اگر (cleanup_ctxt == پوچ)
		بازگشت;	/* handler called after PAM cleanup, shouldn't happen */
	اگر (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		وقتی (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			اگر (errno == EINTR)
				ادامه;
			بازگشت;
		}
	}
	اگر (sshpam_thread_status == -1)
		بازگشت;
	اگر (WIFSIGNALED(sshpam_thread_status)) {
		اگر (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} وگرنه اگر (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
ایستا تهی
pthread_exit(تهی *مقدار)
{
	_exit(0);
}

/* ARGSUSED */
ایستا صحیح
pthread_create(sp_pthread_t *thread, ثابت تهی *attr,
    تهی *(*thread_start)(تهی *), تهی *arg)
{
	pid_t pid;
	ساختار pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	انتخاب ((pid = fork())) {
	حالت -1:
		error("fork(): %s", strerror(errno));
		بازگشت errno;
	حالت 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	پیشفرض:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		بازگشت (0);
	}
}

ایستا صحیح
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	بازگشت (kill(thread, SIGTERM));
}

/* ARGSUSED */
ایستا صحیح
pthread_join(sp_pthread_t thread, تهی **مقدار)
{
	صحیح status;

	اگر (sshpam_thread_status != -1)
		بازگشت (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	وقتی (waitpid(thread, &status, 0) == -1) {
		اگر (errno == EINTR)
			ادامه;
		fatal_f("waitpid: %s", strerror(errno));
	}
	بازگشت (status);
}
#endif


ایستا pam_handle_t *sshpam_handle = پوچ;
ایستا نویسه *sshpam_initial_user;
ایستا صحیح sshpam_err = 0;
ایستا صحیح sshpam_authenticated = 0;
ایستا صحیح sshpam_session_open = 0;
ایستا صحیح sshpam_cred_established = 0;
ایستا صحیح sshpam_account_status = -1;
ایستا صحیح sshpam_maxtries_reached = 0;
ایستا نویسه **sshpam_env = پوچ;
ایستا Authctxt *sshpam_authctxt = پوچ;
ایستا ثابت نویسه *sshpam_password = پوچ;
ایستا نویسه *sshpam_rhost = پوچ;
ایستا نویسه *sshpam_laddr = پوچ;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
ایستا نویسه **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 بازگشت پوچ;
}
#endif

#ifndef HAVE_PAM_PUTENV
ایستا صحیح
pam_putenv(pam_handle_t *pamh, ثابت نویسه *name_مقدار)
{
	بازگشت PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

ایستا تهی
sshpam_password_change_required(صحیح reqd)
{
	بیرونی ساختار sshauthopt *auth_opts;
	ایستا صحیح saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	اگر (sshpam_authctxt == پوچ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	اگر (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} وگرنه {
		اگر (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		اگر (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		اگر (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ایستا تهی
import_environments(ساختار sshbuf *b)
{
	نویسه *env;
	u_int n, i, رقم_env;
	صحیح r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	اگر ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	اگر (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (صحیح)n;
	اگر ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	اگر ((r = sshbuf_get_u32(b, &رقم_env)) != 0)
		fatal_fr(r, "buffer error");
	اگر (رقم_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    رقم_env);
	}
	sshpam_env = xcalloc(رقم_env + 1, اندازه(*sshpam_env));
	debug3("PAM: num env strings %u", رقم_env);
	برای(i = 0; i < رقم_env; i++) {
		اگر ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), پوچ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[رقم_env] = پوچ;

	/* Import PAM environment from subprocess */
	اگر ((r = sshbuf_get_u32(b, &رقم_env)) != 0)
		fatal_fr(r, "buffer error");
	اگر (رقم_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    رقم_env);
	}
	debug("PAM: num PAM env strings %u", رقم_env);
	برای (i = 0; i < رقم_env; i++) {
		اگر ((r = sshbuf_get_cstring(b, &env, پوچ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		اگر ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
ایستا صحیح
sshpam_thread_conv(صحیح n, sshpam_const ساختار pam_message **پیام,
    ساختار pam_response **resp, تهی *data)
{
	ساختار sshbuf *buffer;
	ساختار pam_ctxt *ctxt;
	ساختار pam_response *reply;
	صحیح r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = پوچ;

	اگر (data == پوچ) {
		error("PAM: conversation function passed a null context");
		بازگشت (PAM_CONV_ERR);
	}
	ctxt = data;
	اگر (n <= 0 || n > PAM_MAX_رقم_پیام)
		بازگشت (PAM_CONV_ERR);

	اگر ((reply = calloc(n, اندازه(*reply))) == پوچ)
		بازگشت PAM_CONV_ERR;
	اگر ((buffer = sshbuf_new()) == پوچ) {
		آزاد(reply);
		بازگشت PAM_CONV_ERR;
	}

	برای (i = 0; i < n; ++i) {
		انتخاب (PAM_پیام_MEMBER(پیام, i, پیام_style)) {
		حالت PAM_PROMPT_ECHO_OFF:
		حالت PAM_PROMPT_ECHO_ON:
			اگر ((r = sshbuf_put_cstring(buffer,
			    PAM_پیام_MEMBER(پیام, i, پیام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (ssh_پیام_send(ctxt->pam_csock,
			    PAM_پیام_MEMBER(پیام, i, پیام_style), buffer) == -1)
				برو fail;

			اگر (ssh_پیام_recv(ctxt->pam_csock, buffer) == -1)
				برو fail;
			اگر ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (status != PAM_AUTHTOK)
				برو fail;
			اگر ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, پوچ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			بشکن;
		حالت PAM_ERROR_پیام:
		حالت PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_پیام_MEMBER(پیام, i, پیام_style),
			       PAM_پیام_MEMBER(پیام, i, پیام));
			اگر ((r = sshbuf_put_cstring(buffer,
			    PAM_پیام_MEMBER(پیام, i, پیام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (ssh_پیام_send(ctxt->pam_csock,
			    PAM_پیام_MEMBER(پیام, i, پیام_style), buffer) == -1)
				برو fail;
			بشکن;
		پیشفرض:
			برو fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	بازگشت (PAM_SUCCESS);

 fail:
	برای(i = 0; i < n; i++) {
		آزاد(reply[i].resp);
	}
	آزاد(reply);
	sshbuf_free(buffer);
	بازگشت (PAM_CONV_ERR);
}

ایستا صحیح
check_pam_user(Authctxt *authctxt)
{
	ثابت نویسه *pam_user;

	اگر (authctxt == پوچ || authctxt->pw == پوچ ||
	    authctxt->pw->pw_name == پوچ)
		fatal_f("PAM authctxt user not initialized");

	اگر ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const تهی **) &pam_user)) != PAM_SUCCESS)
		بازگشت sshpam_err;

	اگر (pam_user == پوچ) {
		debug("PAM error: PAM_USER is NULL");
		بازگشت PAM_USER_UNKNOWN;
	}

	اگر (sshpam_initial_user == پوچ)
		fatal_f("internal error: sshpam_initial_user NULL");
	اگر (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		بازگشت PAM_USER_UNKNOWN;
	}
	بازگشت PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ایستا تهی *
sshpam_thread(تهی *ctxtp)
{
	ساختار pam_ctxt *ctxt = ctxtp;
	ساختار sshbuf *buffer = پوچ;
	ساختار pam_conv sshpam_conv;
	صحیح r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	بیرونی نویسه **environ;
	نویسه **env_from_pam;
	u_int i;
	ثابت نویسه *pam_user;
	ثابت نویسه **ptr_pam_user = &pam_user;
	نویسه *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const تهی **)ptr_pam_user);
	اگر (sshpam_err != PAM_SUCCESS)
		برو auth_fail;

	environ[0] = پوچ;
	اگر (tz != پوچ)
		اگر (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	اگر (sshpam_authctxt != پوچ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	اگر (sshpam_authctxt == پوچ)
		fatal_f("PAM authctxt not initialized");

	اگر ((buffer = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت تهی *)&sshpam_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		برو auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	اگر (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	اگر (sshpam_err != PAM_SUCCESS)
		برو auth_fail;
	اگر ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		برو auth_fail;

	اگر (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		برو auth_fail;
	}
	اگر (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		اگر (sshpam_err != PAM_SUCCESS)
			برو auth_fail;
		sshpam_password_change_required(0);
	}

	اگر ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	اگر ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	برای (i = 0; environ[i] != پوچ; i++) {
		/*شمار*/
		اگر (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	اگر ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	برای (i = 0; environ[i] != پوچ; i++) {
		اگر ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	برای (i = 0; env_from_pam != پوچ && env_from_pam[i] != پوچ; i++) {
		/*شمار*/
		اگر (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	اگر ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	برای (i = 0; env_from_pam != پوچ && env_from_pam[i] != پوچ; i++) {
		اگر ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_پیام_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(پوچ);

 auth_fail:
	اگر ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	اگر (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_پیام_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	وگرنه اگر (sshpam_maxtries_reached)
		ssh_پیام_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	وگرنه
		ssh_پیام_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(پوچ);

	بازگشت (پوچ); /* Avoid warning for non-pthread case */
}

تهی
sshpam_thread_cleanup(تهی)
{
	ساختار pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	اگر (ctxt != پوچ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, پوچ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, اندازه(*ctxt));
		cleanup_ctxt = پوچ;
	}
}

ایستا صحیح
sshpam_null_conv(صحیح n, sshpam_const ساختار pam_message **پیام,
    ساختار pam_response **resp, تهی *data)
{
	debug3_f("PAM: entering, %d messages", n);
	بازگشت (PAM_CONV_ERR);
}

ایستا ساختار pam_conv null_conv = { sshpam_null_conv, پوچ };

ایستا صحیح
sshpam_store_conv(صحیح n, sshpam_const ساختار pam_message **پیام,
    ساختار pam_response **resp, تهی *data)
{
	ساختار pam_response *reply;
	صحیح r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = پوچ;

	اگر (n <= 0 || n > PAM_MAX_رقم_پیام)
		بازگشت (PAM_CONV_ERR);

	اگر ((reply = calloc(n, اندازه(*reply))) == پوچ)
		بازگشت (PAM_CONV_ERR);

	برای (i = 0; i < n; ++i) {
		انتخاب (PAM_پیام_MEMBER(پیام, i, پیام_style)) {
		حالت PAM_ERROR_پیام:
		حالت PAM_TEXT_INFO:
			اگر ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_پیام_MEMBER(پیام, i, پیام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			بشکن;
		پیشفرض:
			برو fail;
		}
	}
	*resp = reply;
	بازگشت (PAM_SUCCESS);

 fail:
	برای(i = 0; i < n; i++) {
		آزاد(reply[i].resp);
	}
	آزاد(reply);
	بازگشت (PAM_CONV_ERR);
}

ایستا ساختار pam_conv store_conv = { sshpam_store_conv, پوچ };

تهی
sshpam_cleanup(تهی)
{
	اگر (sshpam_handle == پوچ || !mm_is_monitor())
		بازگشت;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (ثابت تهی *)&null_conv);
	اگر (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	اگر (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = پوچ;
	آزاد(sshpam_initial_user);
	sshpam_initial_user = پوچ;
}

ایستا صحیح
sshpam_init(ساختار ssh *ssh, Authctxt *authctxt)
{
	ثابت نویسه *user = authctxt->user;
	صحیح r;

	اگر (options.pam_service_name == پوچ)
		fatal_f("internal error: NULL PAM service name");
#اگر defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	اگر (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	اگر (sshpam_handle == پوچ && ssh == پوچ)
		fatal("%s: called initially with no packet context", __func__);
	اگر (sshpam_handle != پوچ) {
		/* We already have a PAM context; check if the user matches */
		اگر ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		بازگشت 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	اگر (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = پوچ;
		بازگشت (-1);
	}

	اگر (ssh != پوچ && sshpam_rhost == پوچ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	اگر (sshpam_rhost != پوچ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		اگر (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = پوچ;
			بازگشت (-1);
		}
	}
	اگر (ssh != پوچ && sshpam_laddr != پوچ) {
		نویسه *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		اگر ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		آزاد(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	اگر (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = پوچ;
		بازگشت (-1);
	}
#endif
	بازگشت (0);
}

ایستا تهی
expose_authinfo(ثابت نویسه *caller)
{
	نویسه *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	اگر (sshpam_authctxt->session_info == پوچ)
		auth_info = xstrdup("");
	وگرنه اگر ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == پوچ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	آزاد(auth_info);
}

ایستا تهی *
sshpam_init_ctx(Authctxt *authctxt)
{
	ساختار pam_ctxt *ctxt;
	صحیح result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	اگر (!options.use_pam || sshpam_account_status == 0)
		بازگشت پوچ;

	/* Initialize PAM */
	اگر (sshpam_init(پوچ, authctxt) == -1) {
		error("PAM: initialization failed");
		بازگشت (پوچ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, اندازه *ctxt);

	/* Start the authentication thread */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		آزاد(ctxt);
		بازگشت (پوچ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, پوچ, sshpam_thread, ctxt);
	اگر (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		آزاد(ctxt);
		بازگشت (پوچ);
	}
	cleanup_ctxt = ctxt;
	بازگشت (ctxt);
}

ایستا صحیح
sshpam_query(تهی *ctx, نویسه **name, نویسه **info,
    u_int *رقم, نویسه ***prompts, u_int **echo_on)
{
	ساختار sshbuf *buffer;
	ساختار pam_ctxt *ctxt = ctx;
	u_char type;
	نویسه *پیام;
	size_t mlen, nmesg = 0;
	صحیح r;

	debug3_f("entering");
	اگر ((buffer = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = پوچ;
	*رقم = 0;
	ctxt->pam_done = SshPamNone;

	وقتی (ssh_پیام_recv(ctxt->pam_psock, buffer) == 0) {
		اگر (++nmesg > PAM_MAX_رقم_پیام)
			fatal_f("too many query messages");
		اگر ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &پیام, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		انتخاب (type) {
		حالت PAM_PROMPT_ECHO_ON:
		حالت PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, اندازه(نویسه *));
			*echo_on = xcalloc(1, اندازه(u_int));
			(*prompts)[0] = پیام;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*رقم = 1;
			sshbuf_free(buffer);
			بازگشت (0);
		حالت PAM_ERROR_پیام:
		حالت PAM_TEXT_INFO:
			آزاد(*info);
			*info = پیام; /* transfer ownership */
			پیام = پوچ;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			بازگشت (0);
		حالت PAM_ACCT_EXPIRED:
		حالت PAM_MAXTRIES:
			اگر (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			اگر (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		حالت PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		حالت PAM_SUCCESS:
			اگر (type == PAM_SUCCESS) {
				اگر (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_ریشه_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				آزاد(پیام);
				sshbuf_free(buffer);
				بازگشت (0);
			}
			error("PAM: %s for %s%.100s from %.100s", پیام,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		پیشفرض:
			آزاد(پیام);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			بازگشت (-1);
		}
	}
	sshbuf_free(buffer);
	بازگشت (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ایستا نویسه *
fake_password(ثابت نویسه *wire_password)
{
	ثابت نویسه junk[] = "\b\n\r\177INCORRECT";
	نویسه *ret = پوچ;
	size_t i, l = wire_password != پوچ ? strlen(wire_password) : 0;

	اگر (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	اگر (ret == پوچ)
		بازگشت پوچ;
	برای (i = 0; i < l; i++)
		ret[i] = junk[i % (اندازه(junk) - 1)];
	ret[i] = '\0';
	بازگشت ret;
}

ایستا صحیح
sshpam_respond(تهی *ctx, u_int رقم, نویسه **resp)
{
	ساختار sshbuf *buffer;
	ساختار pam_ctxt *ctxt = ctx;
	نویسه *fake;
	صحیح r;

	debug2_f("PAM: entering, %u responses", رقم);
	انتخاب (ctxt->pam_done) {
	حالت SshPamAuthenticated:
		sshpam_authenticated = 1;
		بازگشت (0);
	حالت SshPamNone:
		بشکن;
	حالت SshPamAgain:
		بازگشت 1;	/* KbdintResultAgain */
	پیشفرض:
		بازگشت (-1);
	}
	اگر (رقم != 1) {
		error("PAM: expected one response, got %u", رقم);
		بازگشت (-1);
	}
	اگر ((buffer = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_ریشه_login == PERMIT_YES)) {
		اگر ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} وگرنه {
		fake = fake_password(*resp);
		اگر ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		آزاد(fake);
	}
	اگر (ssh_پیام_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		بازگشت (-1);
	}
	sshbuf_free(buffer);
	بازگشت (1);
}

ایستا تهی
sshpam_free_ctx(تهی *ctxtp)
{
	ساختار pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	آزاد(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

صحیح
sshpam_priv_kbdint_authdone(تهی *ctxtp)
{
	ساختار pam_ctxt *ctxt = ctxtp;

	بازگشت ctxt->pam_done == SshPamAuthenticated;
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
تهی
start_pam(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	اگر (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	اگر (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

تهی
finish_pam(تهی)
{
	sshpam_cleanup();
}


u_int
do_pam_account(تهی)
{
	debug_f("called");
	اگر (sshpam_account_status != -1)
		بازگشت (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	اگر (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		بازگشت (sshpam_account_status);
	}

	اگر (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	بازگشت (sshpam_account_status);
}

تهی
do_pam_setcred(تهی)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت تهی *)&store_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	اگر (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		بازگشت;
	}
	اگر (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	وگرنه
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

تهی
do_pam_session(ساختار ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت تهی *)&store_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	اگر (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	وگرنه {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

صحیح
is_pam_session_open(تهی)
{
	بازگشت sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
صحیح
do_pam_putenv(نویسه *name, نویسه *مقدار)
{
	صحیح ret = 1;
	نویسه *compound;
	size_t len;

	len = strlen(name) + strlen(مقدار) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, مقدار);
	ret = pam_putenv(sshpam_handle, compound);
	آزاد(compound);

	بازگشت (ret);
}

نویسه **
fetch_pam_child_environment(تهی)
{
	بازگشت sshpam_env;
}

نویسه **
fetch_pam_environment(تهی)
{
	بازگشت (pam_getenvlist(sshpam_handle));
}

تهی
free_pam_environment(نویسه **env)
{
	نویسه **envp;

	اگر (env == پوچ)
		بازگشت;

	برای (envp = env; *envp; envp++)
		آزاد(*envp);
	آزاد(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ایستا صحیح
sshpam_passwd_conv(صحیح n, sshpam_const ساختار pam_message **پیام,
    ساختار pam_response **resp, تهی *data)
{
	ساختار pam_response *reply;
	صحیح r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = پوچ;

	اگر (n <= 0 || n > PAM_MAX_رقم_پیام)
		بازگشت (PAM_CONV_ERR);

	اگر ((reply = calloc(n, اندازه(*reply))) == پوچ)
		بازگشت (PAM_CONV_ERR);

	برای (i = 0; i < n; ++i) {
		انتخاب (PAM_پیام_MEMBER(پیام, i, پیام_style)) {
		حالت PAM_PROMPT_ECHO_OFF:
			اگر (sshpam_password == پوچ)
				برو fail;
			اگر ((reply[i].resp = strdup(sshpam_password)) == پوچ)
				برو fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			بشکن;
		حالت PAM_ERROR_پیام:
		حالت PAM_TEXT_INFO:
			len = strlen(PAM_پیام_MEMBER(پیام, i, پیام));
			اگر (len > 0) {
				اگر ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_پیام_MEMBER(پیام, i, پیام))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			اگر ((reply[i].resp = strdup("")) == پوچ)
				برو fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			بشکن;
		پیشفرض:
			برو fail;
		}
	}
	*resp = reply;
	بازگشت (PAM_SUCCESS);

 fail:
	برای(i = 0; i < n; i++) {
		آزاد(reply[i].resp);
	}
	آزاد(reply);
	بازگشت (PAM_CONV_ERR);
}

ایستا ساختار pam_conv passwd_conv = { sshpam_passwd_conv, پوچ };

/*
 * Attempt password authentication via PAM
 */
صحیح
sshpam_auth_passwd(Authctxt *authctxt, ثابت نویسه *password)
{
	صحیح flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	نویسه *fake = پوچ;

	اگر (!options.use_pam || sshpam_handle == پوچ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	اگر (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_ریشه_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت تهی *)&passwd_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = پوچ;
	آزاد(fake);
	اگر (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	اگر (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	اگر (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		بازگشت 1;
	} وگرنه {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		بازگشت 0;
	}
}

صحیح
sshpam_get_maxtries_reached(تهی)
{
	بازگشت sshpam_maxtries_reached;
}

تهی
sshpam_set_maxtries_reached(صحیح reached)
{
	اگر (reached == 0 || sshpam_maxtries_reached)
		بازگشت;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
