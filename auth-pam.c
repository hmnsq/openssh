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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/wait.h>

#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ifdef USE_PAM
#إذا defined(HAVE_SECURITY_PAM_APPL_H)
#ضمن <security/pam_appl.h>
#وإلاإذا defined (HAVE_PAM_PAM_APPL_H)
#ضمن <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#وإلا
# define sshpam_const	ثابت	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_رسالة_MEMBER(رسالة, n, member) ((*(رسالة))[(n)].member)
#وإلا
# define PAM_رسالة_MEMBER(رسالة, n, member) ((رسالة)[(n)]->member)
#endif

#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-pam.h"
#ضمن "canohost.h"
#ضمن "log.h"
#ضمن "msg.h"
#ضمن "packet.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "ssh2.h"
#ضمن "auth-options.h"
#ifdef GSSAPI
#ضمن "ssh-gss.h"
#endif
#ضمن "monitor_wrap.h"
#ضمن "srclimit.h"

خارجي ServerOptions options;
خارجي بنية sshbuf *loginmsg;
خارجي u_int utmp_len;

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
#ضمن <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
تعريفنوع pthread_t sp_pthread_t;
#وإلا
تعريفنوع pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

تعريفنوع صحيح SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

بنية pam_ctxt {
	sp_pthread_t	 pam_thread;
	صحيح		 pam_psock;
	صحيح		 pam_csock;
	SshPamDone	 pam_done;
};

ساكن فراغ sshpam_free_ctx(فراغ *);
ساكن بنية pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

ساكن صحيح sshpam_thread_status = -1;
ساكن sshsig_t sshpam_oldsig;

ساكن فراغ
sshpam_sigchld_handler(صحيح sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	إذا (cleanup_ctxt == عدم)
		أرجع;	/* handler called after PAM cleanup, shouldn't happen */
	إذا (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		طالما (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			إذا (errno == EINTR)
				استمر;
			أرجع;
		}
	}
	إذا (sshpam_thread_status == -1)
		أرجع;
	إذا (WIFSIGNALED(sshpam_thread_status)) {
		إذا (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} وإلا إذا (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
ساكن فراغ
pthread_exit(فراغ *قيمة)
{
	_exit(0);
}

/* ARGSUSED */
ساكن صحيح
pthread_create(sp_pthread_t *thread, ثابت فراغ *attr,
    فراغ *(*thread_start)(فراغ *), فراغ *arg)
{
	pid_t pid;
	بنية pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	بدل ((pid = fork())) {
	حالة -1:
		error("fork(): %s", strerror(errno));
		أرجع errno;
	حالة 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	افتراضي:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		أرجع (0);
	}
}

ساكن صحيح
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	أرجع (kill(thread, SIGTERM));
}

/* ARGSUSED */
ساكن صحيح
pthread_join(sp_pthread_t thread, فراغ **قيمة)
{
	صحيح status;

	إذا (sshpam_thread_status != -1)
		أرجع (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	طالما (waitpid(thread, &status, 0) == -1) {
		إذا (errno == EINTR)
			استمر;
		fatal_f("waitpid: %s", strerror(errno));
	}
	أرجع (status);
}
#endif


ساكن pam_handle_t *sshpam_handle = عدم;
ساكن حرف *sshpam_initial_user;
ساكن صحيح sshpam_err = 0;
ساكن صحيح sshpam_authenticated = 0;
ساكن صحيح sshpam_session_open = 0;
ساكن صحيح sshpam_cred_established = 0;
ساكن صحيح sshpam_account_status = -1;
ساكن صحيح sshpam_maxtries_reached = 0;
ساكن حرف **sshpam_env = عدم;
ساكن Authctxt *sshpam_authctxt = عدم;
ساكن ثابت حرف *sshpam_password = عدم;
ساكن حرف *sshpam_rhost = عدم;
ساكن حرف *sshpam_laddr = عدم;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
ساكن حرف **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 أرجع عدم;
}
#endif

#ifndef HAVE_PAM_PUTENV
ساكن صحيح
pam_putenv(pam_handle_t *pamh, ثابت حرف *name_قيمة)
{
	أرجع PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

ساكن فراغ
sshpam_password_change_required(صحيح reqd)
{
	خارجي بنية sshauthopt *auth_opts;
	ساكن صحيح saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	إذا (sshpam_authctxt == عدم)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	إذا (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} وإلا {
		إذا (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		إذا (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		إذا (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ساكن فراغ
import_environments(بنية sshbuf *b)
{
	حرف *env;
	u_int n, i, رقم_env;
	صحيح r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	إذا ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	إذا (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (صحيح)n;
	إذا ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	إذا ((r = sshbuf_get_u32(b, &رقم_env)) != 0)
		fatal_fr(r, "buffer error");
	إذا (رقم_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    رقم_env);
	}
	sshpam_env = xcalloc(رقم_env + 1, حجم(*sshpam_env));
	debug3("PAM: num env strings %u", رقم_env);
	لكل(i = 0; i < رقم_env; i++) {
		إذا ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), عدم)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[رقم_env] = عدم;

	/* Import PAM environment from subprocess */
	إذا ((r = sshbuf_get_u32(b, &رقم_env)) != 0)
		fatal_fr(r, "buffer error");
	إذا (رقم_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    رقم_env);
	}
	debug("PAM: num PAM env strings %u", رقم_env);
	لكل (i = 0; i < رقم_env; i++) {
		إذا ((r = sshbuf_get_cstring(b, &env, عدم)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		إذا ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
ساكن صحيح
sshpam_thread_conv(صحيح n, sshpam_const بنية pam_message **رسالة,
    بنية pam_response **resp, فراغ *data)
{
	بنية sshbuf *buffer;
	بنية pam_ctxt *ctxt;
	بنية pam_response *reply;
	صحيح r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = عدم;

	إذا (data == عدم) {
		error("PAM: conversation function passed a null context");
		أرجع (PAM_CONV_ERR);
	}
	ctxt = data;
	إذا (n <= 0 || n > PAM_MAX_رقم_رسالة)
		أرجع (PAM_CONV_ERR);

	إذا ((reply = calloc(n, حجم(*reply))) == عدم)
		أرجع PAM_CONV_ERR;
	إذا ((buffer = sshbuf_new()) == عدم) {
		حرر(reply);
		أرجع PAM_CONV_ERR;
	}

	لكل (i = 0; i < n; ++i) {
		بدل (PAM_رسالة_MEMBER(رسالة, i, رسالة_style)) {
		حالة PAM_PROMPT_ECHO_OFF:
		حالة PAM_PROMPT_ECHO_ON:
			إذا ((r = sshbuf_put_cstring(buffer,
			    PAM_رسالة_MEMBER(رسالة, i, رسالة))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			إذا (ssh_رسالة_send(ctxt->pam_csock,
			    PAM_رسالة_MEMBER(رسالة, i, رسالة_style), buffer) == -1)
				اذهب fail;

			إذا (ssh_رسالة_recv(ctxt->pam_csock, buffer) == -1)
				اذهب fail;
			إذا ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			إذا (status != PAM_AUTHTOK)
				اذهب fail;
			إذا ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, عدم)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اكسر;
		حالة PAM_ERROR_رسالة:
		حالة PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_رسالة_MEMBER(رسالة, i, رسالة_style),
			       PAM_رسالة_MEMBER(رسالة, i, رسالة));
			إذا ((r = sshbuf_put_cstring(buffer,
			    PAM_رسالة_MEMBER(رسالة, i, رسالة))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			إذا (ssh_رسالة_send(ctxt->pam_csock,
			    PAM_رسالة_MEMBER(رسالة, i, رسالة_style), buffer) == -1)
				اذهب fail;
			اكسر;
		افتراضي:
			اذهب fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	أرجع (PAM_SUCCESS);

 fail:
	لكل(i = 0; i < n; i++) {
		حرر(reply[i].resp);
	}
	حرر(reply);
	sshbuf_free(buffer);
	أرجع (PAM_CONV_ERR);
}

ساكن صحيح
check_pam_user(Authctxt *authctxt)
{
	ثابت حرف *pam_user;

	إذا (authctxt == عدم || authctxt->pw == عدم ||
	    authctxt->pw->pw_name == عدم)
		fatal_f("PAM authctxt user not initialized");

	إذا ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const فراغ **) &pam_user)) != PAM_SUCCESS)
		أرجع sshpam_err;

	إذا (pam_user == عدم) {
		debug("PAM error: PAM_USER is NULL");
		أرجع PAM_USER_UNKNOWN;
	}

	إذا (sshpam_initial_user == عدم)
		fatal_f("internal error: sshpam_initial_user NULL");
	إذا (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		أرجع PAM_USER_UNKNOWN;
	}
	أرجع PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ساكن فراغ *
sshpam_thread(فراغ *ctxtp)
{
	بنية pam_ctxt *ctxt = ctxtp;
	بنية sshbuf *buffer = عدم;
	بنية pam_conv sshpam_conv;
	صحيح r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	خارجي حرف **environ;
	حرف **env_from_pam;
	u_int i;
	ثابت حرف *pam_user;
	ثابت حرف **ptr_pam_user = &pam_user;
	حرف *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const فراغ **)ptr_pam_user);
	إذا (sshpam_err != PAM_SUCCESS)
		اذهب auth_fail;

	environ[0] = عدم;
	إذا (tz != عدم)
		إذا (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	إذا (sshpam_authctxt != عدم) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	إذا (sshpam_authctxt == عدم)
		fatal_f("PAM authctxt not initialized");

	إذا ((buffer = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت فراغ *)&sshpam_conv);
	إذا (sshpam_err != PAM_SUCCESS)
		اذهب auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	إذا (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	إذا (sshpam_err != PAM_SUCCESS)
		اذهب auth_fail;
	إذا ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		اذهب auth_fail;

	إذا (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		اذهب auth_fail;
	}
	إذا (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		إذا (sshpam_err != PAM_SUCCESS)
			اذهب auth_fail;
		sshpam_password_change_required(0);
	}

	إذا ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	إذا ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	لكل (i = 0; environ[i] != عدم; i++) {
		/*عدد*/
		إذا (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	إذا ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	لكل (i = 0; environ[i] != عدم; i++) {
		إذا ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	لكل (i = 0; env_from_pam != عدم && env_from_pam[i] != عدم; i++) {
		/*عدد*/
		إذا (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	إذا ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	لكل (i = 0; env_from_pam != عدم && env_from_pam[i] != عدم; i++) {
		إذا ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_رسالة_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(عدم);

 auth_fail:
	إذا ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	إذا (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_رسالة_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	وإلا إذا (sshpam_maxtries_reached)
		ssh_رسالة_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	وإلا
		ssh_رسالة_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(عدم);

	أرجع (عدم); /* Avoid warning for non-pthread case */
}

فراغ
sshpam_thread_cleanup(فراغ)
{
	بنية pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	إذا (ctxt != عدم && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, عدم);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, حجم(*ctxt));
		cleanup_ctxt = عدم;
	}
}

ساكن صحيح
sshpam_null_conv(صحيح n, sshpam_const بنية pam_message **رسالة,
    بنية pam_response **resp, فراغ *data)
{
	debug3_f("PAM: entering, %d messages", n);
	أرجع (PAM_CONV_ERR);
}

ساكن بنية pam_conv null_conv = { sshpam_null_conv, عدم };

ساكن صحيح
sshpam_store_conv(صحيح n, sshpam_const بنية pam_message **رسالة,
    بنية pam_response **resp, فراغ *data)
{
	بنية pam_response *reply;
	صحيح r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = عدم;

	إذا (n <= 0 || n > PAM_MAX_رقم_رسالة)
		أرجع (PAM_CONV_ERR);

	إذا ((reply = calloc(n, حجم(*reply))) == عدم)
		أرجع (PAM_CONV_ERR);

	لكل (i = 0; i < n; ++i) {
		بدل (PAM_رسالة_MEMBER(رسالة, i, رسالة_style)) {
		حالة PAM_ERROR_رسالة:
		حالة PAM_TEXT_INFO:
			إذا ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_رسالة_MEMBER(رسالة, i, رسالة))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			اكسر;
		افتراضي:
			اذهب fail;
		}
	}
	*resp = reply;
	أرجع (PAM_SUCCESS);

 fail:
	لكل(i = 0; i < n; i++) {
		حرر(reply[i].resp);
	}
	حرر(reply);
	أرجع (PAM_CONV_ERR);
}

ساكن بنية pam_conv store_conv = { sshpam_store_conv, عدم };

فراغ
sshpam_cleanup(فراغ)
{
	إذا (sshpam_handle == عدم || !mm_is_monitor())
		أرجع;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (ثابت فراغ *)&null_conv);
	إذا (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	إذا (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = عدم;
	حرر(sshpam_initial_user);
	sshpam_initial_user = عدم;
}

ساكن صحيح
sshpam_init(بنية ssh *ssh, Authctxt *authctxt)
{
	ثابت حرف *user = authctxt->user;
	صحيح r;

	إذا (options.pam_service_name == عدم)
		fatal_f("internal error: NULL PAM service name");
#إذا defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	إذا (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	إذا (sshpam_handle == عدم && ssh == عدم)
		fatal("%s: called initially with no packet context", __func__);
	إذا (sshpam_handle != عدم) {
		/* We already have a PAM context; check if the user matches */
		إذا ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		أرجع 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	إذا (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = عدم;
		أرجع (-1);
	}

	إذا (ssh != عدم && sshpam_rhost == عدم) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	إذا (sshpam_rhost != عدم && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		إذا (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = عدم;
			أرجع (-1);
		}
	}
	إذا (ssh != عدم && sshpam_laddr != عدم) {
		حرف *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		إذا ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		حرر(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	إذا (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = عدم;
		أرجع (-1);
	}
#endif
	أرجع (0);
}

ساكن فراغ
expose_authinfo(ثابت حرف *caller)
{
	حرف *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	إذا (sshpam_authctxt->session_info == عدم)
		auth_info = xstrdup("");
	وإلا إذا ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == عدم)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	حرر(auth_info);
}

ساكن فراغ *
sshpam_init_ctx(Authctxt *authctxt)
{
	بنية pam_ctxt *ctxt;
	صحيح result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	إذا (!options.use_pam || sshpam_account_status == 0)
		أرجع عدم;

	/* Initialize PAM */
	إذا (sshpam_init(عدم, authctxt) == -1) {
		error("PAM: initialization failed");
		أرجع (عدم);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, حجم *ctxt);

	/* Start the authentication thread */
	إذا (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		حرر(ctxt);
		أرجع (عدم);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, عدم, sshpam_thread, ctxt);
	إذا (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		حرر(ctxt);
		أرجع (عدم);
	}
	cleanup_ctxt = ctxt;
	أرجع (ctxt);
}

ساكن صحيح
sshpam_query(فراغ *ctx, حرف **name, حرف **info,
    u_int *رقم, حرف ***prompts, u_int **echo_on)
{
	بنية sshbuf *buffer;
	بنية pam_ctxt *ctxt = ctx;
	u_char type;
	حرف *رسالة;
	size_t mlen, nmesg = 0;
	صحيح r;

	debug3_f("entering");
	إذا ((buffer = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = عدم;
	*رقم = 0;
	ctxt->pam_done = SshPamNone;

	طالما (ssh_رسالة_recv(ctxt->pam_psock, buffer) == 0) {
		إذا (++nmesg > PAM_MAX_رقم_رسالة)
			fatal_f("too many query messages");
		إذا ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &رسالة, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		بدل (type) {
		حالة PAM_PROMPT_ECHO_ON:
		حالة PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, حجم(حرف *));
			*echo_on = xcalloc(1, حجم(u_int));
			(*prompts)[0] = رسالة;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*رقم = 1;
			sshbuf_free(buffer);
			أرجع (0);
		حالة PAM_ERROR_رسالة:
		حالة PAM_TEXT_INFO:
			حرر(*info);
			*info = رسالة; /* transfer ownership */
			رسالة = عدم;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			أرجع (0);
		حالة PAM_ACCT_EXPIRED:
		حالة PAM_MAXTRIES:
			إذا (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			إذا (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		حالة PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		حالة PAM_SUCCESS:
			إذا (type == PAM_SUCCESS) {
				إذا (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_جذر_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				حرر(رسالة);
				sshbuf_free(buffer);
				أرجع (0);
			}
			error("PAM: %s for %s%.100s from %.100s", رسالة,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		افتراضي:
			حرر(رسالة);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			أرجع (-1);
		}
	}
	sshbuf_free(buffer);
	أرجع (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ساكن حرف *
fake_password(ثابت حرف *wire_password)
{
	ثابت حرف junk[] = "\b\n\r\177INCORRECT";
	حرف *ret = عدم;
	size_t i, l = wire_password != عدم ? strlen(wire_password) : 0;

	إذا (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	إذا (ret == عدم)
		أرجع عدم;
	لكل (i = 0; i < l; i++)
		ret[i] = junk[i % (حجم(junk) - 1)];
	ret[i] = '\0';
	أرجع ret;
}

ساكن صحيح
sshpam_respond(فراغ *ctx, u_int رقم, حرف **resp)
{
	بنية sshbuf *buffer;
	بنية pam_ctxt *ctxt = ctx;
	حرف *fake;
	صحيح r;

	debug2_f("PAM: entering, %u responses", رقم);
	بدل (ctxt->pam_done) {
	حالة SshPamAuthenticated:
		sshpam_authenticated = 1;
		أرجع (0);
	حالة SshPamNone:
		اكسر;
	حالة SshPamAgain:
		أرجع 1;	/* KbdintResultAgain */
	افتراضي:
		أرجع (-1);
	}
	إذا (رقم != 1) {
		error("PAM: expected one response, got %u", رقم);
		أرجع (-1);
	}
	إذا ((buffer = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_جذر_login == PERMIT_YES)) {
		إذا ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} وإلا {
		fake = fake_password(*resp);
		إذا ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		حرر(fake);
	}
	إذا (ssh_رسالة_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		أرجع (-1);
	}
	sshbuf_free(buffer);
	أرجع (1);
}

ساكن فراغ
sshpam_free_ctx(فراغ *ctxtp)
{
	بنية pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	حرر(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

صحيح
sshpam_priv_kbdint_authdone(فراغ *ctxtp)
{
	بنية pam_ctxt *ctxt = ctxtp;

	أرجع ctxt->pam_done == SshPamAuthenticated;
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
فراغ
start_pam(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	إذا (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	إذا (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

فراغ
finish_pam(فراغ)
{
	sshpam_cleanup();
}


u_int
do_pam_account(فراغ)
{
	debug_f("called");
	إذا (sshpam_account_status != -1)
		أرجع (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	إذا (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		أرجع (sshpam_account_status);
	}

	إذا (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	أرجع (sshpam_account_status);
}

فراغ
do_pam_setcred(فراغ)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت فراغ *)&store_conv);
	إذا (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	إذا (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		أرجع;
	}
	إذا (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	وإلا
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

فراغ
do_pam_session(بنية ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت فراغ *)&store_conv);
	إذا (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	إذا (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	وإلا {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

صحيح
is_pam_session_open(فراغ)
{
	أرجع sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
صحيح
do_pam_putenv(حرف *name, حرف *قيمة)
{
	صحيح ret = 1;
	حرف *compound;
	size_t len;

	len = strlen(name) + strlen(قيمة) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, قيمة);
	ret = pam_putenv(sshpam_handle, compound);
	حرر(compound);

	أرجع (ret);
}

حرف **
fetch_pam_child_environment(فراغ)
{
	أرجع sshpam_env;
}

حرف **
fetch_pam_environment(فراغ)
{
	أرجع (pam_getenvlist(sshpam_handle));
}

فراغ
free_pam_environment(حرف **env)
{
	حرف **envp;

	إذا (env == عدم)
		أرجع;

	لكل (envp = env; *envp; envp++)
		حرر(*envp);
	حرر(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ساكن صحيح
sshpam_passwd_conv(صحيح n, sshpam_const بنية pam_message **رسالة,
    بنية pam_response **resp, فراغ *data)
{
	بنية pam_response *reply;
	صحيح r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = عدم;

	إذا (n <= 0 || n > PAM_MAX_رقم_رسالة)
		أرجع (PAM_CONV_ERR);

	إذا ((reply = calloc(n, حجم(*reply))) == عدم)
		أرجع (PAM_CONV_ERR);

	لكل (i = 0; i < n; ++i) {
		بدل (PAM_رسالة_MEMBER(رسالة, i, رسالة_style)) {
		حالة PAM_PROMPT_ECHO_OFF:
			إذا (sshpam_password == عدم)
				اذهب fail;
			إذا ((reply[i].resp = strdup(sshpam_password)) == عدم)
				اذهب fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			اكسر;
		حالة PAM_ERROR_رسالة:
		حالة PAM_TEXT_INFO:
			len = strlen(PAM_رسالة_MEMBER(رسالة, i, رسالة));
			إذا (len > 0) {
				إذا ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_رسالة_MEMBER(رسالة, i, رسالة))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			إذا ((reply[i].resp = strdup("")) == عدم)
				اذهب fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			اكسر;
		افتراضي:
			اذهب fail;
		}
	}
	*resp = reply;
	أرجع (PAM_SUCCESS);

 fail:
	لكل(i = 0; i < n; i++) {
		حرر(reply[i].resp);
	}
	حرر(reply);
	أرجع (PAM_CONV_ERR);
}

ساكن بنية pam_conv passwd_conv = { sshpam_passwd_conv, عدم };

/*
 * Attempt password authentication via PAM
 */
صحيح
sshpam_auth_passwd(Authctxt *authctxt, ثابت حرف *password)
{
	صحيح flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	حرف *fake = عدم;

	إذا (!options.use_pam || sshpam_handle == عدم)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	إذا (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_جذر_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ثابت فراغ *)&passwd_conv);
	إذا (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = عدم;
	حرر(fake);
	إذا (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	إذا (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	إذا (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		أرجع 1;
	} وإلا {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		أرجع 0;
	}
}

صحيح
sshpam_get_maxtries_reached(فراغ)
{
	أرجع sshpam_maxtries_reached;
}

فراغ
sshpam_set_maxtries_reached(صحيح reached)
{
	إذا (reached == 0 || sshpam_maxtries_reached)
		أرجع;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
