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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef USE_PAM
#எனில் defined(HAVE_SECURITY_PAM_APPL_H)
#அந்தர்பாவ <security/pam_appl.h>
#அல்லதெனில் defined (HAVE_PAM_PAM_APPL_H)
#அந்தர்பாவ <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#இல்லையெனில்
# define sshpam_const	மாறிலி	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_செய்தி_MEMBER(செய்தி, n, member) ((*(செய்தி))[(n)].member)
#இல்லையெனில்
# define PAM_செய்தி_MEMBER(செய்தி, n, member) ((செய்தி)[(n)]->member)
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-pam.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "auth-options.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "srclimit.h"

வெளி ServerOptions options;
வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி u_int utmp_len;

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
#அந்தர்பாவ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
வகைவரை pthread_t sp_pthread_t;
#இல்லையெனில்
வகைவரை pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

வகைவரை முழு SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

கட்டமைப்பு pam_ctxt {
	sp_pthread_t	 pam_thread;
	முழு		 pam_psock;
	முழு		 pam_csock;
	SshPamDone	 pam_done;
};

நிலையான வெறுமை sshpam_free_ctx(வெறுமை *);
நிலையான கட்டமைப்பு pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

நிலையான முழு sshpam_thread_status = -1;
நிலையான sshsig_t sshpam_oldsig;

நிலையான வெறுமை
sshpam_sigchld_handler(முழு sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	எனில் (cleanup_ctxt == வெற்று)
		திரும்பு;	/* handler called after PAM cleanup, shouldn't happen */
	எனில் (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		போது (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			எனில் (errno == EINTR)
				தொடர்;
			திரும்பு;
		}
	}
	எனில் (sshpam_thread_status == -1)
		திரும்பு;
	எனில் (WIFSIGNALED(sshpam_thread_status)) {
		எனில் (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} இல்லையெனில் எனில் (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
நிலையான வெறுமை
pthread_exit(வெறுமை *மதிப்பு)
{
	_exit(0);
}

/* ARGSUSED */
நிலையான முழு
pthread_create(sp_pthread_t *thread, மாறிலி வெறுமை *attr,
    வெறுமை *(*thread_start)(வெறுமை *), வெறுமை *arg)
{
	pid_t pid;
	கட்டமைப்பு pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	தேர்வு ((pid = fork())) {
	நிலை -1:
		error("fork(): %s", strerror(errno));
		திரும்பு errno;
	நிலை 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	இயல்பு:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		திரும்பு (0);
	}
}

நிலையான முழு
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	திரும்பு (kill(thread, SIGTERM));
}

/* ARGSUSED */
நிலையான முழு
pthread_join(sp_pthread_t thread, வெறுமை **மதிப்பு)
{
	முழு status;

	எனில் (sshpam_thread_status != -1)
		திரும்பு (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	போது (waitpid(thread, &status, 0) == -1) {
		எனில் (errno == EINTR)
			தொடர்;
		fatal_f("waitpid: %s", strerror(errno));
	}
	திரும்பு (status);
}
#endif


நிலையான pam_handle_t *sshpam_handle = வெற்று;
நிலையான எழுத்து *sshpam_initial_user;
நிலையான முழு sshpam_err = 0;
நிலையான முழு sshpam_authenticated = 0;
நிலையான முழு sshpam_session_open = 0;
நிலையான முழு sshpam_cred_established = 0;
நிலையான முழு sshpam_account_status = -1;
நிலையான முழு sshpam_maxtries_reached = 0;
நிலையான எழுத்து **sshpam_env = வெற்று;
நிலையான Authctxt *sshpam_authctxt = வெற்று;
நிலையான மாறிலி எழுத்து *sshpam_password = வெற்று;
நிலையான எழுத்து *sshpam_rhost = வெற்று;
நிலையான எழுத்து *sshpam_laddr = வெற்று;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
நிலையான எழுத்து **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 திரும்பு வெற்று;
}
#endif

#ifndef HAVE_PAM_PUTENV
நிலையான முழு
pam_putenv(pam_handle_t *pamh, மாறிலி எழுத்து *name_மதிப்பு)
{
	திரும்பு PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

நிலையான வெறுமை
sshpam_password_change_required(முழு reqd)
{
	வெளி கட்டமைப்பு sshauthopt *auth_opts;
	நிலையான முழு saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	எனில் (sshpam_authctxt == வெற்று)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	எனில் (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} இல்லையெனில் {
		எனில் (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		எனில் (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		எனில் (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
நிலையான வெறுமை
import_environments(கட்டமைப்பு sshbuf *b)
{
	எழுத்து *env;
	u_int n, i, இலக்கம்_env;
	முழு r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	எனில் ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (முழு)n;
	எனில் ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	எனில் ((r = sshbuf_get_u32(b, &இலக்கம்_env)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (இலக்கம்_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    இலக்கம்_env);
	}
	sshpam_env = xcalloc(இலக்கம்_env + 1, அளவு(*sshpam_env));
	debug3("PAM: num env strings %u", இலக்கம்_env);
	க்கு(i = 0; i < இலக்கம்_env; i++) {
		எனில் ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), வெற்று)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[இலக்கம்_env] = வெற்று;

	/* Import PAM environment from subprocess */
	எனில் ((r = sshbuf_get_u32(b, &இலக்கம்_env)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (இலக்கம்_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    இலக்கம்_env);
	}
	debug("PAM: num PAM env strings %u", இலக்கம்_env);
	க்கு (i = 0; i < இலக்கம்_env; i++) {
		எனில் ((r = sshbuf_get_cstring(b, &env, வெற்று)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		எனில் ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
நிலையான முழு
sshpam_thread_conv(முழு n, sshpam_const கட்டமைப்பு pam_message **செய்தி,
    கட்டமைப்பு pam_response **resp, வெறுமை *data)
{
	கட்டமைப்பு sshbuf *buffer;
	கட்டமைப்பு pam_ctxt *ctxt;
	கட்டமைப்பு pam_response *reply;
	முழு r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = வெற்று;

	எனில் (data == வெற்று) {
		error("PAM: conversation function passed a null context");
		திரும்பு (PAM_CONV_ERR);
	}
	ctxt = data;
	எனில் (n <= 0 || n > PAM_MAX_இலக்கம்_செய்தி)
		திரும்பு (PAM_CONV_ERR);

	எனில் ((reply = calloc(n, அளவு(*reply))) == வெற்று)
		திரும்பு PAM_CONV_ERR;
	எனில் ((buffer = sshbuf_new()) == வெற்று) {
		விடுவி(reply);
		திரும்பு PAM_CONV_ERR;
	}

	க்கு (i = 0; i < n; ++i) {
		தேர்வு (PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style)) {
		நிலை PAM_PROMPT_ECHO_OFF:
		நிலை PAM_PROMPT_ECHO_ON:
			எனில் ((r = sshbuf_put_cstring(buffer,
			    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			எனில் (ssh_செய்தி_send(ctxt->pam_csock,
			    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style), buffer) == -1)
				செல் fail;

			எனில் (ssh_செய்தி_recv(ctxt->pam_csock, buffer) == -1)
				செல் fail;
			எனில் ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			எனில் (status != PAM_AUTHTOK)
				செல் fail;
			எனில் ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, வெற்று)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			நிறுத்து;
		நிலை PAM_ERROR_செய்தி:
		நிலை PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style),
			       PAM_செய்தி_MEMBER(செய்தி, i, செய்தி));
			எனில் ((r = sshbuf_put_cstring(buffer,
			    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			எனில் (ssh_செய்தி_send(ctxt->pam_csock,
			    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style), buffer) == -1)
				செல் fail;
			நிறுத்து;
		இயல்பு:
			செல் fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	திரும்பு (PAM_SUCCESS);

 fail:
	க்கு(i = 0; i < n; i++) {
		விடுவி(reply[i].resp);
	}
	விடுவி(reply);
	sshbuf_free(buffer);
	திரும்பு (PAM_CONV_ERR);
}

நிலையான முழு
check_pam_user(Authctxt *authctxt)
{
	மாறிலி எழுத்து *pam_user;

	எனில் (authctxt == வெற்று || authctxt->pw == வெற்று ||
	    authctxt->pw->pw_name == வெற்று)
		fatal_f("PAM authctxt user not initialized");

	எனில் ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const வெறுமை **) &pam_user)) != PAM_SUCCESS)
		திரும்பு sshpam_err;

	எனில் (pam_user == வெற்று) {
		debug("PAM error: PAM_USER is NULL");
		திரும்பு PAM_USER_UNKNOWN;
	}

	எனில் (sshpam_initial_user == வெற்று)
		fatal_f("internal error: sshpam_initial_user NULL");
	எனில் (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		திரும்பு PAM_USER_UNKNOWN;
	}
	திரும்பு PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
நிலையான வெறுமை *
sshpam_thread(வெறுமை *ctxtp)
{
	கட்டமைப்பு pam_ctxt *ctxt = ctxtp;
	கட்டமைப்பு sshbuf *buffer = வெற்று;
	கட்டமைப்பு pam_conv sshpam_conv;
	முழு r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	வெளி எழுத்து **environ;
	எழுத்து **env_from_pam;
	u_int i;
	மாறிலி எழுத்து *pam_user;
	மாறிலி எழுத்து **ptr_pam_user = &pam_user;
	எழுத்து *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const வெறுமை **)ptr_pam_user);
	எனில் (sshpam_err != PAM_SUCCESS)
		செல் auth_fail;

	environ[0] = வெற்று;
	எனில் (tz != வெற்று)
		எனில் (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	எனில் (sshpam_authctxt != வெற்று) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	எனில் (sshpam_authctxt == வெற்று)
		fatal_f("PAM authctxt not initialized");

	எனில் ((buffer = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (மாறிலி வெறுமை *)&sshpam_conv);
	எனில் (sshpam_err != PAM_SUCCESS)
		செல் auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	எனில் (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	எனில் (sshpam_err != PAM_SUCCESS)
		செல் auth_fail;
	எனில் ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		செல் auth_fail;

	எனில் (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		செல் auth_fail;
	}
	எனில் (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		எனில் (sshpam_err != PAM_SUCCESS)
			செல் auth_fail;
		sshpam_password_change_required(0);
	}

	எனில் ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	எனில் ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	க்கு (i = 0; environ[i] != வெற்று; i++) {
		/*மொத்தம்*/
		எனில் (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	எனில் ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	க்கு (i = 0; environ[i] != வெற்று; i++) {
		எனில் ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	க்கு (i = 0; env_from_pam != வெற்று && env_from_pam[i] != வெற்று; i++) {
		/*மொத்தம்*/
		எனில் (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	எனில் ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	க்கு (i = 0; env_from_pam != வெற்று && env_from_pam[i] != வெற்று; i++) {
		எனில் ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_செய்தி_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(வெற்று);

 auth_fail:
	எனில் ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	எனில் (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_செய்தி_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	இல்லையெனில் எனில் (sshpam_maxtries_reached)
		ssh_செய்தி_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	இல்லையெனில்
		ssh_செய்தி_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(வெற்று);

	திரும்பு (வெற்று); /* Avoid warning for non-pthread case */
}

வெறுமை
sshpam_thread_cleanup(வெறுமை)
{
	கட்டமைப்பு pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	எனில் (ctxt != வெற்று && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, வெற்று);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, அளவு(*ctxt));
		cleanup_ctxt = வெற்று;
	}
}

நிலையான முழு
sshpam_null_conv(முழு n, sshpam_const கட்டமைப்பு pam_message **செய்தி,
    கட்டமைப்பு pam_response **resp, வெறுமை *data)
{
	debug3_f("PAM: entering, %d messages", n);
	திரும்பு (PAM_CONV_ERR);
}

நிலையான கட்டமைப்பு pam_conv null_conv = { sshpam_null_conv, வெற்று };

நிலையான முழு
sshpam_store_conv(முழு n, sshpam_const கட்டமைப்பு pam_message **செய்தி,
    கட்டமைப்பு pam_response **resp, வெறுமை *data)
{
	கட்டமைப்பு pam_response *reply;
	முழு r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = வெற்று;

	எனில் (n <= 0 || n > PAM_MAX_இலக்கம்_செய்தி)
		திரும்பு (PAM_CONV_ERR);

	எனில் ((reply = calloc(n, அளவு(*reply))) == வெற்று)
		திரும்பு (PAM_CONV_ERR);

	க்கு (i = 0; i < n; ++i) {
		தேர்வு (PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style)) {
		நிலை PAM_ERROR_செய்தி:
		நிலை PAM_TEXT_INFO:
			எனில் ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			நிறுத்து;
		இயல்பு:
			செல் fail;
		}
	}
	*resp = reply;
	திரும்பு (PAM_SUCCESS);

 fail:
	க்கு(i = 0; i < n; i++) {
		விடுவி(reply[i].resp);
	}
	விடுவி(reply);
	திரும்பு (PAM_CONV_ERR);
}

நிலையான கட்டமைப்பு pam_conv store_conv = { sshpam_store_conv, வெற்று };

வெறுமை
sshpam_cleanup(வெறுமை)
{
	எனில் (sshpam_handle == வெற்று || !mm_is_monitor())
		திரும்பு;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (மாறிலி வெறுமை *)&null_conv);
	எனில் (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	எனில் (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = வெற்று;
	விடுவி(sshpam_initial_user);
	sshpam_initial_user = வெற்று;
}

நிலையான முழு
sshpam_init(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	மாறிலி எழுத்து *user = authctxt->user;
	முழு r;

	எனில் (options.pam_service_name == வெற்று)
		fatal_f("internal error: NULL PAM service name");
#எனில் defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	எனில் (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	எனில் (sshpam_handle == வெற்று && ssh == வெற்று)
		fatal("%s: called initially with no packet context", __func__);
	எனில் (sshpam_handle != வெற்று) {
		/* We already have a PAM context; check if the user matches */
		எனில் ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		திரும்பு 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	எனில் (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = வெற்று;
		திரும்பு (-1);
	}

	எனில் (ssh != வெற்று && sshpam_rhost == வெற்று) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	எனில் (sshpam_rhost != வெற்று && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		எனில் (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = வெற்று;
			திரும்பு (-1);
		}
	}
	எனில் (ssh != வெற்று && sshpam_laddr != வெற்று) {
		எழுத்து *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		எனில் ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		விடுவி(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	எனில் (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = வெற்று;
		திரும்பு (-1);
	}
#endif
	திரும்பு (0);
}

நிலையான வெறுமை
expose_authinfo(மாறிலி எழுத்து *caller)
{
	எழுத்து *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	எனில் (sshpam_authctxt->session_info == வெற்று)
		auth_info = xstrdup("");
	இல்லையெனில் எனில் ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	விடுவி(auth_info);
}

நிலையான வெறுமை *
sshpam_init_ctx(Authctxt *authctxt)
{
	கட்டமைப்பு pam_ctxt *ctxt;
	முழு result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	எனில் (!options.use_pam || sshpam_account_status == 0)
		திரும்பு வெற்று;

	/* Initialize PAM */
	எனில் (sshpam_init(வெற்று, authctxt) == -1) {
		error("PAM: initialization failed");
		திரும்பு (வெற்று);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, அளவு *ctxt);

	/* Start the authentication thread */
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		விடுவி(ctxt);
		திரும்பு (வெற்று);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, வெற்று, sshpam_thread, ctxt);
	எனில் (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		விடுவி(ctxt);
		திரும்பு (வெற்று);
	}
	cleanup_ctxt = ctxt;
	திரும்பு (ctxt);
}

நிலையான முழு
sshpam_query(வெறுமை *ctx, எழுத்து **name, எழுத்து **info,
    u_int *இலக்கம், எழுத்து ***prompts, u_int **echo_on)
{
	கட்டமைப்பு sshbuf *buffer;
	கட்டமைப்பு pam_ctxt *ctxt = ctx;
	u_char type;
	எழுத்து *செய்தி;
	size_t mlen, nmesg = 0;
	முழு r;

	debug3_f("entering");
	எனில் ((buffer = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = வெற்று;
	*இலக்கம் = 0;
	ctxt->pam_done = SshPamNone;

	போது (ssh_செய்தி_recv(ctxt->pam_psock, buffer) == 0) {
		எனில் (++nmesg > PAM_MAX_இலக்கம்_செய்தி)
			fatal_f("too many query messages");
		எனில் ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &செய்தி, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		தேர்வு (type) {
		நிலை PAM_PROMPT_ECHO_ON:
		நிலை PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, அளவு(எழுத்து *));
			*echo_on = xcalloc(1, அளவு(u_int));
			(*prompts)[0] = செய்தி;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*இலக்கம் = 1;
			sshbuf_free(buffer);
			திரும்பு (0);
		நிலை PAM_ERROR_செய்தி:
		நிலை PAM_TEXT_INFO:
			விடுவி(*info);
			*info = செய்தி; /* transfer ownership */
			செய்தி = வெற்று;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			திரும்பு (0);
		நிலை PAM_ACCT_EXPIRED:
		நிலை PAM_MAXTRIES:
			எனில் (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			எனில் (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		நிலை PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		நிலை PAM_SUCCESS:
			எனில் (type == PAM_SUCCESS) {
				எனில் (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_வேர்_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				விடுவி(செய்தி);
				sshbuf_free(buffer);
				திரும்பு (0);
			}
			error("PAM: %s for %s%.100s from %.100s", செய்தி,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		இயல்பு:
			விடுவி(செய்தி);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			திரும்பு (-1);
		}
	}
	sshbuf_free(buffer);
	திரும்பு (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
நிலையான எழுத்து *
fake_password(மாறிலி எழுத்து *wire_password)
{
	மாறிலி எழுத்து junk[] = "\b\n\r\177INCORRECT";
	எழுத்து *ret = வெற்று;
	size_t i, l = wire_password != வெற்று ? strlen(wire_password) : 0;

	எனில் (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	எனில் (ret == வெற்று)
		திரும்பு வெற்று;
	க்கு (i = 0; i < l; i++)
		ret[i] = junk[i % (அளவு(junk) - 1)];
	ret[i] = '\0';
	திரும்பு ret;
}

நிலையான முழு
sshpam_respond(வெறுமை *ctx, u_int இலக்கம், எழுத்து **resp)
{
	கட்டமைப்பு sshbuf *buffer;
	கட்டமைப்பு pam_ctxt *ctxt = ctx;
	எழுத்து *fake;
	முழு r;

	debug2_f("PAM: entering, %u responses", இலக்கம்);
	தேர்வு (ctxt->pam_done) {
	நிலை SshPamAuthenticated:
		sshpam_authenticated = 1;
		திரும்பு (0);
	நிலை SshPamNone:
		நிறுத்து;
	நிலை SshPamAgain:
		திரும்பு 1;	/* KbdintResultAgain */
	இயல்பு:
		திரும்பு (-1);
	}
	எனில் (இலக்கம் != 1) {
		error("PAM: expected one response, got %u", இலக்கம்);
		திரும்பு (-1);
	}
	எனில் ((buffer = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_வேர்_login == PERMIT_YES)) {
		எனில் ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} இல்லையெனில் {
		fake = fake_password(*resp);
		எனில் ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		விடுவி(fake);
	}
	எனில் (ssh_செய்தி_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		திரும்பு (-1);
	}
	sshbuf_free(buffer);
	திரும்பு (1);
}

நிலையான வெறுமை
sshpam_free_ctx(வெறுமை *ctxtp)
{
	கட்டமைப்பு pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	விடுவி(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

முழு
sshpam_priv_kbdint_authdone(வெறுமை *ctxtp)
{
	கட்டமைப்பு pam_ctxt *ctxt = ctxtp;

	திரும்பு ctxt->pam_done == SshPamAuthenticated;
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
வெறுமை
start_pam(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	எனில் (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	எனில் (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

வெறுமை
finish_pam(வெறுமை)
{
	sshpam_cleanup();
}


u_int
do_pam_account(வெறுமை)
{
	debug_f("called");
	எனில் (sshpam_account_status != -1)
		திரும்பு (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	எனில் (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		திரும்பு (sshpam_account_status);
	}

	எனில் (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	திரும்பு (sshpam_account_status);
}

வெறுமை
do_pam_setcred(வெறுமை)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (மாறிலி வெறுமை *)&store_conv);
	எனில் (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	எனில் (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		திரும்பு;
	}
	எனில் (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	இல்லையெனில்
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

வெறுமை
do_pam_session(கட்டமைப்பு ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (மாறிலி வெறுமை *)&store_conv);
	எனில் (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	எனில் (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	இல்லையெனில் {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

முழு
is_pam_session_open(வெறுமை)
{
	திரும்பு sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
முழு
do_pam_putenv(எழுத்து *name, எழுத்து *மதிப்பு)
{
	முழு ret = 1;
	எழுத்து *compound;
	size_t len;

	len = strlen(name) + strlen(மதிப்பு) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, மதிப்பு);
	ret = pam_putenv(sshpam_handle, compound);
	விடுவி(compound);

	திரும்பு (ret);
}

எழுத்து **
fetch_pam_child_environment(வெறுமை)
{
	திரும்பு sshpam_env;
}

எழுத்து **
fetch_pam_environment(வெறுமை)
{
	திரும்பு (pam_getenvlist(sshpam_handle));
}

வெறுமை
free_pam_environment(எழுத்து **env)
{
	எழுத்து **envp;

	எனில் (env == வெற்று)
		திரும்பு;

	க்கு (envp = env; *envp; envp++)
		விடுவி(*envp);
	விடுவி(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
நிலையான முழு
sshpam_passwd_conv(முழு n, sshpam_const கட்டமைப்பு pam_message **செய்தி,
    கட்டமைப்பு pam_response **resp, வெறுமை *data)
{
	கட்டமைப்பு pam_response *reply;
	முழு r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = வெற்று;

	எனில் (n <= 0 || n > PAM_MAX_இலக்கம்_செய்தி)
		திரும்பு (PAM_CONV_ERR);

	எனில் ((reply = calloc(n, அளவு(*reply))) == வெற்று)
		திரும்பு (PAM_CONV_ERR);

	க்கு (i = 0; i < n; ++i) {
		தேர்வு (PAM_செய்தி_MEMBER(செய்தி, i, செய்தி_style)) {
		நிலை PAM_PROMPT_ECHO_OFF:
			எனில் (sshpam_password == வெற்று)
				செல் fail;
			எனில் ((reply[i].resp = strdup(sshpam_password)) == வெற்று)
				செல் fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			நிறுத்து;
		நிலை PAM_ERROR_செய்தி:
		நிலை PAM_TEXT_INFO:
			len = strlen(PAM_செய்தி_MEMBER(செய்தி, i, செய்தி));
			எனில் (len > 0) {
				எனில் ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_செய்தி_MEMBER(செய்தி, i, செய்தி))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			எனில் ((reply[i].resp = strdup("")) == வெற்று)
				செல் fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			நிறுத்து;
		இயல்பு:
			செல் fail;
		}
	}
	*resp = reply;
	திரும்பு (PAM_SUCCESS);

 fail:
	க்கு(i = 0; i < n; i++) {
		விடுவி(reply[i].resp);
	}
	விடுவி(reply);
	திரும்பு (PAM_CONV_ERR);
}

நிலையான கட்டமைப்பு pam_conv passwd_conv = { sshpam_passwd_conv, வெற்று };

/*
 * Attempt password authentication via PAM
 */
முழு
sshpam_auth_passwd(Authctxt *authctxt, மாறிலி எழுத்து *password)
{
	முழு flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	எழுத்து *fake = வெற்று;

	எனில் (!options.use_pam || sshpam_handle == வெற்று)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	எனில் (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_வேர்_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (மாறிலி வெறுமை *)&passwd_conv);
	எனில் (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = வெற்று;
	விடுவி(fake);
	எனில் (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	எனில் (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	எனில் (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		திரும்பு 1;
	} இல்லையெனில் {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		திரும்பு 0;
	}
}

முழு
sshpam_get_maxtries_reached(வெறுமை)
{
	திரும்பு sshpam_maxtries_reached;
}

வெறுமை
sshpam_set_maxtries_reached(முழு reached)
{
	எனில் (reached == 0 || sshpam_maxtries_reached)
		திரும்பு;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
