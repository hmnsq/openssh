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

#اگر_تعریف_شدہ USE_PAM
#اگر defined(HAVE_SECURITY_PAM_APPL_H)
#شامل <security/pam_appl.h>
#وگرنہ_اگر defined (HAVE_PAM_PAM_APPL_H)
#شامل <pam/pam_appl.h>
#اگر_ختم

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#اگر_تعریف_شدہ PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ورنہ
# define sshpam_const	ثابت	/* LinuxPAM, OpenPAM, AIX */
#اگر_ختم

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#اگر_تعریف_شدہ PAM_SUN_CODEBASE
# define PAM_پیغام_MEMBER(پیغام, n, member) ((*(پیغام))[(n)].member)
#ورنہ
# define PAM_پیغام_MEMBER(پیغام, n, member) ((پیغام)[(n)]->member)
#اگر_ختم

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
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "srclimit.h"

خارجی ServerOptions options;
خارجی ساخت sshbuf *loginmsg;
خارجی u_int utmp_len;

/* so we don't silently change behaviour */
#اگر_تعریف_شدہ USE_POSIX_دھاگے
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#اگر_ختم

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#اگر_تعریف_شدہ UNSUPPORTED_POSIX_دھاگے_HACK
#شامل <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
قسمتعریف pthread_t sp_pthread_t;
#ورنہ
قسمتعریف pid_t sp_pthread_t;
#تعریف_کرو pthread_exit	fake_pthread_exit
#تعریف_کرو pthread_create	fake_pthread_create
#تعریف_کرو pthread_cancel	fake_pthread_cancel
#تعریف_کرو pthread_join	fake_pthread_join
#اگر_ختم

قسمتعریف صحیح Ssh_Pam_مکمل;
#تعریف_کرو SshPamError -1
#تعریف_کرو SshPamNone 0
#تعریف_کرو SshPamAuthenticated 1
#تعریف_کرو SshPamAgain 2

ساخت pam_ctxt {
	sp_pthread_t	 pam_thread;
	صحیح		 pam_psock;
	صحیح		 pam_csock;
	Ssh_Pam_مکمل	 pam_مکمل;
};

ساکن خالی sshpam_free_ctx(خالی *);
ساکن ساخت pam_ctxt *cleanup_ctxt;

#اگر_غیر_تعریف_شدہ UNSUPPORTED_POSIX_دھاگے_HACK
/*
 * Simulate threads with processes.
 */

ساکن صحیح sshpam_thread_حالت = -1;
ساکن sshsig_t sshpam_oldsig;

ساکن خالی
sshpam_sigchld_handler(صحیح sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	اگر (cleanup_ctxt == تہی)
		واپس;	/* handler called after PAM cleanup, shouldn't happen */
	اگر (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_حالت, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		جب (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_حالت, 0) == -1) {
			اگر (errno == EINTR)
				جاری;
			واپس;
		}
	}
	اگر (sshpam_thread_حالت == -1)
		واپس;
	اگر (WIFSIGNALED(sshpam_thread_حالت)) {
		اگر (signal_is_crash(WTERMSIG(sshpam_thread_حالت)))
			_exit(EXIT_بچہ_CRASH);
	} ورنہ اگر (!WIFEXITED(sshpam_thread_حالت))
		_exit(EXIT_بچہ_CRASH);
}

/* ARGSUSED */
ساکن خالی
pthread_exit(خالی *قدر)
{
	_exit(0);
}

/* ARGSUSED */
ساکن صحیح
pthread_create(sp_pthread_t *thread, ثابت خالی *attr,
    خالی *(*thread_آغاز)(خالی *), خالی *arg)
{
	pid_t pid;
	ساخت pam_ctxt *ctx = arg;

	sshpam_thread_حالت = -1;
	انتخاب ((pid = fork())) {
	حالت -1:
		error("fork(): %s", strerror(errno));
		واپس errno;
	حالت 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_آغاز(arg);
		_exit(1);
	طےشدہ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		واپس (0);
	}
}

ساکن صحیح
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	واپس (kill(thread, SIGTERM));
}

/* ARGSUSED */
ساکن صحیح
pthread_join(sp_pthread_t thread, خالی **قدر)
{
	صحیح حالت_2;

	اگر (sshpam_thread_حالت != -1)
		واپس (sshpam_thread_حالت);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	جب (waitpid(thread, &حالت_2, 0) == -1) {
		اگر (errno == EINTR)
			جاری;
		fatal_f("waitpid: %s", strerror(errno));
	}
	واپس (حالت_2);
}
#اگر_ختم


ساکن pam_handle_t *sshpam_handle = تہی;
ساکن حرف *sshpam_initial_user;
ساکن صحیح sshpam_err = 0;
ساکن صحیح sshpam_authenticated = 0;
ساکن صحیح sshpam_session_open = 0;
ساکن صحیح sshpam_cred_established = 0;
ساکن صحیح sshpam_account_حالت = -1;
ساکن صحیح sshpam_maxtries_reached = 0;
ساکن حرف **sshpam_env = تہی;
ساکن Authctxt *sshpam_authctxt = تہی;
ساکن ثابت حرف *sshpam_password = تہی;
ساکن حرف *sshpam_rhost = تہی;
ساکن حرف *sshpam_laddr = تہی;

/* Some PAM implementations don't implement this */
#اگر_غیر_تعریف_شدہ HAVE_PAM_GETENVLIST
ساکن حرف **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 واپس تہی;
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_PAM_PUTENV
ساکن صحیح
pam_putenv(pam_handle_t *pamh, ثابت حرف *name_قدر)
{
	واپس PAM_SUCCESS;
}
#اگر_ختم /* HAVE_PAM_PUTENV */

ساکن خالی
sshpam_password_change_required(صحیح reqd)
{
	خارجی ساخت sshauthopt *auth_opts;
	ساکن صحیح saved_پورٹ, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	اگر (sshpam_authctxt == تہی)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	اگر (reqd) {
		saved_پورٹ = auth_opts->permit_پورٹ_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_پورٹ_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ورنہ {
		اگر (saved_پورٹ)
			auth_opts->permit_پورٹ_forwarding_flag = saved_پورٹ;
		اگر (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		اگر (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ساکن خالی
import_environments(ساخت sshbuf *b)
{
	حرف *env;
	u_int n, i, عدد_env;
	صحیح r;

	debug3_f("entering");

#اگر_غیر_تعریف_شدہ UNSUPPORTED_POSIX_دھاگے_HACK
	/* Import variables set by do_pam_account */
	اگر ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	اگر (n > زیادہ_سے_زیادہ_عدد)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_حالت = (صحیح)n;
	اگر ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	اگر ((r = sshbuf_get_u32(b, &عدد_env)) != 0)
		fatal_fr(r, "buffer error");
	اگر (عدد_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    عدد_env);
	}
	sshpam_env = xcalloc(عدد_env + 1, حجم(*sshpam_env));
	debug3("PAM: num env strings %u", عدد_env);
	برائے(i = 0; i < عدد_env; i++) {
		اگر ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), تہی)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[عدد_env] = تہی;

	/* Import PAM environment from subprocess */
	اگر ((r = sshbuf_get_u32(b, &عدد_env)) != 0)
		fatal_fr(r, "buffer error");
	اگر (عدد_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    عدد_env);
	}
	debug("PAM: num PAM env strings %u", عدد_env);
	برائے (i = 0; i < عدد_env; i++) {
		اگر ((r = sshbuf_get_cstring(b, &env, تہی)) != 0)
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
#اگر_ختم
}

/*
 * Conversation function for authentication thread.
 */
ساکن صحیح
sshpam_thread_conv(صحیح n, sshpam_const ساخت pam_پیغام **پیغام,
    ساخت pam_response **resp, خالی *ڈیٹا)
{
	ساخت sshbuf *بفر;
	ساخت pam_ctxt *ctxt;
	ساخت pam_response *جواب;
	صحیح r, i;
	u_char حالت_2;

	debug3_f("PAM: entering, %d messages", n);
	*resp = تہی;

	اگر (ڈیٹا == تہی) {
		error("PAM: conversation function passed a null context");
		واپس (PAM_CONV_ERR);
	}
	ctxt = ڈیٹا;
	اگر (n <= 0 || n > PAM_MAX_عدد_پیغام)
		واپس (PAM_CONV_ERR);

	اگر ((جواب = صفر_حافظہ_دو(n, حجم(*جواب))) == تہی)
		واپس PAM_CONV_ERR;
	اگر ((بفر = sshbuf_new()) == تہی) {
		آزاد(جواب);
		واپس PAM_CONV_ERR;
	}

	برائے (i = 0; i < n; ++i) {
		انتخاب (PAM_پیغام_MEMBER(پیغام, i, پیغام_style)) {
		حالت PAM_PROMPT_ECHO_OFF:
		حالت PAM_PROMPT_ECHO_ON:
			اگر ((r = sshbuf_put_cstring(بفر,
			    PAM_پیغام_MEMBER(پیغام, i, پیغام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (ssh_پیغام_send(ctxt->pam_csock,
			    PAM_پیغام_MEMBER(پیغام, i, پیغام_style), بفر) == -1)
				جاؤ fail;

			اگر (ssh_پیغام_recv(ctxt->pam_csock, بفر) == -1)
				جاؤ fail;
			اگر ((r = sshbuf_get_u8(بفر, &حالت_2)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (حالت_2 != PAM_AUTHTOK)
				جاؤ fail;
			اگر ((r = sshbuf_get_cstring(بفر,
			    &جواب[i].resp, تہی)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			توڑو;
		حالت PAM_ERROR_پیغام:
		حالت PAM_متن_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_پیغام_MEMBER(پیغام, i, پیغام_style),
			       PAM_پیغام_MEMBER(پیغام, i, پیغام));
			اگر ((r = sshbuf_put_cstring(بفر,
			    PAM_پیغام_MEMBER(پیغام, i, پیغام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			اگر (ssh_پیغام_send(ctxt->pam_csock,
			    PAM_پیغام_MEMBER(پیغام, i, پیغام_style), بفر) == -1)
				جاؤ fail;
			توڑو;
		طےشدہ:
			جاؤ fail;
		}
		sshbuf_reset(بفر);
	}
	sshbuf_free(بفر);
	*resp = جواب;
	واپس (PAM_SUCCESS);

 fail:
	برائے(i = 0; i < n; i++) {
		آزاد(جواب[i].resp);
	}
	آزاد(جواب);
	sshbuf_free(بفر);
	واپس (PAM_CONV_ERR);
}

ساکن صحیح
check_pam_user(Authctxt *authctxt)
{
	ثابت حرف *pam_user;

	اگر (authctxt == تہی || authctxt->pw == تہی ||
	    authctxt->pw->pw_name == تہی)
		fatal_f("PAM authctxt user not initialized");

	اگر ((sshpam_err = pam_get_شے(sshpam_handle, PAM_USER,
	    (sshpam_const خالی **) &pam_user)) != PAM_SUCCESS)
		واپس sshpam_err;

	اگر (pam_user == تہی) {
		debug("PAM error: PAM_USER is NULL");
		واپس PAM_USER_UNKNOWN;
	}

	اگر (sshpam_initial_user == تہی)
		fatal_f("internal error: sshpam_initial_user NULL");
	اگر (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		واپس PAM_USER_UNKNOWN;
	}
	واپس PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ساکن خالی *
sshpam_thread(خالی *ctxtp)
{
	ساخت pam_ctxt *ctxt = ctxtp;
	ساخت sshbuf *بفر = تہی;
	ساخت pam_conv sshpam_conv;
	صحیح r, flags = (options.permit_خالی_خانے_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#اگر_غیر_تعریف_شدہ UNSUPPORTED_POSIX_دھاگے_HACK
	خارجی حرف **environ;
	حرف **env_from_pam;
	u_int i;
	ثابت حرف *pam_user;
	ثابت حرف **ptr_pam_user = &pam_user;
	حرف *tz = getenv("TZ");

	sshpam_err = pam_get_شے(sshpam_handle, PAM_USER,
	    (sshpam_const خالی **)ptr_pam_user);
	اگر (sshpam_err != PAM_SUCCESS)
		جاؤ auth_fail;

	environ[0] = تہی;
	اگر (tz != تہی)
		اگر (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	اگر (sshpam_authctxt != تہی) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#اگر_ختم

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	اگر (sshpam_authctxt == تہی)
		fatal_f("PAM authctxt not initialized");

	اگر ((بفر = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_CONV,
	    (ثابت خالی *)&sshpam_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		جاؤ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	اگر (sshpam_err == PAM_MAXTRIES)
		sshpam_سیٹ_maxtries_reached(1);
	اگر (sshpam_err != PAM_SUCCESS)
		جاؤ auth_fail;
	اگر ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		جاؤ auth_fail;

	اگر (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		جاؤ auth_fail;
	}
	اگر (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		اگر (sshpam_err != PAM_SUCCESS)
			جاؤ auth_fail;
		sshpam_password_change_required(0);
	}

	اگر ((r = sshbuf_put_cstring(بفر, "OK")) != 0)
		fatal_fr(r, "buffer error");

#اگر_غیر_تعریف_شدہ UNSUPPORTED_POSIX_دھاگے_HACK
	/* Export variables set by do_pam_account */
	اگر ((r = sshbuf_put_u32(بفر, sshpam_account_حالت)) != 0 ||
	    (r = sshbuf_put_u32(بفر, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	برائے (i = 0; environ[i] != تہی; i++) {
		/*گنتی*/
		اگر (i > زیادہ_سے_زیادہ_عدد)
			fatal_f("too many environment strings");
	}
	اگر ((r = sshbuf_put_u32(بفر, i)) != 0)
		fatal_fr(r, "buffer error");
	برائے (i = 0; environ[i] != تہی; i++) {
		اگر ((r = sshbuf_put_cstring(بفر, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	برائے (i = 0; env_from_pam != تہی && env_from_pam[i] != تہی; i++) {
		/*گنتی*/
		اگر (i > زیادہ_سے_زیادہ_عدد)
			fatal_f("too many PAM environment strings");
	}
	اگر ((r = sshbuf_put_u32(بفر, i)) != 0)
		fatal_fr(r, "buffer error");
	برائے (i = 0; env_from_pam != تہی && env_from_pam[i] != تہی; i++) {
		اگر ((r = sshbuf_put_cstring(بفر, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#اگر_ختم /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_پیغام_send(ctxt->pam_csock, sshpam_err, بفر);
	sshbuf_free(بفر);
	pthread_exit(تہی);

 auth_fail:
	اگر ((r = sshbuf_put_cstring(بفر,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	اگر (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_پیغام_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, بفر);
	ورنہ اگر (sshpam_maxtries_reached)
		ssh_پیغام_send(ctxt->pam_csock, PAM_MAXTRIES, بفر);
	ورنہ
		ssh_پیغام_send(ctxt->pam_csock, PAM_AUTH_ERR, بفر);
	sshbuf_free(بفر);
	pthread_exit(تہی);

	واپس (تہی); /* Avoid warning for non-pthread case */
}

خالی
sshpam_thread_cleanup(خالی)
{
	ساخت pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	اگر (ctxt != تہی && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, تہی);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, حجم(*ctxt));
		cleanup_ctxt = تہی;
	}
}

ساکن صحیح
sshpam_null_conv(صحیح n, sshpam_const ساخت pam_پیغام **پیغام,
    ساخت pam_response **resp, خالی *ڈیٹا)
{
	debug3_f("PAM: entering, %d messages", n);
	واپس (PAM_CONV_ERR);
}

ساکن ساخت pam_conv null_conv = { sshpam_null_conv, تہی };

ساکن صحیح
sshpam_store_conv(صحیح n, sshpam_const ساخت pam_پیغام **پیغام,
    ساخت pam_response **resp, خالی *ڈیٹا)
{
	ساخت pam_response *جواب;
	صحیح r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = تہی;

	اگر (n <= 0 || n > PAM_MAX_عدد_پیغام)
		واپس (PAM_CONV_ERR);

	اگر ((جواب = صفر_حافظہ_دو(n, حجم(*جواب))) == تہی)
		واپس (PAM_CONV_ERR);

	برائے (i = 0; i < n; ++i) {
		انتخاب (PAM_پیغام_MEMBER(پیغام, i, پیغام_style)) {
		حالت PAM_ERROR_پیغام:
		حالت PAM_متن_INFO:
			اگر ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_پیغام_MEMBER(پیغام, i, پیغام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			جواب[i].resp_retcode = PAM_SUCCESS;
			توڑو;
		طےشدہ:
			جاؤ fail;
		}
	}
	*resp = جواب;
	واپس (PAM_SUCCESS);

 fail:
	برائے(i = 0; i < n; i++) {
		آزاد(جواب[i].resp);
	}
	آزاد(جواب);
	واپس (PAM_CONV_ERR);
}

ساکن ساخت pam_conv store_conv = { sshpam_store_conv, تہی };

خالی
sshpam_cleanup(خالی)
{
	اگر (sshpam_handle == تہی || !mm_is_monitor())
		واپس;
	debug("PAM: cleanup");
	pam_سیٹ_شے(sshpam_handle, PAM_CONV, (ثابت خالی *)&null_conv);
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
	pam_انتہا(sshpam_handle, sshpam_err);
	sshpam_handle = تہی;
	آزاد(sshpam_initial_user);
	sshpam_initial_user = تہی;
}

ساکن صحیح
sshpam_init(ساخت ssh *ssh, Authctxt *authctxt)
{
	ثابت حرف *user = authctxt->user;
	صحیح r;

	اگر (options.pam_service_name == تہی)
		fatal_f("internal error: NULL PAM service name");
#اگر defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_سائز)
	/* Protect buggy PAM implementations from excessively long usernames */
	اگر (لڑی_لمبائی(user) >= PAM_MAX_RESP_سائز)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
#اگر_ختم
	اگر (sshpam_handle == تہی && ssh == تہی)
		fatal("%s: called initially with no packet context", __func__);
	اگر (sshpam_handle != تہی) {
		/* We already have a PAM context; check if the user matches */
		اگر ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		واپس 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_آغاز(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	اگر (sshpam_err != PAM_SUCCESS) {
		pam_انتہا(sshpam_handle, sshpam_err);
		sshpam_handle = تہی;
		واپس (-1);
	}

	اگر (ssh != تہی && sshpam_rhost == تہی) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_اندر(ssh));
	}
	اگر (sshpam_rhost != تہی && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		اگر (sshpam_err != PAM_SUCCESS) {
			pam_انتہا(sshpam_handle, sshpam_err);
			sshpam_handle = تہی;
			واپس (-1);
		}
	}
	اگر (ssh != تہی && sshpam_laddr != تہی) {
		حرف *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    sshpam_laddr, ssh_local_پورٹ(ssh));
		اگر ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		آزاد(conninfo);
	}

#اگر_تعریف_شدہ PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_TTY, "ssh");
	اگر (sshpam_err != PAM_SUCCESS) {
		pam_انتہا(sshpam_handle, sshpam_err);
		sshpam_handle = تہی;
		واپس (-1);
	}
#اگر_ختم
	واپس (0);
}

ساکن خالی
expose_authinfo(ثابت حرف *caller)
{
	حرف *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	اگر (sshpam_authctxt->session_info == تہی)
		auth_info = xstrdup("");
	ورنہ اگر ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == تہی)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	آزاد(auth_info);
}

ساکن خالی *
sshpam_init_ctx(Authctxt *authctxt)
{
	ساخت pam_ctxt *ctxt;
	صحیح نتیجہ, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	اگر (!options.use_pam || sshpam_account_حالت == 0)
		واپس تہی;

	/* Initialize PAM */
	اگر (sshpam_init(تہی, authctxt) == -1) {
		error("PAM: initialization failed");
		واپس (تہی);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, حجم *ctxt);

	/* Start the authentication thread */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		آزاد(ctxt);
		واپس (تہی);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	نتیجہ = pthread_create(&ctxt->pam_thread, تہی, sshpam_thread, ctxt);
	اگر (نتیجہ != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(نتیجہ));
		close(socks[0]);
		close(socks[1]);
		آزاد(ctxt);
		واپس (تہی);
	}
	cleanup_ctxt = ctxt;
	واپس (ctxt);
}

ساکن صحیح
sshpam_query(خالی *ctx, حرف **name, حرف **info,
    u_int *عدد, حرف ***prompts, u_int **echo_on)
{
	ساخت sshbuf *بفر;
	ساخت pam_ctxt *ctxt = ctx;
	u_char type;
	حرف *پیغام;
	سائز_t mlen, nmesg = 0;
	صحیح r;

	debug3_f("entering");
	اگر ((بفر = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = تہی;
	*عدد = 0;
	ctxt->pam_مکمل = SshPamNone;

	جب (ssh_پیغام_recv(ctxt->pam_psock, بفر) == 0) {
		اگر (++nmesg > PAM_MAX_عدد_پیغام)
			fatal_f("too many query messages");
		اگر ((r = sshbuf_get_u8(بفر, &type)) != 0 ||
		    (r = sshbuf_get_cstring(بفر, &پیغام, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		انتخاب (type) {
		حالت PAM_PROMPT_ECHO_ON:
		حالت PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, حجم(حرف *));
			*echo_on = xcalloc(1, حجم(u_int));
			(*prompts)[0] = پیغام;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*عدد = 1;
			sshbuf_free(بفر);
			واپس (0);
		حالت PAM_ERROR_پیغام:
		حالت PAM_متن_INFO:
			آزاد(*info);
			*info = پیغام; /* transfer ownership */
			پیغام = تہی;
			ctxt->pam_مکمل = SshPamAgain;
			sshbuf_free(بفر);
			واپس (0);
		حالت PAM_ACCT_EXPIRED:
		حالت PAM_MAXTRIES:
			اگر (type == PAM_ACCT_EXPIRED)
				sshpam_account_حالت = 0;
			اگر (type == PAM_MAXTRIES)
				sshpam_سیٹ_maxtries_reached(1);
			/* FALLTHROUGH */
		حالت PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		حالت PAM_SUCCESS:
			اگر (type == PAM_SUCCESS) {
				اگر (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_جڑ_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(بفر);
				ctxt->pam_مکمل = SshPamAuthenticated;
				آزاد(پیغام);
				sshbuf_free(بفر);
				واپس (0);
			}
			error("PAM: %s for %s%.100s from %.100s", پیغام,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		طےشدہ:
			آزاد(پیغام);
			ctxt->pam_مکمل = SshPamError;
			sshbuf_free(بفر);
			واپس (-1);
		}
	}
	sshbuf_free(بفر);
	واپس (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ساکن حرف *
fake_password(ثابت حرف *wire_password)
{
	ثابت حرف junk[] = "\b\n\r\177INCORRECT";
	حرف *ret = تہی;
	سائز_t i, l = wire_password != تہی ? لڑی_لمبائی(wire_password) : 0;

	اگر (l >= زیادہ_سے_زیادہ_عدد)
		fatal_f("password length too long: %zu", l);

	ret = حافظہ_دو(l + 1);
	اگر (ret == تہی)
		واپس تہی;
	برائے (i = 0; i < l; i++)
		ret[i] = junk[i % (حجم(junk) - 1)];
	ret[i] = '\0';
	واپس ret;
}

ساکن صحیح
sshpam_respond(خالی *ctx, u_int عدد, حرف **resp)
{
	ساخت sshbuf *بفر;
	ساخت pam_ctxt *ctxt = ctx;
	حرف *fake;
	صحیح r;

	debug2_f("PAM: entering, %u responses", عدد);
	انتخاب (ctxt->pam_مکمل) {
	حالت SshPamAuthenticated:
		sshpam_authenticated = 1;
		واپس (0);
	حالت SshPamNone:
		توڑو;
	حالت SshPamAgain:
		واپس 1;	/* KbdintResultAgain */
	طےشدہ:
		واپس (-1);
	}
	اگر (عدد != 1) {
		error("PAM: expected one response, got %u", عدد);
		واپس (-1);
	}
	اگر ((بفر = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_جڑ_login == PERMIT_YES)) {
		اگر ((r = sshbuf_put_cstring(بفر, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ورنہ {
		fake = fake_password(*resp);
		اگر ((r = sshbuf_put_cstring(بفر, fake)) != 0)
			fatal_fr(r, "buffer error");
		آزاد(fake);
	}
	اگر (ssh_پیغام_send(ctxt->pam_psock, PAM_AUTHTOK, بفر) == -1) {
		sshbuf_free(بفر);
		واپس (-1);
	}
	sshbuf_free(بفر);
	واپس (1);
}

ساکن خالی
sshpam_free_ctx(خالی *ctxtp)
{
	ساخت pam_ctxt *ctxt = ctxtp;

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
sshpam_priv_kbdint_authdone(خالی *ctxtp)
{
	ساخت pam_ctxt *ctxt = ctxtp;

	واپس ctxt->pam_مکمل == SshPamAuthenticated;
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
خالی
آغاز_pam(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	اگر (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	اگر (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

خالی
اختتام_pam(خالی)
{
	sshpam_cleanup();
}


u_int
do_pam_account(خالی)
{
	debug_f("called");
	اگر (sshpam_account_حالت != -1)
		واپس (sshpam_account_حالت);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	اگر (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_حالت = 0;
		واپس (sshpam_account_حالت);
	}

	اگر (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_حالت = 1;
	واپس (sshpam_account_حالت);
}

خالی
do_pam_setcred(خالی)
{
	sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_CONV,
	    (ثابت خالی *)&store_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	اگر (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		واپس;
	}
	اگر (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ورنہ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

خالی
do_pam_session(ساخت ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_CONV,
	    (ثابت خالی *)&store_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	اگر (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ورنہ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

صحیح
is_pam_session_open(خالی)
{
	واپس sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
صحیح
do_pam_putenv(حرف *name, حرف *قدر)
{
	صحیح ret = 1;
	حرف *compound;
	سائز_t len;

	len = لڑی_لمبائی(name) + لڑی_لمبائی(قدر) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, قدر);
	ret = pam_putenv(sshpam_handle, compound);
	آزاد(compound);

	واپس (ret);
}

حرف **
fetch_pam_بچہ_environment(خالی)
{
	واپس sshpam_env;
}

حرف **
fetch_pam_environment(خالی)
{
	واپس (pam_getenvlist(sshpam_handle));
}

خالی
free_pam_environment(حرف **env)
{
	حرف **envp;

	اگر (env == تہی)
		واپس;

	برائے (envp = env; *envp; envp++)
		آزاد(*envp);
	آزاد(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ساکن صحیح
sshpam_passwd_conv(صحیح n, sshpam_const ساخت pam_پیغام **پیغام,
    ساخت pam_response **resp, خالی *ڈیٹا)
{
	ساخت pam_response *جواب;
	صحیح r, i;
	سائز_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = تہی;

	اگر (n <= 0 || n > PAM_MAX_عدد_پیغام)
		واپس (PAM_CONV_ERR);

	اگر ((جواب = صفر_حافظہ_دو(n, حجم(*جواب))) == تہی)
		واپس (PAM_CONV_ERR);

	برائے (i = 0; i < n; ++i) {
		انتخاب (PAM_پیغام_MEMBER(پیغام, i, پیغام_style)) {
		حالت PAM_PROMPT_ECHO_OFF:
			اگر (sshpam_password == تہی)
				جاؤ fail;
			اگر ((جواب[i].resp = strdup(sshpam_password)) == تہی)
				جاؤ fail;
			جواب[i].resp_retcode = PAM_SUCCESS;
			توڑو;
		حالت PAM_ERROR_پیغام:
		حالت PAM_متن_INFO:
			len = لڑی_لمبائی(PAM_پیغام_MEMBER(پیغام, i, پیغام));
			اگر (len > 0) {
				اگر ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_پیغام_MEMBER(پیغام, i, پیغام))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			اگر ((جواب[i].resp = strdup("")) == تہی)
				جاؤ fail;
			جواب[i].resp_retcode = PAM_SUCCESS;
			توڑو;
		طےشدہ:
			جاؤ fail;
		}
	}
	*resp = جواب;
	واپس (PAM_SUCCESS);

 fail:
	برائے(i = 0; i < n; i++) {
		آزاد(جواب[i].resp);
	}
	آزاد(جواب);
	واپس (PAM_CONV_ERR);
}

ساکن ساخت pam_conv passwd_conv = { sshpam_passwd_conv, تہی };

/*
 * Attempt password authentication via PAM
 */
صحیح
sshpam_auth_passwd(Authctxt *authctxt, ثابت حرف *password)
{
	صحیح flags = (options.permit_خالی_خانے_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	حرف *fake = تہی;

	اگر (!options.use_pam || sshpam_handle == تہی)
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
	    options.permit_جڑ_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_سیٹ_شے(sshpam_handle, PAM_CONV,
	    (ثابت خالی *)&passwd_conv);
	اگر (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = تہی;
	آزاد(fake);
	اگر (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	اگر (sshpam_err == PAM_MAXTRIES)
		sshpam_سیٹ_maxtries_reached(1);
	اگر (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		واپس 1;
	} ورنہ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		واپس 0;
	}
}

صحیح
sshpam_get_maxtries_reached(خالی)
{
	واپس sshpam_maxtries_reached;
}

خالی
sshpam_سیٹ_maxtries_reached(صحیح reached)
{
	اگر (reached == 0 || sshpam_maxtries_reached)
		واپس;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#اگر_ختم /* USE_PAM */
