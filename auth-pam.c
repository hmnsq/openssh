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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef USE_PAM
#যদি defined(HAVE_SECURITY_PAM_APPL_H)
#অন্তর্ভাব <security/pam_appl.h>
#নোচেদ্যদি defined (HAVE_PAM_PAM_APPL_H)
#অন্তর্ভাব <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#অন্যথা
# define sshpam_const	ধ্রুব	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_বার্তা_MEMBER(বার্তা, n, member) ((*(বার্তা))[(n)].member)
#অন্যথা
# define PAM_বার্তা_MEMBER(বার্তা, n, member) ((বার্তা)[(n)]->member)
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "auth-options.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "srclimit.h"

বাহ্য ServerOptions options;
বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য u_int utmp_len;

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
#অন্তর্ভাব <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
প্রকারনির্দেশ pthread_t sp_pthread_t;
#অন্যথা
প্রকারনির্দেশ pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

প্রকারনির্দেশ পূর্ণাঙ্ক SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

সংরচনা pam_ctxt {
	sp_pthread_t	 pam_thread;
	পূর্ণাঙ্ক		 pam_psock;
	পূর্ণাঙ্ক		 pam_csock;
	SshPamDone	 pam_done;
};

স্থির শূন্য sshpam_free_ctx(শূন্য *);
স্থির সংরচনা pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

স্থির পূর্ণাঙ্ক sshpam_thread_status = -1;
স্থির sshsig_t sshpam_oldsig;

স্থির শূন্য
sshpam_sigchld_handler(পূর্ণাঙ্ক sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	যদি (cleanup_ctxt == রিক্ত)
		প্রত্যাগম;	/* handler called after PAM cleanup, shouldn't happen */
	যদি (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		যাবত্ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			যদি (errno == EINTR)
				অনুবর্ত;
			প্রত্যাগম;
		}
	}
	যদি (sshpam_thread_status == -1)
		প্রত্যাগম;
	যদি (WIFSIGNALED(sshpam_thread_status)) {
		যদি (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} অন্যথা যদি (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
স্থির শূন্য
pthread_exit(শূন্য *মান)
{
	_exit(0);
}

/* ARGSUSED */
স্থির পূর্ণাঙ্ক
pthread_create(sp_pthread_t *thread, ধ্রুব শূন্য *attr,
    শূন্য *(*thread_start)(শূন্য *), শূন্য *arg)
{
	pid_t pid;
	সংরচনা pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	বিকল্প ((pid = fork())) {
	পক্ষ -1:
		error("fork(): %s", strerror(errno));
		প্রত্যাগম errno;
	পক্ষ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	স্বভাব:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		প্রত্যাগম (0);
	}
}

স্থির পূর্ণাঙ্ক
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	প্রত্যাগম (kill(thread, SIGTERM));
}

/* ARGSUSED */
স্থির পূর্ণাঙ্ক
pthread_join(sp_pthread_t thread, শূন্য **মান)
{
	পূর্ণাঙ্ক status;

	যদি (sshpam_thread_status != -1)
		প্রত্যাগম (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	যাবত্ (waitpid(thread, &status, 0) == -1) {
		যদি (errno == EINTR)
			অনুবর্ত;
		fatal_f("waitpid: %s", strerror(errno));
	}
	প্রত্যাগম (status);
}
#endif


স্থির pam_handle_t *sshpam_handle = রিক্ত;
স্থির বর্ণ *sshpam_initial_user;
স্থির পূর্ণাঙ্ক sshpam_err = 0;
স্থির পূর্ণাঙ্ক sshpam_authenticated = 0;
স্থির পূর্ণাঙ্ক sshpam_session_open = 0;
স্থির পূর্ণাঙ্ক sshpam_cred_established = 0;
স্থির পূর্ণাঙ্ক sshpam_account_status = -1;
স্থির পূর্ণাঙ্ক sshpam_maxtries_reached = 0;
স্থির বর্ণ **sshpam_env = রিক্ত;
স্থির Authctxt *sshpam_authctxt = রিক্ত;
স্থির ধ্রুব বর্ণ *sshpam_password = রিক্ত;
স্থির বর্ণ *sshpam_rhost = রিক্ত;
স্থির বর্ণ *sshpam_laddr = রিক্ত;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
স্থির বর্ণ **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 প্রত্যাগম রিক্ত;
}
#endif

#ifndef HAVE_PAM_PUTENV
স্থির পূর্ণাঙ্ক
pam_putenv(pam_handle_t *pamh, ধ্রুব বর্ণ *name_মান)
{
	প্রত্যাগম PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

স্থির শূন্য
sshpam_password_change_required(পূর্ণাঙ্ক reqd)
{
	বাহ্য সংরচনা sshauthopt *auth_opts;
	স্থির পূর্ণাঙ্ক saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	যদি (sshpam_authctxt == রিক্ত)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	যদি (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} অন্যথা {
		যদি (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		যদি (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		যদি (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
স্থির শূন্য
import_environments(সংরচনা sshbuf *b)
{
	বর্ণ *env;
	u_int n, i, অঙ্ক_env;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	যদি ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	যদি (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (পূর্ণাঙ্ক)n;
	যদি ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	যদি ((r = sshbuf_get_u32(b, &অঙ্ক_env)) != 0)
		fatal_fr(r, "buffer error");
	যদি (অঙ্ক_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    অঙ্ক_env);
	}
	sshpam_env = xcalloc(অঙ্ক_env + 1, পরিমাণ(*sshpam_env));
	debug3("PAM: num env strings %u", অঙ্ক_env);
	প্রতি(i = 0; i < অঙ্ক_env; i++) {
		যদি ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), রিক্ত)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[অঙ্ক_env] = রিক্ত;

	/* Import PAM environment from subprocess */
	যদি ((r = sshbuf_get_u32(b, &অঙ্ক_env)) != 0)
		fatal_fr(r, "buffer error");
	যদি (অঙ্ক_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    অঙ্ক_env);
	}
	debug("PAM: num PAM env strings %u", অঙ্ক_env);
	প্রতি (i = 0; i < অঙ্ক_env; i++) {
		যদি ((r = sshbuf_get_cstring(b, &env, রিক্ত)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		যদি ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
স্থির পূর্ণাঙ্ক
sshpam_thread_conv(পূর্ণাঙ্ক n, sshpam_const সংরচনা pam_message **বার্তা,
    সংরচনা pam_response **resp, শূন্য *data)
{
	সংরচনা sshbuf *buffer;
	সংরচনা pam_ctxt *ctxt;
	সংরচনা pam_response *reply;
	পূর্ণাঙ্ক r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = রিক্ত;

	যদি (data == রিক্ত) {
		error("PAM: conversation function passed a null context");
		প্রত্যাগম (PAM_CONV_ERR);
	}
	ctxt = data;
	যদি (n <= 0 || n > PAM_MAX_অঙ্ক_বার্তা)
		প্রত্যাগম (PAM_CONV_ERR);

	যদি ((reply = calloc(n, পরিমাণ(*reply))) == রিক্ত)
		প্রত্যাগম PAM_CONV_ERR;
	যদি ((buffer = sshbuf_new()) == রিক্ত) {
		মুক্ত(reply);
		প্রত্যাগম PAM_CONV_ERR;
	}

	প্রতি (i = 0; i < n; ++i) {
		বিকল্প (PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style)) {
		পক্ষ PAM_PROMPT_ECHO_OFF:
		পক্ষ PAM_PROMPT_ECHO_ON:
			যদি ((r = sshbuf_put_cstring(buffer,
			    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			যদি (ssh_বার্তা_send(ctxt->pam_csock,
			    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style), buffer) == -1)
				গচ্ছ fail;

			যদি (ssh_বার্তা_recv(ctxt->pam_csock, buffer) == -1)
				গচ্ছ fail;
			যদি ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			যদি (status != PAM_AUTHTOK)
				গচ্ছ fail;
			যদি ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, রিক্ত)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ভঙ্গ;
		পক্ষ PAM_ERROR_বার্তা:
		পক্ষ PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style),
			       PAM_বার্তা_MEMBER(বার্তা, i, বার্তা));
			যদি ((r = sshbuf_put_cstring(buffer,
			    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			যদি (ssh_বার্তা_send(ctxt->pam_csock,
			    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style), buffer) == -1)
				গচ্ছ fail;
			ভঙ্গ;
		স্বভাব:
			গচ্ছ fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	প্রত্যাগম (PAM_SUCCESS);

 fail:
	প্রতি(i = 0; i < n; i++) {
		মুক্ত(reply[i].resp);
	}
	মুক্ত(reply);
	sshbuf_free(buffer);
	প্রত্যাগম (PAM_CONV_ERR);
}

স্থির পূর্ণাঙ্ক
check_pam_user(Authctxt *authctxt)
{
	ধ্রুব বর্ণ *pam_user;

	যদি (authctxt == রিক্ত || authctxt->pw == রিক্ত ||
	    authctxt->pw->pw_name == রিক্ত)
		fatal_f("PAM authctxt user not initialized");

	যদি ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const শূন্য **) &pam_user)) != PAM_SUCCESS)
		প্রত্যাগম sshpam_err;

	যদি (pam_user == রিক্ত) {
		debug("PAM error: PAM_USER is NULL");
		প্রত্যাগম PAM_USER_UNKNOWN;
	}

	যদি (sshpam_initial_user == রিক্ত)
		fatal_f("internal error: sshpam_initial_user NULL");
	যদি (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		প্রত্যাগম PAM_USER_UNKNOWN;
	}
	প্রত্যাগম PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
স্থির শূন্য *
sshpam_thread(শূন্য *ctxtp)
{
	সংরচনা pam_ctxt *ctxt = ctxtp;
	সংরচনা sshbuf *buffer = রিক্ত;
	সংরচনা pam_conv sshpam_conv;
	পূর্ণাঙ্ক r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	বাহ্য বর্ণ **environ;
	বর্ণ **env_from_pam;
	u_int i;
	ধ্রুব বর্ণ *pam_user;
	ধ্রুব বর্ণ **ptr_pam_user = &pam_user;
	বর্ণ *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const শূন্য **)ptr_pam_user);
	যদি (sshpam_err != PAM_SUCCESS)
		গচ্ছ auth_fail;

	environ[0] = রিক্ত;
	যদি (tz != রিক্ত)
		যদি (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	যদি (sshpam_authctxt != রিক্ত) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	যদি (sshpam_authctxt == রিক্ত)
		fatal_f("PAM authctxt not initialized");

	যদি ((buffer = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ধ্রুব শূন্য *)&sshpam_conv);
	যদি (sshpam_err != PAM_SUCCESS)
		গচ্ছ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	যদি (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	যদি (sshpam_err != PAM_SUCCESS)
		গচ্ছ auth_fail;
	যদি ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		গচ্ছ auth_fail;

	যদি (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		গচ্ছ auth_fail;
	}
	যদি (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		যদি (sshpam_err != PAM_SUCCESS)
			গচ্ছ auth_fail;
		sshpam_password_change_required(0);
	}

	যদি ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	যদি ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	প্রতি (i = 0; environ[i] != রিক্ত; i++) {
		/*গুনতি*/
		যদি (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	যদি ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	প্রতি (i = 0; environ[i] != রিক্ত; i++) {
		যদি ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	প্রতি (i = 0; env_from_pam != রিক্ত && env_from_pam[i] != রিক্ত; i++) {
		/*গুনতি*/
		যদি (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	যদি ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	প্রতি (i = 0; env_from_pam != রিক্ত && env_from_pam[i] != রিক্ত; i++) {
		যদি ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_বার্তা_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(রিক্ত);

 auth_fail:
	যদি ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	যদি (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_বার্তা_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	অন্যথা যদি (sshpam_maxtries_reached)
		ssh_বার্তা_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	অন্যথা
		ssh_বার্তা_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(রিক্ত);

	প্রত্যাগম (রিক্ত); /* Avoid warning for non-pthread case */
}

শূন্য
sshpam_thread_cleanup(শূন্য)
{
	সংরচনা pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	যদি (ctxt != রিক্ত && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, রিক্ত);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, পরিমাণ(*ctxt));
		cleanup_ctxt = রিক্ত;
	}
}

স্থির পূর্ণাঙ্ক
sshpam_null_conv(পূর্ণাঙ্ক n, sshpam_const সংরচনা pam_message **বার্তা,
    সংরচনা pam_response **resp, শূন্য *data)
{
	debug3_f("PAM: entering, %d messages", n);
	প্রত্যাগম (PAM_CONV_ERR);
}

স্থির সংরচনা pam_conv null_conv = { sshpam_null_conv, রিক্ত };

স্থির পূর্ণাঙ্ক
sshpam_store_conv(পূর্ণাঙ্ক n, sshpam_const সংরচনা pam_message **বার্তা,
    সংরচনা pam_response **resp, শূন্য *data)
{
	সংরচনা pam_response *reply;
	পূর্ণাঙ্ক r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = রিক্ত;

	যদি (n <= 0 || n > PAM_MAX_অঙ্ক_বার্তা)
		প্রত্যাগম (PAM_CONV_ERR);

	যদি ((reply = calloc(n, পরিমাণ(*reply))) == রিক্ত)
		প্রত্যাগম (PAM_CONV_ERR);

	প্রতি (i = 0; i < n; ++i) {
		বিকল্প (PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style)) {
		পক্ষ PAM_ERROR_বার্তা:
		পক্ষ PAM_TEXT_INFO:
			যদি ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			ভঙ্গ;
		স্বভাব:
			গচ্ছ fail;
		}
	}
	*resp = reply;
	প্রত্যাগম (PAM_SUCCESS);

 fail:
	প্রতি(i = 0; i < n; i++) {
		মুক্ত(reply[i].resp);
	}
	মুক্ত(reply);
	প্রত্যাগম (PAM_CONV_ERR);
}

স্থির সংরচনা pam_conv store_conv = { sshpam_store_conv, রিক্ত };

শূন্য
sshpam_cleanup(শূন্য)
{
	যদি (sshpam_handle == রিক্ত || !mm_is_monitor())
		প্রত্যাগম;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (ধ্রুব শূন্য *)&null_conv);
	যদি (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	যদি (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = রিক্ত;
	মুক্ত(sshpam_initial_user);
	sshpam_initial_user = রিক্ত;
}

স্থির পূর্ণাঙ্ক
sshpam_init(সংরচনা ssh *ssh, Authctxt *authctxt)
{
	ধ্রুব বর্ণ *user = authctxt->user;
	পূর্ণাঙ্ক r;

	যদি (options.pam_service_name == রিক্ত)
		fatal_f("internal error: NULL PAM service name");
#যদি defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	যদি (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	যদি (sshpam_handle == রিক্ত && ssh == রিক্ত)
		fatal("%s: called initially with no packet context", __func__);
	যদি (sshpam_handle != রিক্ত) {
		/* We already have a PAM context; check if the user matches */
		যদি ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		প্রত্যাগম 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	যদি (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = রিক্ত;
		প্রত্যাগম (-1);
	}

	যদি (ssh != রিক্ত && sshpam_rhost == রিক্ত) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	যদি (sshpam_rhost != রিক্ত && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		যদি (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = রিক্ত;
			প্রত্যাগম (-1);
		}
	}
	যদি (ssh != রিক্ত && sshpam_laddr != রিক্ত) {
		বর্ণ *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		যদি ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		মুক্ত(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	যদি (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = রিক্ত;
		প্রত্যাগম (-1);
	}
#endif
	প্রত্যাগম (0);
}

স্থির শূন্য
expose_authinfo(ধ্রুব বর্ণ *caller)
{
	বর্ণ *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	যদি (sshpam_authctxt->session_info == রিক্ত)
		auth_info = xstrdup("");
	অন্যথা যদি ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	মুক্ত(auth_info);
}

স্থির শূন্য *
sshpam_init_ctx(Authctxt *authctxt)
{
	সংরচনা pam_ctxt *ctxt;
	পূর্ণাঙ্ক result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	যদি (!options.use_pam || sshpam_account_status == 0)
		প্রত্যাগম রিক্ত;

	/* Initialize PAM */
	যদি (sshpam_init(রিক্ত, authctxt) == -1) {
		error("PAM: initialization failed");
		প্রত্যাগম (রিক্ত);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, পরিমাণ *ctxt);

	/* Start the authentication thread */
	যদি (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		মুক্ত(ctxt);
		প্রত্যাগম (রিক্ত);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, রিক্ত, sshpam_thread, ctxt);
	যদি (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		মুক্ত(ctxt);
		প্রত্যাগম (রিক্ত);
	}
	cleanup_ctxt = ctxt;
	প্রত্যাগম (ctxt);
}

স্থির পূর্ণাঙ্ক
sshpam_query(শূন্য *ctx, বর্ণ **name, বর্ণ **info,
    u_int *অঙ্ক, বর্ণ ***prompts, u_int **echo_on)
{
	সংরচনা sshbuf *buffer;
	সংরচনা pam_ctxt *ctxt = ctx;
	u_char type;
	বর্ণ *বার্তা;
	size_t mlen, nmesg = 0;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি ((buffer = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = রিক্ত;
	*অঙ্ক = 0;
	ctxt->pam_done = SshPamNone;

	যাবত্ (ssh_বার্তা_recv(ctxt->pam_psock, buffer) == 0) {
		যদি (++nmesg > PAM_MAX_অঙ্ক_বার্তা)
			fatal_f("too many query messages");
		যদি ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &বার্তা, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		বিকল্প (type) {
		পক্ষ PAM_PROMPT_ECHO_ON:
		পক্ষ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, পরিমাণ(বর্ণ *));
			*echo_on = xcalloc(1, পরিমাণ(u_int));
			(*prompts)[0] = বার্তা;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*অঙ্ক = 1;
			sshbuf_free(buffer);
			প্রত্যাগম (0);
		পক্ষ PAM_ERROR_বার্তা:
		পক্ষ PAM_TEXT_INFO:
			মুক্ত(*info);
			*info = বার্তা; /* transfer ownership */
			বার্তা = রিক্ত;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			প্রত্যাগম (0);
		পক্ষ PAM_ACCT_EXPIRED:
		পক্ষ PAM_MAXTRIES:
			যদি (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			যদি (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		পক্ষ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		পক্ষ PAM_SUCCESS:
			যদি (type == PAM_SUCCESS) {
				যদি (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_মূল_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				মুক্ত(বার্তা);
				sshbuf_free(buffer);
				প্রত্যাগম (0);
			}
			error("PAM: %s for %s%.100s from %.100s", বার্তা,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		স্বভাব:
			মুক্ত(বার্তা);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			প্রত্যাগম (-1);
		}
	}
	sshbuf_free(buffer);
	প্রত্যাগম (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
স্থির বর্ণ *
fake_password(ধ্রুব বর্ণ *wire_password)
{
	ধ্রুব বর্ণ junk[] = "\b\n\r\177INCORRECT";
	বর্ণ *ret = রিক্ত;
	size_t i, l = wire_password != রিক্ত ? strlen(wire_password) : 0;

	যদি (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	যদি (ret == রিক্ত)
		প্রত্যাগম রিক্ত;
	প্রতি (i = 0; i < l; i++)
		ret[i] = junk[i % (পরিমাণ(junk) - 1)];
	ret[i] = '\0';
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
sshpam_respond(শূন্য *ctx, u_int অঙ্ক, বর্ণ **resp)
{
	সংরচনা sshbuf *buffer;
	সংরচনা pam_ctxt *ctxt = ctx;
	বর্ণ *fake;
	পূর্ণাঙ্ক r;

	debug2_f("PAM: entering, %u responses", অঙ্ক);
	বিকল্প (ctxt->pam_done) {
	পক্ষ SshPamAuthenticated:
		sshpam_authenticated = 1;
		প্রত্যাগম (0);
	পক্ষ SshPamNone:
		ভঙ্গ;
	পক্ষ SshPamAgain:
		প্রত্যাগম 1;	/* KbdintResultAgain */
	স্বভাব:
		প্রত্যাগম (-1);
	}
	যদি (অঙ্ক != 1) {
		error("PAM: expected one response, got %u", অঙ্ক);
		প্রত্যাগম (-1);
	}
	যদি ((buffer = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_মূল_login == PERMIT_YES)) {
		যদি ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} অন্যথা {
		fake = fake_password(*resp);
		যদি ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		মুক্ত(fake);
	}
	যদি (ssh_বার্তা_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		প্রত্যাগম (-1);
	}
	sshbuf_free(buffer);
	প্রত্যাগম (1);
}

স্থির শূন্য
sshpam_free_ctx(শূন্য *ctxtp)
{
	সংরচনা pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	মুক্ত(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

পূর্ণাঙ্ক
sshpam_priv_kbdint_authdone(শূন্য *ctxtp)
{
	সংরচনা pam_ctxt *ctxt = ctxtp;

	প্রত্যাগম ctxt->pam_done == SshPamAuthenticated;
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
শূন্য
start_pam(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	যদি (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	যদি (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

শূন্য
finish_pam(শূন্য)
{
	sshpam_cleanup();
}


u_int
do_pam_account(শূন্য)
{
	debug_f("called");
	যদি (sshpam_account_status != -1)
		প্রত্যাগম (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	যদি (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		প্রত্যাগম (sshpam_account_status);
	}

	যদি (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	প্রত্যাগম (sshpam_account_status);
}

শূন্য
do_pam_setcred(শূন্য)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ধ্রুব শূন্য *)&store_conv);
	যদি (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	যদি (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		প্রত্যাগম;
	}
	যদি (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	অন্যথা
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

শূন্য
do_pam_session(সংরচনা ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ধ্রুব শূন্য *)&store_conv);
	যদি (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	যদি (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	অন্যথা {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

পূর্ণাঙ্ক
is_pam_session_open(শূন্য)
{
	প্রত্যাগম sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
পূর্ণাঙ্ক
do_pam_putenv(বর্ণ *name, বর্ণ *মান)
{
	পূর্ণাঙ্ক ret = 1;
	বর্ণ *compound;
	size_t len;

	len = strlen(name) + strlen(মান) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, মান);
	ret = pam_putenv(sshpam_handle, compound);
	মুক্ত(compound);

	প্রত্যাগম (ret);
}

বর্ণ **
fetch_pam_child_environment(শূন্য)
{
	প্রত্যাগম sshpam_env;
}

বর্ণ **
fetch_pam_environment(শূন্য)
{
	প্রত্যাগম (pam_getenvlist(sshpam_handle));
}

শূন্য
free_pam_environment(বর্ণ **env)
{
	বর্ণ **envp;

	যদি (env == রিক্ত)
		প্রত্যাগম;

	প্রতি (envp = env; *envp; envp++)
		মুক্ত(*envp);
	মুক্ত(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
স্থির পূর্ণাঙ্ক
sshpam_passwd_conv(পূর্ণাঙ্ক n, sshpam_const সংরচনা pam_message **বার্তা,
    সংরচনা pam_response **resp, শূন্য *data)
{
	সংরচনা pam_response *reply;
	পূর্ণাঙ্ক r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = রিক্ত;

	যদি (n <= 0 || n > PAM_MAX_অঙ্ক_বার্তা)
		প্রত্যাগম (PAM_CONV_ERR);

	যদি ((reply = calloc(n, পরিমাণ(*reply))) == রিক্ত)
		প্রত্যাগম (PAM_CONV_ERR);

	প্রতি (i = 0; i < n; ++i) {
		বিকল্প (PAM_বার্তা_MEMBER(বার্তা, i, বার্তা_style)) {
		পক্ষ PAM_PROMPT_ECHO_OFF:
			যদি (sshpam_password == রিক্ত)
				গচ্ছ fail;
			যদি ((reply[i].resp = strdup(sshpam_password)) == রিক্ত)
				গচ্ছ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ভঙ্গ;
		পক্ষ PAM_ERROR_বার্তা:
		পক্ষ PAM_TEXT_INFO:
			len = strlen(PAM_বার্তা_MEMBER(বার্তা, i, বার্তা));
			যদি (len > 0) {
				যদি ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_বার্তা_MEMBER(বার্তা, i, বার্তা))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			যদি ((reply[i].resp = strdup("")) == রিক্ত)
				গচ্ছ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ভঙ্গ;
		স্বভাব:
			গচ্ছ fail;
		}
	}
	*resp = reply;
	প্রত্যাগম (PAM_SUCCESS);

 fail:
	প্রতি(i = 0; i < n; i++) {
		মুক্ত(reply[i].resp);
	}
	মুক্ত(reply);
	প্রত্যাগম (PAM_CONV_ERR);
}

স্থির সংরচনা pam_conv passwd_conv = { sshpam_passwd_conv, রিক্ত };

/*
 * Attempt password authentication via PAM
 */
পূর্ণাঙ্ক
sshpam_auth_passwd(Authctxt *authctxt, ধ্রুব বর্ণ *password)
{
	পূর্ণাঙ্ক flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	বর্ণ *fake = রিক্ত;

	যদি (!options.use_pam || sshpam_handle == রিক্ত)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	যদি (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_মূল_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ধ্রুব শূন্য *)&passwd_conv);
	যদি (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = রিক্ত;
	মুক্ত(fake);
	যদি (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	যদি (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	যদি (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		প্রত্যাগম 1;
	} অন্যথা {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		প্রত্যাগম 0;
	}
}

পূর্ণাঙ্ক
sshpam_get_maxtries_reached(শূন্য)
{
	প্রত্যাগম sshpam_maxtries_reached;
}

শূন্য
sshpam_set_maxtries_reached(পূর্ণাঙ্ক reached)
{
	যদি (reached == 0 || sshpam_maxtries_reached)
		প্রত্যাগম;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
