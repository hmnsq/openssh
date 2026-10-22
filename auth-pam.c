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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే USE_PAM
#ఒకవేళ defined(HAVE_SECURITY_PAM_APPL_H)
#అన్తర్భావ <security/pam_appl.h>
#లేదావేళ defined (HAVE_PAM_PAM_APPL_H)
#అన్తర్భావ <pam/pam_appl.h>
#అయితే_ముగింపు

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#నిర్వచితమైతే PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#లేకపోతే
# define sshpam_const	స్థిరరాశి	/* LinuxPAM, OpenPAM, AIX */
#అయితే_ముగింపు

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#నిర్వచితమైతే PAM_SUN_CODEBASE
# define PAM_సందేశం_MEMBER(సందేశం, n, member) ((*(సందేశం))[(n)].member)
#లేకపోతే
# define PAM_సందేశం_MEMBER(సందేశం, n, member) ((సందేశం)[(n)]->member)
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-pam.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "auth-options.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "srclimit.h"

బాహ్య ServerOptions options;
బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య u_int utmp_len;

/* so we don't silently change behaviour */
#నిర్వచితమైతే USE_POSIX_దారాలు
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#అయితే_ముగింపు

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#నిర్వచితమైతే UNSUPPORTED_POSIX_దారాలు_HACK
#అన్తర్భావ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
రకనిర్వచనం pthread_t sp_pthread_t;
#లేకపోతే
రకనిర్వచనం pid_t sp_pthread_t;
#నిర్వచించు pthread_exit	fake_pthread_exit
#నిర్వచించు pthread_create	fake_pthread_create
#నిర్వచించు pthread_cancel	fake_pthread_cancel
#నిర్వచించు pthread_join	fake_pthread_join
#అయితే_ముగింపు

రకనిర్వచనం పూర్ణాంకం Ssh_Pam_పూర్తి;
#నిర్వచించు SshPamError -1
#నిర్వచించు SshPamNone 0
#నిర్వచించు SshPamAuthenticated 1
#నిర్వచించు SshPamAgain 2

నిర్మాణం pam_ctxt {
	sp_pthread_t	 pam_thread;
	పూర్ణాంకం		 pam_psock;
	పూర్ణాంకం		 pam_csock;
	Ssh_Pam_పూర్తి	 pam_పూర్తి;
};

స్థిర శూన్య sshpam_free_ctx(శూన్య *);
స్థిర నిర్మాణం pam_ctxt *cleanup_ctxt;

#నిర్వచితం_కాకపోతే UNSUPPORTED_POSIX_దారాలు_HACK
/*
 * Simulate threads with processes.
 */

స్థిర పూర్ణాంకం sshpam_thread_స్థితి = -1;
స్థిర sshsig_t sshpam_oldsig;

స్థిర శూన్య
sshpam_sigchld_handler(పూర్ణాంకం sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ (cleanup_ctxt == ఖాళీ)
		తిరిగి;	/* handler called after PAM cleanup, shouldn't happen */
	ఒకవేళ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_స్థితి, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		అయితే (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_స్థితి, 0) == -1) {
			ఒకవేళ (errno == EINTR)
				కొనసాగు;
			తిరిగి;
		}
	}
	ఒకవేళ (sshpam_thread_స్థితి == -1)
		తిరిగి;
	ఒకవేళ (WIFSIGNALED(sshpam_thread_స్థితి)) {
		ఒకవేళ (signal_is_crash(WTERMSIG(sshpam_thread_స్థితి)))
			_exit(EXIT_బిడ్డ_CRASH);
	} లేకపోతే ఒకవేళ (!WIFEXITED(sshpam_thread_స్థితి))
		_exit(EXIT_బిడ్డ_CRASH);
}

/* ARGSUSED */
స్థిర శూన్య
pthread_exit(శూన్య *విలువ)
{
	_exit(0);
}

/* ARGSUSED */
స్థిర పూర్ణాంకం
pthread_create(sp_pthread_t *thread, స్థిరరాశి శూన్య *attr,
    శూన్య *(*thread_ప్రారంభం)(శూన్య *), శూన్య *arg)
{
	pid_t pid;
	నిర్మాణం pam_ctxt *ctx = arg;

	sshpam_thread_స్థితి = -1;
	ఎంపిక ((pid = fork())) {
	స్థితి -1:
		error("fork(): %s", strerror(errno));
		తిరిగి errno;
	స్థితి 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_ప్రారంభం(arg);
		_exit(1);
	అప్రమేయ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		తిరిగి (0);
	}
}

స్థిర పూర్ణాంకం
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	తిరిగి (kill(thread, SIGTERM));
}

/* ARGSUSED */
స్థిర పూర్ణాంకం
pthread_join(sp_pthread_t thread, శూన్య **విలువ)
{
	పూర్ణాంకం స్థితి_2;

	ఒకవేళ (sshpam_thread_స్థితి != -1)
		తిరిగి (sshpam_thread_స్థితి);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	అయితే (waitpid(thread, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno == EINTR)
			కొనసాగు;
		fatal_f("waitpid: %s", strerror(errno));
	}
	తిరిగి (స్థితి_2);
}
#అయితే_ముగింపు


స్థిర pam_handle_t *sshpam_handle = ఖాళీ;
స్థిర అక్షరం *sshpam_initial_user;
స్థిర పూర్ణాంకం sshpam_err = 0;
స్థిర పూర్ణాంకం sshpam_authenticated = 0;
స్థిర పూర్ణాంకం sshpam_session_open = 0;
స్థిర పూర్ణాంకం sshpam_cred_established = 0;
స్థిర పూర్ణాంకం sshpam_account_స్థితి = -1;
స్థిర పూర్ణాంకం sshpam_maxtries_reached = 0;
స్థిర అక్షరం **sshpam_env = ఖాళీ;
స్థిర Authctxt *sshpam_authctxt = ఖాళీ;
స్థిర స్థిరరాశి అక్షరం *sshpam_password = ఖాళీ;
స్థిర అక్షరం *sshpam_rhost = ఖాళీ;
స్థిర అక్షరం *sshpam_laddr = ఖాళీ;

/* Some PAM implementations don't implement this */
#నిర్వచితం_కాకపోతే HAVE_PAM_GETENVLIST
స్థిర అక్షరం **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 తిరిగి ఖాళీ;
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_PAM_PUTENV
స్థిర పూర్ణాంకం
pam_putenv(pam_handle_t *pamh, స్థిరరాశి అక్షరం *name_విలువ)
{
	తిరిగి PAM_SUCCESS;
}
#అయితే_ముగింపు /* HAVE_PAM_PUTENV */

స్థిర శూన్య
sshpam_password_change_required(పూర్ణాంకం reqd)
{
	బాహ్య నిర్మాణం sshauthopt *auth_opts;
	స్థిర పూర్ణాంకం saved_పోర్టు, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ఒకవేళ (sshpam_authctxt == ఖాళీ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ఒకవేళ (reqd) {
		saved_పోర్టు = auth_opts->permit_పోర్టు_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_పోర్టు_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} లేకపోతే {
		ఒకవేళ (saved_పోర్టు)
			auth_opts->permit_పోర్టు_forwarding_flag = saved_పోర్టు;
		ఒకవేళ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ఒకవేళ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
స్థిర శూన్య
import_environments(నిర్మాణం sshbuf *b)
{
	అక్షరం *env;
	u_int n, i, అంకె_env;
	పూర్ణాంకం r;

	debug3_f("entering");

#నిర్వచితం_కాకపోతే UNSUPPORTED_POSIX_దారాలు_HACK
	/* Import variables set by do_pam_account */
	ఒకవేళ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (n > గరిష్ఠ_పూర్ణాంకం)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_స్థితి = (పూర్ణాంకం)n;
	ఒకవేళ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ఒకవేళ ((r = sshbuf_get_u32(b, &అంకె_env)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (అంకె_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    అంకె_env);
	}
	sshpam_env = xcalloc(అంకె_env + 1, పరిమాణం(*sshpam_env));
	debug3("PAM: num env strings %u", అంకె_env);
	కొరకు(i = 0; i < అంకె_env; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ఖాళీ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[అంకె_env] = ఖాళీ;

	/* Import PAM environment from subprocess */
	ఒకవేళ ((r = sshbuf_get_u32(b, &అంకె_env)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (అంకె_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    అంకె_env);
	}
	debug("PAM: num PAM env strings %u", అంకె_env);
	కొరకు (i = 0; i < అంకె_env; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(b, &env, ఖాళీ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ఒకవేళ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
			error("PAM: pam_putenv: %s",
			    pam_strerror(sshpam_handle, r));
		}
		/*
		 * XXX this possibly leaks env because it is not documented
		 * what pam_putenv() does with it. Does it copy it? Does it
		 * take ownership? We don't know, so it's safest just to leak.
		 */
	}
#అయితే_ముగింపు
}

/*
 * Conversation function for authentication thread.
 */
స్థిర పూర్ణాంకం
sshpam_thread_conv(పూర్ణాంకం n, sshpam_const నిర్మాణం pam_సందేశం **సందేశం,
    నిర్మాణం pam_response **resp, శూన్య *దత్తాంశం)
{
	నిర్మాణం sshbuf *బఫరు;
	నిర్మాణం pam_ctxt *ctxt;
	నిర్మాణం pam_response *జవాబు;
	పూర్ణాంకం r, i;
	u_char స్థితి_2;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ఖాళీ;

	ఒకవేళ (దత్తాంశం == ఖాళీ) {
		error("PAM: conversation function passed a null context");
		తిరిగి (PAM_CONV_ERR);
	}
	ctxt = దత్తాంశం;
	ఒకవేళ (n <= 0 || n > PAM_MAX_అంకె_సందేశం)
		తిరిగి (PAM_CONV_ERR);

	ఒకవేళ ((జవాబు = సున్నా_జ్ఞాపకం_ఇవ్వు(n, పరిమాణం(*జవాబు))) == ఖాళీ)
		తిరిగి PAM_CONV_ERR;
	ఒకవేళ ((బఫరు = sshbuf_new()) == ఖాళీ) {
		విడుదల(జవాబు);
		తిరిగి PAM_CONV_ERR;
	}

	కొరకు (i = 0; i < n; ++i) {
		ఎంపిక (PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style)) {
		స్థితి PAM_PROMPT_ECHO_OFF:
		స్థితి PAM_PROMPT_ECHO_ON:
			ఒకవేళ ((r = sshbuf_put_cstring(బఫరు,
			    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ఒకవేళ (ssh_సందేశం_send(ctxt->pam_csock,
			    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style), బఫరు) == -1)
				వెళ్ళు fail;

			ఒకవేళ (ssh_సందేశం_recv(ctxt->pam_csock, బఫరు) == -1)
				వెళ్ళు fail;
			ఒకవేళ ((r = sshbuf_get_u8(బఫరు, &స్థితి_2)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ఒకవేళ (స్థితి_2 != PAM_AUTHTOK)
				వెళ్ళు fail;
			ఒకవేళ ((r = sshbuf_get_cstring(బఫరు,
			    &జవాబు[i].resp, ఖాళీ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ఆపు;
		స్థితి PAM_ERROR_సందేశం:
		స్థితి PAM_పాఠ్యం_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style),
			       PAM_సందేశం_MEMBER(సందేశం, i, సందేశం));
			ఒకవేళ ((r = sshbuf_put_cstring(బఫరు,
			    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ఒకవేళ (ssh_సందేశం_send(ctxt->pam_csock,
			    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style), బఫరు) == -1)
				వెళ్ళు fail;
			ఆపు;
		అప్రమేయ:
			వెళ్ళు fail;
		}
		sshbuf_reset(బఫరు);
	}
	sshbuf_free(బఫరు);
	*resp = జవాబు;
	తిరిగి (PAM_SUCCESS);

 fail:
	కొరకు(i = 0; i < n; i++) {
		విడుదల(జవాబు[i].resp);
	}
	విడుదల(జవాబు);
	sshbuf_free(బఫరు);
	తిరిగి (PAM_CONV_ERR);
}

స్థిర పూర్ణాంకం
check_pam_user(Authctxt *authctxt)
{
	స్థిరరాశి అక్షరం *pam_user;

	ఒకవేళ (authctxt == ఖాళీ || authctxt->pw == ఖాళీ ||
	    authctxt->pw->pw_name == ఖాళీ)
		fatal_f("PAM authctxt user not initialized");

	ఒకవేళ ((sshpam_err = pam_get_అంశం(sshpam_handle, PAM_USER,
	    (sshpam_const శూన్య **) &pam_user)) != PAM_SUCCESS)
		తిరిగి sshpam_err;

	ఒకవేళ (pam_user == ఖాళీ) {
		debug("PAM error: PAM_USER is NULL");
		తిరిగి PAM_USER_UNKNOWN;
	}

	ఒకవేళ (sshpam_initial_user == ఖాళీ)
		fatal_f("internal error: sshpam_initial_user NULL");
	ఒకవేళ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		తిరిగి PAM_USER_UNKNOWN;
	}
	తిరిగి PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
స్థిర శూన్య *
sshpam_thread(శూన్య *ctxtp)
{
	నిర్మాణం pam_ctxt *ctxt = ctxtp;
	నిర్మాణం sshbuf *బఫరు = ఖాళీ;
	నిర్మాణం pam_conv sshpam_conv;
	పూర్ణాంకం r, flags = (options.permit_ఖాళీలు_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#నిర్వచితం_కాకపోతే UNSUPPORTED_POSIX_దారాలు_HACK
	బాహ్య అక్షరం **environ;
	అక్షరం **env_from_pam;
	u_int i;
	స్థిరరాశి అక్షరం *pam_user;
	స్థిరరాశి అక్షరం **ptr_pam_user = &pam_user;
	అక్షరం *tz = getenv("TZ");

	sshpam_err = pam_get_అంశం(sshpam_handle, PAM_USER,
	    (sshpam_const శూన్య **)ptr_pam_user);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		వెళ్ళు auth_fail;

	environ[0] = ఖాళీ;
	ఒకవేళ (tz != ఖాళీ)
		ఒకవేళ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ఒకవేళ (sshpam_authctxt != ఖాళీ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#అయితే_ముగింపు

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ఒకవేళ (sshpam_authctxt == ఖాళీ)
		fatal_f("PAM authctxt not initialized");

	ఒకవేళ ((బఫరు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_CONV,
	    (స్థిరరాశి శూన్య *)&sshpam_conv);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		వెళ్ళు auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ఒకవేళ (sshpam_err == PAM_MAXTRIES)
		sshpam_సమితి_maxtries_reached(1);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		వెళ్ళు auth_fail;
	ఒకవేళ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		వెళ్ళు auth_fail;

	ఒకవేళ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		వెళ్ళు auth_fail;
	}
	ఒకవేళ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ఒకవేళ (sshpam_err != PAM_SUCCESS)
			వెళ్ళు auth_fail;
		sshpam_password_change_required(0);
	}

	ఒకవేళ ((r = sshbuf_put_cstring(బఫరు, "OK")) != 0)
		fatal_fr(r, "buffer error");

#నిర్వచితం_కాకపోతే UNSUPPORTED_POSIX_దారాలు_HACK
	/* Export variables set by do_pam_account */
	ఒకవేళ ((r = sshbuf_put_u32(బఫరు, sshpam_account_స్థితి)) != 0 ||
	    (r = sshbuf_put_u32(బఫరు, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	కొరకు (i = 0; environ[i] != ఖాళీ; i++) {
		/*లెక్క*/
		ఒకవేళ (i > గరిష్ఠ_పూర్ణాంకం)
			fatal_f("too many environment strings");
	}
	ఒకవేళ ((r = sshbuf_put_u32(బఫరు, i)) != 0)
		fatal_fr(r, "buffer error");
	కొరకు (i = 0; environ[i] != ఖాళీ; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(బఫరు, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	కొరకు (i = 0; env_from_pam != ఖాళీ && env_from_pam[i] != ఖాళీ; i++) {
		/*లెక్క*/
		ఒకవేళ (i > గరిష్ఠ_పూర్ణాంకం)
			fatal_f("too many PAM environment strings");
	}
	ఒకవేళ ((r = sshbuf_put_u32(బఫరు, i)) != 0)
		fatal_fr(r, "buffer error");
	కొరకు (i = 0; env_from_pam != ఖాళీ && env_from_pam[i] != ఖాళీ; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(బఫరు, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#అయితే_ముగింపు /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_సందేశం_send(ctxt->pam_csock, sshpam_err, బఫరు);
	sshbuf_free(బఫరు);
	pthread_exit(ఖాళీ);

 auth_fail:
	ఒకవేళ ((r = sshbuf_put_cstring(బఫరు,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ఒకవేళ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_సందేశం_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, బఫరు);
	లేకపోతే ఒకవేళ (sshpam_maxtries_reached)
		ssh_సందేశం_send(ctxt->pam_csock, PAM_MAXTRIES, బఫరు);
	లేకపోతే
		ssh_సందేశం_send(ctxt->pam_csock, PAM_AUTH_ERR, బఫరు);
	sshbuf_free(బఫరు);
	pthread_exit(ఖాళీ);

	తిరిగి (ఖాళీ); /* Avoid warning for non-pthread case */
}

శూన్య
sshpam_thread_cleanup(శూన్య)
{
	నిర్మాణం pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ఒకవేళ (ctxt != ఖాళీ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ఖాళీ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, పరిమాణం(*ctxt));
		cleanup_ctxt = ఖాళీ;
	}
}

స్థిర పూర్ణాంకం
sshpam_null_conv(పూర్ణాంకం n, sshpam_const నిర్మాణం pam_సందేశం **సందేశం,
    నిర్మాణం pam_response **resp, శూన్య *దత్తాంశం)
{
	debug3_f("PAM: entering, %d messages", n);
	తిరిగి (PAM_CONV_ERR);
}

స్థిర నిర్మాణం pam_conv null_conv = { sshpam_null_conv, ఖాళీ };

స్థిర పూర్ణాంకం
sshpam_store_conv(పూర్ణాంకం n, sshpam_const నిర్మాణం pam_సందేశం **సందేశం,
    నిర్మాణం pam_response **resp, శూన్య *దత్తాంశం)
{
	నిర్మాణం pam_response *జవాబు;
	పూర్ణాంకం r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ఖాళీ;

	ఒకవేళ (n <= 0 || n > PAM_MAX_అంకె_సందేశం)
		తిరిగి (PAM_CONV_ERR);

	ఒకవేళ ((జవాబు = సున్నా_జ్ఞాపకం_ఇవ్వు(n, పరిమాణం(*జవాబు))) == ఖాళీ)
		తిరిగి (PAM_CONV_ERR);

	కొరకు (i = 0; i < n; ++i) {
		ఎంపిక (PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style)) {
		స్థితి PAM_ERROR_సందేశం:
		స్థితి PAM_పాఠ్యం_INFO:
			ఒకవేళ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			జవాబు[i].resp_retcode = PAM_SUCCESS;
			ఆపు;
		అప్రమేయ:
			వెళ్ళు fail;
		}
	}
	*resp = జవాబు;
	తిరిగి (PAM_SUCCESS);

 fail:
	కొరకు(i = 0; i < n; i++) {
		విడుదల(జవాబు[i].resp);
	}
	విడుదల(జవాబు);
	తిరిగి (PAM_CONV_ERR);
}

స్థిర నిర్మాణం pam_conv store_conv = { sshpam_store_conv, ఖాళీ };

శూన్య
sshpam_cleanup(శూన్య)
{
	ఒకవేళ (sshpam_handle == ఖాళీ || !mm_is_monitor())
		తిరిగి;
	debug("PAM: cleanup");
	pam_సమితి_అంశం(sshpam_handle, PAM_CONV, (స్థిరరాశి శూన్య *)&null_conv);
	ఒకవేళ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ఒకవేళ (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_చివర(sshpam_handle, sshpam_err);
	sshpam_handle = ఖాళీ;
	విడుదల(sshpam_initial_user);
	sshpam_initial_user = ఖాళీ;
}

స్థిర పూర్ణాంకం
sshpam_init(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	స్థిరరాశి అక్షరం *user = authctxt->user;
	పూర్ణాంకం r;

	ఒకవేళ (options.pam_service_name == ఖాళీ)
		fatal_f("internal error: NULL PAM service name");
#ఒకవేళ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_కొలత)
	/* Protect buggy PAM implementations from excessively long usernames */
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(user) >= PAM_MAX_RESP_కొలత)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
#అయితే_ముగింపు
	ఒకవేళ (sshpam_handle == ఖాళీ && ssh == ఖాళీ)
		fatal("%s: called initially with no packet context", __func__);
	ఒకవేళ (sshpam_handle != ఖాళీ) {
		/* We already have a PAM context; check if the user matches */
		ఒకవేళ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		తిరిగి 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_ప్రారంభం(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ఒకవేళ (sshpam_err != PAM_SUCCESS) {
		pam_చివర(sshpam_handle, sshpam_err);
		sshpam_handle = ఖాళీ;
		తిరిగి (-1);
	}

	ఒకవేళ (ssh != ఖాళీ && sshpam_rhost == ఖాళీ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_లోపల(ssh));
	}
	ఒకవేళ (sshpam_rhost != ఖాళీ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ఒకవేళ (sshpam_err != PAM_SUCCESS) {
			pam_చివర(sshpam_handle, sshpam_err);
			sshpam_handle = ఖాళీ;
			తిరిగి (-1);
		}
	}
	ఒకవేళ (ssh != ఖాళీ && sshpam_laddr != ఖాళీ) {
		అక్షరం *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
		    sshpam_laddr, ssh_local_పోర్టు(ssh));
		ఒకవేళ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		విడుదల(conninfo);
	}

#నిర్వచితమైతే PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_TTY, "ssh");
	ఒకవేళ (sshpam_err != PAM_SUCCESS) {
		pam_చివర(sshpam_handle, sshpam_err);
		sshpam_handle = ఖాళీ;
		తిరిగి (-1);
	}
#అయితే_ముగింపు
	తిరిగి (0);
}

స్థిర శూన్య
expose_authinfo(స్థిరరాశి అక్షరం *caller)
{
	అక్షరం *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ఒకవేళ (sshpam_authctxt->session_info == ఖాళీ)
		auth_info = xstrdup("");
	లేకపోతే ఒకవేళ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	విడుదల(auth_info);
}

స్థిర శూన్య *
sshpam_init_ctx(Authctxt *authctxt)
{
	నిర్మాణం pam_ctxt *ctxt;
	పూర్ణాంకం ఫలితం, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ఒకవేళ (!options.use_pam || sshpam_account_స్థితి == 0)
		తిరిగి ఖాళీ;

	/* Initialize PAM */
	ఒకవేళ (sshpam_init(ఖాళీ, authctxt) == -1) {
		error("PAM: initialization failed");
		తిరిగి (ఖాళీ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, పరిమాణం *ctxt);

	/* Start the authentication thread */
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		విడుదల(ctxt);
		తిరిగి (ఖాళీ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	ఫలితం = pthread_create(&ctxt->pam_thread, ఖాళీ, sshpam_thread, ctxt);
	ఒకవేళ (ఫలితం != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(ఫలితం));
		close(socks[0]);
		close(socks[1]);
		విడుదల(ctxt);
		తిరిగి (ఖాళీ);
	}
	cleanup_ctxt = ctxt;
	తిరిగి (ctxt);
}

స్థిర పూర్ణాంకం
sshpam_query(శూన్య *ctx, అక్షరం **name, అక్షరం **info,
    u_int *అంకె, అక్షరం ***prompts, u_int **echo_on)
{
	నిర్మాణం sshbuf *బఫరు;
	నిర్మాణం pam_ctxt *ctxt = ctx;
	u_char type;
	అక్షరం *సందేశం;
	కొలత_t mlen, nmesg = 0;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ ((బఫరు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ఖాళీ;
	*అంకె = 0;
	ctxt->pam_పూర్తి = SshPamNone;

	అయితే (ssh_సందేశం_recv(ctxt->pam_psock, బఫరు) == 0) {
		ఒకవేళ (++nmesg > PAM_MAX_అంకె_సందేశం)
			fatal_f("too many query messages");
		ఒకవేళ ((r = sshbuf_get_u8(బఫరు, &type)) != 0 ||
		    (r = sshbuf_get_cstring(బఫరు, &సందేశం, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		ఎంపిక (type) {
		స్థితి PAM_PROMPT_ECHO_ON:
		స్థితి PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, పరిమాణం(అక్షరం *));
			*echo_on = xcalloc(1, పరిమాణం(u_int));
			(*prompts)[0] = సందేశం;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*అంకె = 1;
			sshbuf_free(బఫరు);
			తిరిగి (0);
		స్థితి PAM_ERROR_సందేశం:
		స్థితి PAM_పాఠ్యం_INFO:
			విడుదల(*info);
			*info = సందేశం; /* transfer ownership */
			సందేశం = ఖాళీ;
			ctxt->pam_పూర్తి = SshPamAgain;
			sshbuf_free(బఫరు);
			తిరిగి (0);
		స్థితి PAM_ACCT_EXPIRED:
		స్థితి PAM_MAXTRIES:
			ఒకవేళ (type == PAM_ACCT_EXPIRED)
				sshpam_account_స్థితి = 0;
			ఒకవేళ (type == PAM_MAXTRIES)
				sshpam_సమితి_maxtries_reached(1);
			/* FALLTHROUGH */
		స్థితి PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		స్థితి PAM_SUCCESS:
			ఒకవేళ (type == PAM_SUCCESS) {
				ఒకవేళ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_మూలం_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(బఫరు);
				ctxt->pam_పూర్తి = SshPamAuthenticated;
				విడుదల(సందేశం);
				sshbuf_free(బఫరు);
				తిరిగి (0);
			}
			error("PAM: %s for %s%.100s from %.100s", సందేశం,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		అప్రమేయ:
			విడుదల(సందేశం);
			ctxt->pam_పూర్తి = SshPamError;
			sshbuf_free(బఫరు);
			తిరిగి (-1);
		}
	}
	sshbuf_free(బఫరు);
	తిరిగి (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
స్థిర అక్షరం *
fake_password(స్థిరరాశి అక్షరం *wire_password)
{
	స్థిరరాశి అక్షరం junk[] = "\b\n\r\177INCORRECT";
	అక్షరం *ret = ఖాళీ;
	కొలత_t i, l = wire_password != ఖాళీ ? అక్షరశ్రేణి_పొడవు(wire_password) : 0;

	ఒకవేళ (l >= గరిష్ఠ_పూర్ణాంకం)
		fatal_f("password length too long: %zu", l);

	ret = జ్ఞాపకం_ఇవ్వు(l + 1);
	ఒకవేళ (ret == ఖాళీ)
		తిరిగి ఖాళీ;
	కొరకు (i = 0; i < l; i++)
		ret[i] = junk[i % (పరిమాణం(junk) - 1)];
	ret[i] = '\0';
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
sshpam_respond(శూన్య *ctx, u_int అంకె, అక్షరం **resp)
{
	నిర్మాణం sshbuf *బఫరు;
	నిర్మాణం pam_ctxt *ctxt = ctx;
	అక్షరం *fake;
	పూర్ణాంకం r;

	debug2_f("PAM: entering, %u responses", అంకె);
	ఎంపిక (ctxt->pam_పూర్తి) {
	స్థితి SshPamAuthenticated:
		sshpam_authenticated = 1;
		తిరిగి (0);
	స్థితి SshPamNone:
		ఆపు;
	స్థితి SshPamAgain:
		తిరిగి 1;	/* KbdintResultAgain */
	అప్రమేయ:
		తిరిగి (-1);
	}
	ఒకవేళ (అంకె != 1) {
		error("PAM: expected one response, got %u", అంకె);
		తిరిగి (-1);
	}
	ఒకవేళ ((బఫరు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_మూలం_login == PERMIT_YES)) {
		ఒకవేళ ((r = sshbuf_put_cstring(బఫరు, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} లేకపోతే {
		fake = fake_password(*resp);
		ఒకవేళ ((r = sshbuf_put_cstring(బఫరు, fake)) != 0)
			fatal_fr(r, "buffer error");
		విడుదల(fake);
	}
	ఒకవేళ (ssh_సందేశం_send(ctxt->pam_psock, PAM_AUTHTOK, బఫరు) == -1) {
		sshbuf_free(బఫరు);
		తిరిగి (-1);
	}
	sshbuf_free(బఫరు);
	తిరిగి (1);
}

స్థిర శూన్య
sshpam_free_ctx(శూన్య *ctxtp)
{
	నిర్మాణం pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	విడుదల(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

పూర్ణాంకం
sshpam_priv_kbdint_authdone(శూన్య *ctxtp)
{
	నిర్మాణం pam_ctxt *ctxt = ctxtp;

	తిరిగి ctxt->pam_పూర్తి == SshPamAuthenticated;
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
శూన్య
ప్రారంభం_pam(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ఒకవేళ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ఒకవేళ (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

శూన్య
ముగింపు_pam(శూన్య)
{
	sshpam_cleanup();
}


u_int
do_pam_account(శూన్య)
{
	debug_f("called");
	ఒకవేళ (sshpam_account_స్థితి != -1)
		తిరిగి (sshpam_account_స్థితి);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ఒకవేళ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_స్థితి = 0;
		తిరిగి (sshpam_account_స్థితి);
	}

	ఒకవేళ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_స్థితి = 1;
	తిరిగి (sshpam_account_స్థితి);
}

శూన్య
do_pam_setcred(శూన్య)
{
	sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_CONV,
	    (స్థిరరాశి శూన్య *)&store_conv);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ఒకవేళ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		తిరిగి;
	}
	ఒకవేళ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	లేకపోతే
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

శూన్య
do_pam_session(నిర్మాణం ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_CONV,
	    (స్థిరరాశి శూన్య *)&store_conv);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ఒకవేళ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	లేకపోతే {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

పూర్ణాంకం
is_pam_session_open(శూన్య)
{
	తిరిగి sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
పూర్ణాంకం
do_pam_putenv(అక్షరం *name, అక్షరం *విలువ)
{
	పూర్ణాంకం ret = 1;
	అక్షరం *compound;
	కొలత_t len;

	len = అక్షరశ్రేణి_పొడవు(name) + అక్షరశ్రేణి_పొడవు(విలువ) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, విలువ);
	ret = pam_putenv(sshpam_handle, compound);
	విడుదల(compound);

	తిరిగి (ret);
}

అక్షరం **
fetch_pam_బిడ్డ_environment(శూన్య)
{
	తిరిగి sshpam_env;
}

అక్షరం **
fetch_pam_environment(శూన్య)
{
	తిరిగి (pam_getenvlist(sshpam_handle));
}

శూన్య
free_pam_environment(అక్షరం **env)
{
	అక్షరం **envp;

	ఒకవేళ (env == ఖాళీ)
		తిరిగి;

	కొరకు (envp = env; *envp; envp++)
		విడుదల(*envp);
	విడుదల(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
స్థిర పూర్ణాంకం
sshpam_passwd_conv(పూర్ణాంకం n, sshpam_const నిర్మాణం pam_సందేశం **సందేశం,
    నిర్మాణం pam_response **resp, శూన్య *దత్తాంశం)
{
	నిర్మాణం pam_response *జవాబు;
	పూర్ణాంకం r, i;
	కొలత_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ఖాళీ;

	ఒకవేళ (n <= 0 || n > PAM_MAX_అంకె_సందేశం)
		తిరిగి (PAM_CONV_ERR);

	ఒకవేళ ((జవాబు = సున్నా_జ్ఞాపకం_ఇవ్వు(n, పరిమాణం(*జవాబు))) == ఖాళీ)
		తిరిగి (PAM_CONV_ERR);

	కొరకు (i = 0; i < n; ++i) {
		ఎంపిక (PAM_సందేశం_MEMBER(సందేశం, i, సందేశం_style)) {
		స్థితి PAM_PROMPT_ECHO_OFF:
			ఒకవేళ (sshpam_password == ఖాళీ)
				వెళ్ళు fail;
			ఒకవేళ ((జవాబు[i].resp = strdup(sshpam_password)) == ఖాళీ)
				వెళ్ళు fail;
			జవాబు[i].resp_retcode = PAM_SUCCESS;
			ఆపు;
		స్థితి PAM_ERROR_సందేశం:
		స్థితి PAM_పాఠ్యం_INFO:
			len = అక్షరశ్రేణి_పొడవు(PAM_సందేశం_MEMBER(సందేశం, i, సందేశం));
			ఒకవేళ (len > 0) {
				ఒకవేళ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_సందేశం_MEMBER(సందేశం, i, సందేశం))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ఒకవేళ ((జవాబు[i].resp = strdup("")) == ఖాళీ)
				వెళ్ళు fail;
			జవాబు[i].resp_retcode = PAM_SUCCESS;
			ఆపు;
		అప్రమేయ:
			వెళ్ళు fail;
		}
	}
	*resp = జవాబు;
	తిరిగి (PAM_SUCCESS);

 fail:
	కొరకు(i = 0; i < n; i++) {
		విడుదల(జవాబు[i].resp);
	}
	విడుదల(జవాబు);
	తిరిగి (PAM_CONV_ERR);
}

స్థిర నిర్మాణం pam_conv passwd_conv = { sshpam_passwd_conv, ఖాళీ };

/*
 * Attempt password authentication via PAM
 */
పూర్ణాంకం
sshpam_auth_passwd(Authctxt *authctxt, స్థిరరాశి అక్షరం *password)
{
	పూర్ణాంకం flags = (options.permit_ఖాళీలు_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	అక్షరం *fake = ఖాళీ;

	ఒకవేళ (!options.use_pam || sshpam_handle == ఖాళీ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ఒకవేళ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_మూలం_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_సమితి_అంశం(sshpam_handle, PAM_CONV,
	    (స్థిరరాశి శూన్య *)&passwd_conv);
	ఒకవేళ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ఖాళీ;
	విడుదల(fake);
	ఒకవేళ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ఒకవేళ (sshpam_err == PAM_MAXTRIES)
		sshpam_సమితి_maxtries_reached(1);
	ఒకవేళ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		తిరిగి 1;
	} లేకపోతే {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		తిరిగి 0;
	}
}

పూర్ణాంకం
sshpam_get_maxtries_reached(శూన్య)
{
	తిరిగి sshpam_maxtries_reached;
}

శూన్య
sshpam_సమితి_maxtries_reached(పూర్ణాంకం reached)
{
	ఒకవేళ (reached == 0 || sshpam_maxtries_reached)
		తిరిగి;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#అయితే_ముగింపు /* USE_PAM */
