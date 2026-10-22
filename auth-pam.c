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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef USE_PAM
#ଯଦି defined(HAVE_SECURITY_PAM_APPL_H)
#ଅନ୍ତର୍ଭାଵ <security/pam_appl.h>
#ନଚେତଯଦି defined (HAVE_PAM_PAM_APPL_H)
#ଅନ୍ତର୍ଭାଵ <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ଅନ୍ୟଥା
# define sshpam_const	ଅଚଳ	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, n, member) ((*(ସନ୍ଦେଶ))[(n)].member)
#ଅନ୍ୟଥା
# define PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, n, member) ((ସନ୍ଦେଶ)[(n)]->member)
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-pam.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"

ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ u_int utmp_len;

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
#ଅନ୍ତର୍ଭାଵ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
ପ୍ରକାରବ୍ୟାଖ୍ୟା pthread_t sp_pthread_t;
#ଅନ୍ୟଥା
ପ୍ରକାରବ୍ୟାଖ୍ୟା pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

ସଂରଚନା pam_ctxt {
	sp_pthread_t	 pam_thread;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 pam_psock;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 pam_csock;
	SshPamDone	 pam_done;
};

ସ୍ଥିର ଶୂନ୍ୟ sshpam_free_ctx(ଶୂନ୍ୟ *);
ସ୍ଥିର ସଂରଚନା pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_thread_status = -1;
ସ୍ଥିର sshsig_t sshpam_oldsig;

ସ୍ଥିର ଶୂନ୍ୟ
sshpam_sigchld_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି (cleanup_ctxt == ଖାଲି)
		ଫେରନ୍ତୁ;	/* handler called after PAM cleanup, shouldn't happen */
	ଯଦି (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ଯେତେବେଳେ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			ଯଦି (errno == EINTR)
				ଜାରି;
			ଫେରନ୍ତୁ;
		}
	}
	ଯଦି (sshpam_thread_status == -1)
		ଫେରନ୍ତୁ;
	ଯଦି (WIFSIGNALED(sshpam_thread_status)) {
		ଯଦି (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} ଅନ୍ୟଥା ଯଦି (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
ସ୍ଥିର ଶୂନ୍ୟ
pthread_exit(ଶୂନ୍ୟ *ମୂଲ୍ୟ)
{
	_exit(0);
}

/* ARGSUSED */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pthread_create(sp_pthread_t *thread, ଅଚଳ ଶୂନ୍ୟ *attr,
    ଶୂନ୍ୟ *(*thread_start)(ଶୂନ୍ୟ *), ଶୂନ୍ୟ *arg)
{
	pid_t pid;
	ସଂରଚନା pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	ବାଛ ((pid = fork())) {
	ସ୍ଥିତି -1:
		error("fork(): %s", strerror(errno));
		ଫେରନ୍ତୁ errno;
	ସ୍ଥିତି 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		ଫେରନ୍ତୁ (0);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ଫେରନ୍ତୁ (kill(thread, SIGTERM));
}

/* ARGSUSED */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pthread_join(sp_pthread_t thread, ଶୂନ୍ୟ **ମୂଲ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯଦି (sshpam_thread_status != -1)
		ଫେରନ୍ତୁ (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ଯେତେବେଳେ (waitpid(thread, &status, 0) == -1) {
		ଯଦି (errno == EINTR)
			ଜାରି;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ଫେରନ୍ତୁ (status);
}
#endif


ସ୍ଥିର pam_handle_t *sshpam_handle = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *sshpam_initial_user;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_err = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_authenticated = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_session_open = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_cred_established = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_account_status = -1;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_maxtries_reached = 0;
ସ୍ଥିର ଅକ୍ଷର **sshpam_env = ଖାଲି;
ସ୍ଥିର Authctxt *sshpam_authctxt = ଖାଲି;
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *sshpam_password = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *sshpam_rhost = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *sshpam_laddr = ଖାଲି;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
ସ୍ଥିର ଅକ୍ଷର **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 ଫେରନ୍ତୁ ଖାଲି;
}
#endif

#ifndef HAVE_PAM_PUTENV
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pam_putenv(pam_handle_t *pamh, ଅଚଳ ଅକ୍ଷର *name_ମୂଲ୍ୟ)
{
	ଫେରନ୍ତୁ PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

ସ୍ଥିର ଶୂନ୍ୟ
sshpam_password_change_required(ପୂର୍ଣ୍ଣସଂଖ୍ୟା reqd)
{
	ବାହ୍ୟ ସଂରଚନା sshauthopt *auth_opts;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ଯଦି (sshpam_authctxt == ଖାଲି)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ଯଦି (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ଅନ୍ୟଥା {
		ଯଦି (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		ଯଦି (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ଯଦି (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ସ୍ଥିର ଶୂନ୍ୟ
import_environments(ସଂରଚନା sshbuf *b)
{
	ଅକ୍ଷର *env;
	u_int n, i, ଅଙ୍କ_env;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	ଯଦି ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)n;
	ଯଦି ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ଯଦି ((r = sshbuf_get_u32(b, &ଅଙ୍କ_env)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (ଅଙ୍କ_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    ଅଙ୍କ_env);
	}
	sshpam_env = xcalloc(ଅଙ୍କ_env + 1, ଆକାର(*sshpam_env));
	debug3("PAM: num env strings %u", ଅଙ୍କ_env);
	ପାଇଁ(i = 0; i < ଅଙ୍କ_env; i++) {
		ଯଦି ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ଖାଲି)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[ଅଙ୍କ_env] = ଖାଲି;

	/* Import PAM environment from subprocess */
	ଯଦି ((r = sshbuf_get_u32(b, &ଅଙ୍କ_env)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (ଅଙ୍କ_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    ଅଙ୍କ_env);
	}
	debug("PAM: num PAM env strings %u", ଅଙ୍କ_env);
	ପାଇଁ (i = 0; i < ଅଙ୍କ_env; i++) {
		ଯଦି ((r = sshbuf_get_cstring(b, &env, ଖାଲି)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ଯଦି ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_thread_conv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, sshpam_const ସଂରଚନା pam_message **ସନ୍ଦେଶ,
    ସଂରଚନା pam_response **resp, ଶୂନ୍ୟ *data)
{
	ସଂରଚନା sshbuf *buffer;
	ସଂରଚନା pam_ctxt *ctxt;
	ସଂରଚନା pam_response *reply;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ଖାଲି;

	ଯଦି (data == ଖାଲି) {
		error("PAM: conversation function passed a null context");
		ଫେରନ୍ତୁ (PAM_CONV_ERR);
	}
	ctxt = data;
	ଯଦି (n <= 0 || n > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ)
		ଫେରନ୍ତୁ (PAM_CONV_ERR);

	ଯଦି ((reply = calloc(n, ଆକାର(*reply))) == ଖାଲି)
		ଫେରନ୍ତୁ PAM_CONV_ERR;
	ଯଦି ((buffer = sshbuf_new()) == ଖାଲି) {
		ମୁକ୍ତ(reply);
		ଫେରନ୍ତୁ PAM_CONV_ERR;
	}

	ପାଇଁ (i = 0; i < n; ++i) {
		ବାଛ (PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style)) {
		ସ୍ଥିତି PAM_PROMPT_ECHO_OFF:
		ସ୍ଥିତି PAM_PROMPT_ECHO_ON:
			ଯଦି ((r = sshbuf_put_cstring(buffer,
			    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ଯଦି (ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock,
			    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style), buffer) == -1)
				ଯାଅ fail;

			ଯଦି (ssh_ସନ୍ଦେଶ_recv(ctxt->pam_csock, buffer) == -1)
				ଯାଅ fail;
			ଯଦି ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ଯଦି (status != PAM_AUTHTOK)
				ଯାଅ fail;
			ଯଦି ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, ଖାଲି)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PAM_ERROR_ସନ୍ଦେଶ:
		ସ୍ଥିତି PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style),
			       PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ));
			ଯଦି ((r = sshbuf_put_cstring(buffer,
			    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ଯଦି (ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock,
			    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style), buffer) == -1)
				ଯାଅ fail;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯାଅ fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	ଫେରନ୍ତୁ (PAM_SUCCESS);

 fail:
	ପାଇଁ(i = 0; i < n; i++) {
		ମୁକ୍ତ(reply[i].resp);
	}
	ମୁକ୍ତ(reply);
	sshbuf_free(buffer);
	ଫେରନ୍ତୁ (PAM_CONV_ERR);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_pam_user(Authctxt *authctxt)
{
	ଅଚଳ ଅକ୍ଷର *pam_user;

	ଯଦି (authctxt == ଖାଲି || authctxt->pw == ଖାଲି ||
	    authctxt->pw->pw_name == ଖାଲି)
		fatal_f("PAM authctxt user not initialized");

	ଯଦି ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ଶୂନ୍ୟ **) &pam_user)) != PAM_SUCCESS)
		ଫେରନ୍ତୁ sshpam_err;

	ଯଦି (pam_user == ଖାଲି) {
		debug("PAM error: PAM_USER is NULL");
		ଫେରନ୍ତୁ PAM_USER_UNKNOWN;
	}

	ଯଦି (sshpam_initial_user == ଖାଲି)
		fatal_f("internal error: sshpam_initial_user NULL");
	ଯଦି (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		ଫେରନ୍ତୁ PAM_USER_UNKNOWN;
	}
	ଫେରନ୍ତୁ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ସ୍ଥିର ଶୂନ୍ୟ *
sshpam_thread(ଶୂନ୍ୟ *ctxtp)
{
	ସଂରଚନା pam_ctxt *ctxt = ctxtp;
	ସଂରଚନା sshbuf *buffer = ଖାଲି;
	ସଂରଚନା pam_conv sshpam_conv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	ବାହ୍ୟ ଅକ୍ଷର **environ;
	ଅକ୍ଷର **env_from_pam;
	u_int i;
	ଅଚଳ ଅକ୍ଷର *pam_user;
	ଅଚଳ ଅକ୍ଷର **ptr_pam_user = &pam_user;
	ଅକ୍ଷର *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ଶୂନ୍ୟ **)ptr_pam_user);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		ଯାଅ auth_fail;

	environ[0] = ଖାଲି;
	ଯଦି (tz != ଖାଲି)
		ଯଦି (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ଯଦି (sshpam_authctxt != ଖାଲି) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ଯଦି (sshpam_authctxt == ଖାଲି)
		fatal_f("PAM authctxt not initialized");

	ଯଦି ((buffer = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ଅଚଳ ଶୂନ୍ୟ *)&sshpam_conv);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		ଯାଅ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ଯଦି (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		ଯାଅ auth_fail;
	ଯଦି ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		ଯାଅ auth_fail;

	ଯଦି (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		ଯାଅ auth_fail;
	}
	ଯଦି (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ଯଦି (sshpam_err != PAM_SUCCESS)
			ଯାଅ auth_fail;
		sshpam_password_change_required(0);
	}

	ଯଦି ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	ଯଦି ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	ପାଇଁ (i = 0; environ[i] != ଖାଲି; i++) {
		/*ଗଣନା*/
		ଯଦି (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	ଯଦି ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	ପାଇଁ (i = 0; environ[i] != ଖାଲି; i++) {
		ଯଦି ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	ପାଇଁ (i = 0; env_from_pam != ଖାଲି && env_from_pam[i] != ଖାଲି; i++) {
		/*ଗଣନା*/
		ଯଦି (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	ଯଦି ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	ପାଇଁ (i = 0; env_from_pam != ଖାଲି && env_from_pam[i] != ଖାଲି; i++) {
		ଯଦି ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(ଖାଲି);

 auth_fail:
	ଯଦି ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ଯଦି (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	ଅନ୍ୟଥା ଯଦି (sshpam_maxtries_reached)
		ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	ଅନ୍ୟଥା
		ssh_ସନ୍ଦେଶ_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(ଖାଲି);

	ଫେରନ୍ତୁ (ଖାଲି); /* Avoid warning for non-pthread case */
}

ଶୂନ୍ୟ
sshpam_thread_cleanup(ଶୂନ୍ୟ)
{
	ସଂରଚନା pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ଯଦି (ctxt != ଖାଲି && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ଖାଲି);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, ଆକାର(*ctxt));
		cleanup_ctxt = ଖାଲି;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_null_conv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, sshpam_const ସଂରଚନା pam_message **ସନ୍ଦେଶ,
    ସଂରଚନା pam_response **resp, ଶୂନ୍ୟ *data)
{
	debug3_f("PAM: entering, %d messages", n);
	ଫେରନ୍ତୁ (PAM_CONV_ERR);
}

ସ୍ଥିର ସଂରଚନା pam_conv null_conv = { sshpam_null_conv, ଖାଲି };

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_store_conv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, sshpam_const ସଂରଚନା pam_message **ସନ୍ଦେଶ,
    ସଂରଚନା pam_response **resp, ଶୂନ୍ୟ *data)
{
	ସଂରଚନା pam_response *reply;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ଖାଲି;

	ଯଦି (n <= 0 || n > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ)
		ଫେରନ୍ତୁ (PAM_CONV_ERR);

	ଯଦି ((reply = calloc(n, ଆକାର(*reply))) == ଖାଲି)
		ଫେରନ୍ତୁ (PAM_CONV_ERR);

	ପାଇଁ (i = 0; i < n; ++i) {
		ବାଛ (PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style)) {
		ସ୍ଥିତି PAM_ERROR_ସନ୍ଦେଶ:
		ସ୍ଥିତି PAM_TEXT_INFO:
			ଯଦି ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯାଅ fail;
		}
	}
	*resp = reply;
	ଫେରନ୍ତୁ (PAM_SUCCESS);

 fail:
	ପାଇଁ(i = 0; i < n; i++) {
		ମୁକ୍ତ(reply[i].resp);
	}
	ମୁକ୍ତ(reply);
	ଫେରନ୍ତୁ (PAM_CONV_ERR);
}

ସ୍ଥିର ସଂରଚନା pam_conv store_conv = { sshpam_store_conv, ଖାଲି };

ଶୂନ୍ୟ
sshpam_cleanup(ଶୂନ୍ୟ)
{
	ଯଦି (sshpam_handle == ଖାଲି || !mm_is_monitor())
		ଫେରନ୍ତୁ;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (ଅଚଳ ଶୂନ୍ୟ *)&null_conv);
	ଯଦି (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ଯଦି (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = ଖାଲି;
	ମୁକ୍ତ(sshpam_initial_user);
	sshpam_initial_user = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_init(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	ଅଚଳ ଅକ୍ଷର *user = authctxt->user;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (options.pam_service_name == ଖାଲି)
		fatal_f("internal error: NULL PAM service name");
#ଯଦି defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	ଯଦି (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	ଯଦି (sshpam_handle == ଖାଲି && ssh == ଖାଲି)
		fatal("%s: called initially with no packet context", __func__);
	ଯଦି (sshpam_handle != ଖାଲି) {
		/* We already have a PAM context; check if the user matches */
		ଯଦି ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		ଫେରନ୍ତୁ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ଯଦି (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ଖାଲି;
		ଫେରନ୍ତୁ (-1);
	}

	ଯଦି (ssh != ଖାଲି && sshpam_rhost == ଖାଲି) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	ଯଦି (sshpam_rhost != ଖାଲି && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ଯଦି (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = ଖାଲି;
			ଫେରନ୍ତୁ (-1);
		}
	}
	ଯଦି (ssh != ଖାଲି && sshpam_laddr != ଖାଲି) {
		ଅକ୍ଷର *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		ଯଦି ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		ମୁକ୍ତ(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	ଯଦି (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ଖାଲି;
		ଫେରନ୍ତୁ (-1);
	}
#endif
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ଶୂନ୍ୟ
expose_authinfo(ଅଚଳ ଅକ୍ଷର *caller)
{
	ଅକ୍ଷର *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ଯଦି (sshpam_authctxt->session_info == ଖାଲି)
		auth_info = xstrdup("");
	ଅନ୍ୟଥା ଯଦି ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	ମୁକ୍ତ(auth_info);
}

ସ୍ଥିର ଶୂନ୍ୟ *
sshpam_init_ctx(Authctxt *authctxt)
{
	ସଂରଚନା pam_ctxt *ctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ଯଦି (!options.use_pam || sshpam_account_status == 0)
		ଫେରନ୍ତୁ ଖାଲି;

	/* Initialize PAM */
	ଯଦି (sshpam_init(ଖାଲି, authctxt) == -1) {
		error("PAM: initialization failed");
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, ଆକାର *ctxt);

	/* Start the authentication thread */
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		ମୁକ୍ତ(ctxt);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, ଖାଲି, sshpam_thread, ctxt);
	ଯଦି (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		ମୁକ୍ତ(ctxt);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	cleanup_ctxt = ctxt;
	ଫେରନ୍ତୁ (ctxt);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_query(ଶୂନ୍ୟ *ctx, ଅକ୍ଷର **name, ଅକ୍ଷର **info,
    u_int *ଅଙ୍କ, ଅକ୍ଷର ***prompts, u_int **echo_on)
{
	ସଂରଚନା sshbuf *buffer;
	ସଂରଚନା pam_ctxt *ctxt = ctx;
	u_char type;
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	size_t mlen, nmesg = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି ((buffer = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ଖାଲି;
	*ଅଙ୍କ = 0;
	ctxt->pam_done = SshPamNone;

	ଯେତେବେଳେ (ssh_ସନ୍ଦେଶ_recv(ctxt->pam_psock, buffer) == 0) {
		ଯଦି (++nmesg > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ)
			fatal_f("too many query messages");
		ଯଦି ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &ସନ୍ଦେଶ, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		ବାଛ (type) {
		ସ୍ଥିତି PAM_PROMPT_ECHO_ON:
		ସ୍ଥିତି PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, ଆକାର(ଅକ୍ଷର *));
			*echo_on = xcalloc(1, ଆକାର(u_int));
			(*prompts)[0] = ସନ୍ଦେଶ;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*ଅଙ୍କ = 1;
			sshbuf_free(buffer);
			ଫେରନ୍ତୁ (0);
		ସ୍ଥିତି PAM_ERROR_ସନ୍ଦେଶ:
		ସ୍ଥିତି PAM_TEXT_INFO:
			ମୁକ୍ତ(*info);
			*info = ସନ୍ଦେଶ; /* transfer ownership */
			ସନ୍ଦେଶ = ଖାଲି;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			ଫେରନ୍ତୁ (0);
		ସ୍ଥିତି PAM_ACCT_EXPIRED:
		ସ୍ଥିତି PAM_MAXTRIES:
			ଯଦି (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			ଯଦି (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		ସ୍ଥିତି PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		ସ୍ଥିତି PAM_SUCCESS:
			ଯଦି (type == PAM_SUCCESS) {
				ଯଦି (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_ମୂଳ_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				ମୁକ୍ତ(ସନ୍ଦେଶ);
				sshbuf_free(buffer);
				ଫେରନ୍ତୁ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", ସନ୍ଦେଶ,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ମୁକ୍ତ(ସନ୍ଦେଶ);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			ଫେରନ୍ତୁ (-1);
		}
	}
	sshbuf_free(buffer);
	ଫେରନ୍ତୁ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ସ୍ଥିର ଅକ୍ଷର *
fake_password(ଅଚଳ ଅକ୍ଷର *wire_password)
{
	ଅଚଳ ଅକ୍ଷର junk[] = "\b\n\r\177INCORRECT";
	ଅକ୍ଷର *ret = ଖାଲି;
	size_t i, l = wire_password != ଖାଲି ? strlen(wire_password) : 0;

	ଯଦି (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	ଯଦି (ret == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ପାଇଁ (i = 0; i < l; i++)
		ret[i] = junk[i % (ଆକାର(junk) - 1)];
	ret[i] = '\0';
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_respond(ଶୂନ୍ୟ *ctx, u_int ଅଙ୍କ, ଅକ୍ଷର **resp)
{
	ସଂରଚନା sshbuf *buffer;
	ସଂରଚନା pam_ctxt *ctxt = ctx;
	ଅକ୍ଷର *fake;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2_f("PAM: entering, %u responses", ଅଙ୍କ);
	ବାଛ (ctxt->pam_done) {
	ସ୍ଥିତି SshPamAuthenticated:
		sshpam_authenticated = 1;
		ଫେରନ୍ତୁ (0);
	ସ୍ଥିତି SshPamNone:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SshPamAgain:
		ଫେରନ୍ତୁ 1;	/* KbdintResultAgain */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (ଅଙ୍କ != 1) {
		error("PAM: expected one response, got %u", ଅଙ୍କ);
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି ((buffer = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_ମୂଳ_login == PERMIT_YES)) {
		ଯଦି ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ଅନ୍ୟଥା {
		fake = fake_password(*resp);
		ଯଦି ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		ମୁକ୍ତ(fake);
	}
	ଯଦି (ssh_ସନ୍ଦେଶ_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		ଫେରନ୍ତୁ (-1);
	}
	sshbuf_free(buffer);
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ଶୂନ୍ୟ
sshpam_free_ctx(ଶୂନ୍ୟ *ctxtp)
{
	ସଂରଚନା pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	ମୁକ୍ତ(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_priv_kbdint_authdone(ଶୂନ୍ୟ *ctxtp)
{
	ସଂରଚନା pam_ctxt *ctxt = ctxtp;

	ଫେରନ୍ତୁ ctxt->pam_done == SshPamAuthenticated;
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
ଶୂନ୍ୟ
start_pam(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ଯଦି (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ଯଦି (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

ଶୂନ୍ୟ
finish_pam(ଶୂନ୍ୟ)
{
	sshpam_cleanup();
}


u_int
do_pam_account(ଶୂନ୍ୟ)
{
	debug_f("called");
	ଯଦି (sshpam_account_status != -1)
		ଫେରନ୍ତୁ (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ଯଦି (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		ଫେରନ୍ତୁ (sshpam_account_status);
	}

	ଯଦି (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	ଫେରନ୍ତୁ (sshpam_account_status);
}

ଶୂନ୍ୟ
do_pam_setcred(ଶୂନ୍ୟ)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ଅଚଳ ଶୂନ୍ୟ *)&store_conv);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ଯଦି (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		ଫେରନ୍ତୁ;
	}
	ଯଦି (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ଅନ୍ୟଥା
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

ଶୂନ୍ୟ
do_pam_session(ସଂରଚନା ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ଅଚଳ ଶୂନ୍ୟ *)&store_conv);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ଯଦି (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ଅନ୍ୟଥା {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_pam_session_open(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_pam_putenv(ଅକ୍ଷର *name, ଅକ୍ଷର *ମୂଲ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 1;
	ଅକ୍ଷର *compound;
	size_t len;

	len = strlen(name) + strlen(ମୂଲ୍ୟ) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, ମୂଲ୍ୟ);
	ret = pam_putenv(sshpam_handle, compound);
	ମୁକ୍ତ(compound);

	ଫେରନ୍ତୁ (ret);
}

ଅକ୍ଷର **
fetch_pam_child_environment(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ sshpam_env;
}

ଅକ୍ଷର **
fetch_pam_environment(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ (pam_getenvlist(sshpam_handle));
}

ଶୂନ୍ୟ
free_pam_environment(ଅକ୍ଷର **env)
{
	ଅକ୍ଷର **envp;

	ଯଦି (env == ଖାଲି)
		ଫେରନ୍ତୁ;

	ପାଇଁ (envp = env; *envp; envp++)
		ମୁକ୍ତ(*envp);
	ମୁକ୍ତ(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_passwd_conv(ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, sshpam_const ସଂରଚନା pam_message **ସନ୍ଦେଶ,
    ସଂରଚନା pam_response **resp, ଶୂନ୍ୟ *data)
{
	ସଂରଚନା pam_response *reply;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ଖାଲି;

	ଯଦି (n <= 0 || n > PAM_MAX_ଅଙ୍କ_ସନ୍ଦେଶ)
		ଫେରନ୍ତୁ (PAM_CONV_ERR);

	ଯଦି ((reply = calloc(n, ଆକାର(*reply))) == ଖାଲି)
		ଫେରନ୍ତୁ (PAM_CONV_ERR);

	ପାଇଁ (i = 0; i < n; ++i) {
		ବାଛ (PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ_style)) {
		ସ୍ଥିତି PAM_PROMPT_ECHO_OFF:
			ଯଦି (sshpam_password == ଖାଲି)
				ଯାଅ fail;
			ଯଦି ((reply[i].resp = strdup(sshpam_password)) == ଖାଲି)
				ଯାଅ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PAM_ERROR_ସନ୍ଦେଶ:
		ସ୍ଥିତି PAM_TEXT_INFO:
			len = strlen(PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ));
			ଯଦି (len > 0) {
				ଯଦି ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_ସନ୍ଦେଶ_MEMBER(ସନ୍ଦେଶ, i, ସନ୍ଦେଶ))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ଯଦି ((reply[i].resp = strdup("")) == ଖାଲି)
				ଯାଅ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯାଅ fail;
		}
	}
	*resp = reply;
	ଫେରନ୍ତୁ (PAM_SUCCESS);

 fail:
	ପାଇଁ(i = 0; i < n; i++) {
		ମୁକ୍ତ(reply[i].resp);
	}
	ମୁକ୍ତ(reply);
	ଫେରନ୍ତୁ (PAM_CONV_ERR);
}

ସ୍ଥିର ସଂରଚନା pam_conv passwd_conv = { sshpam_passwd_conv, ଖାଲି };

/*
 * Attempt password authentication via PAM
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_auth_passwd(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *password)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	ଅକ୍ଷର *fake = ଖାଲି;

	ଯଦି (!options.use_pam || sshpam_handle == ଖାଲି)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ଯଦି (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_ମୂଳ_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ଅଚଳ ଶୂନ୍ୟ *)&passwd_conv);
	ଯଦି (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ଖାଲି;
	ମୁକ୍ତ(fake);
	ଯଦି (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ଯଦି (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ଯଦି (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		ଫେରନ୍ତୁ 1;
	} ଅନ୍ୟଥା {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		ଫେରନ୍ତୁ 0;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshpam_get_maxtries_reached(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ sshpam_maxtries_reached;
}

ଶୂନ୍ୟ
sshpam_set_maxtries_reached(ପୂର୍ଣ୍ଣସଂଖ୍ୟା reached)
{
	ଯଦି (reached == 0 || sshpam_maxtries_reached)
		ଫେରନ୍ତୁ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
