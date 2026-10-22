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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef USE_PAM
#ಯದಿ defined(HAVE_SECURITY_PAM_APPL_H)
#ಅನ್ತರ್ಭಾವ <security/pam_appl.h>
#ನೋಚೇದ್ಯದಿ defined (HAVE_PAM_PAM_APPL_H)
#ಅನ್ತರ್ಭಾವ <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ಅನ್ಯಥಾ
# define sshpam_const	ಧ್ರುವ	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, n, member) ((*(ಸಂದೇಶ))[(n)].member)
#ಅನ್ಯಥಾ
# define PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, n, member) ((ಸಂದೇಶ)[(n)]->member)
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"

ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;
ಬಾಹ್ಯ u_int utmp_len;

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
#ಅನ್ತರ್ಭಾವ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
ಪ್ರಕಾರನಿರ್ದೇಶ pthread_t sp_pthread_t;
#ಅನ್ಯಥಾ
ಪ್ರಕಾರನಿರ್ದೇಶ pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

ಸಂರಚನಾ pam_ctxt {
	sp_pthread_t	 pam_thread;
	ಪೂರ್ಣಾಙ್ಕ		 pam_psock;
	ಪೂರ್ಣಾಙ್ಕ		 pam_csock;
	SshPamDone	 pam_done;
};

ಸ್ಥಿರ ಶೂನ್ಯ sshpam_free_ctx(ಶೂನ್ಯ *);
ಸ್ಥಿರ ಸಂರಚನಾ pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_thread_status = -1;
ಸ್ಥಿರ sshsig_t sshpam_oldsig;

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_sigchld_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ (cleanup_ctxt == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;	/* handler called after PAM cleanup, shouldn't happen */
	ಯದಿ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ಯಾವತ್ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			ಯದಿ (errno == EINTR)
				ಅನುವರ್ತ;
			ಪ್ರತ್ಯಾಗಮ;
		}
	}
	ಯದಿ (sshpam_thread_status == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (WIFSIGNALED(sshpam_thread_status)) {
		ಯದಿ (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} ಅನ್ಯಥಾ ಯದಿ (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
ಸ್ಥಿರ ಶೂನ್ಯ
pthread_exit(ಶೂನ್ಯ *ಮೌಲ್ಯ)
{
	_exit(0);
}

/* ARGSUSED */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pthread_create(sp_pthread_t *thread, ಧ್ರುವ ಶೂನ್ಯ *attr,
    ಶೂನ್ಯ *(*thread_start)(ಶೂನ್ಯ *), ಶೂನ್ಯ *arg)
{
	pid_t pid;
	ಸಂರಚನಾ pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	ವಿಕಲ್ಪ ((pid = fork())) {
	ಪಕ್ಷ -1:
		error("fork(): %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ errno;
	ಪಕ್ಷ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	ಸ್ವಭಾವ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		ಪ್ರತ್ಯಾಗಮ (0);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ಪ್ರತ್ಯಾಗಮ (kill(thread, SIGTERM));
}

/* ARGSUSED */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pthread_join(sp_pthread_t thread, ಶೂನ್ಯ **ಮೌಲ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯದಿ (sshpam_thread_status != -1)
		ಪ್ರತ್ಯಾಗಮ (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ಯಾವತ್ (waitpid(thread, &status, 0) == -1) {
		ಯದಿ (errno == EINTR)
			ಅನುವರ್ತ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಪ್ರತ್ಯಾಗಮ (status);
}
#endif


ಸ್ಥಿರ pam_handle_t *sshpam_handle = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *sshpam_initial_user;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_err = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_authenticated = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_session_open = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_cred_established = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_account_status = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshpam_maxtries_reached = 0;
ಸ್ಥಿರ ವರ್ಣ **sshpam_env = ರಿಕ್ತ;
ಸ್ಥಿರ Authctxt *sshpam_authctxt = ರಿಕ್ತ;
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *sshpam_password = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *sshpam_rhost = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *sshpam_laddr = ರಿಕ್ತ;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
ಸ್ಥಿರ ವರ್ಣ **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}
#endif

#ifndef HAVE_PAM_PUTENV
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pam_putenv(pam_handle_t *pamh, ಧ್ರುವ ವರ್ಣ *name_ಮೌಲ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_password_change_required(ಪೂರ್ಣಾಙ್ಕ reqd)
{
	ಬಾಹ್ಯ ಸಂರಚನಾ sshauthopt *auth_opts;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ಯದಿ (sshpam_authctxt == ರಿಕ್ತ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ಯದಿ (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ಅನ್ಯಥಾ {
		ಯದಿ (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		ಯದಿ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ಯದಿ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ಸ್ಥಿರ ಶೂನ್ಯ
import_environments(ಸಂರಚನಾ sshbuf *b)
{
	ವರ್ಣ *env;
	u_int n, i, ಅಂಕೆ_env;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	ಯದಿ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (ಪೂರ್ಣಾಙ್ಕ)n;
	ಯದಿ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ಯದಿ ((r = sshbuf_get_u32(b, &ಅಂಕೆ_env)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (ಅಂಕೆ_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    ಅಂಕೆ_env);
	}
	sshpam_env = xcalloc(ಅಂಕೆ_env + 1, ಪರಿಮಾಣ(*sshpam_env));
	debug3("PAM: num env strings %u", ಅಂಕೆ_env);
	ಪ್ರತಿ(i = 0; i < ಅಂಕೆ_env; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ರಿಕ್ತ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[ಅಂಕೆ_env] = ರಿಕ್ತ;

	/* Import PAM environment from subprocess */
	ಯದಿ ((r = sshbuf_get_u32(b, &ಅಂಕೆ_env)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (ಅಂಕೆ_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    ಅಂಕೆ_env);
	}
	debug("PAM: num PAM env strings %u", ಅಂಕೆ_env);
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_env; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(b, &env, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ಯದಿ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_thread_conv(ಪೂರ್ಣಾಙ್ಕ n, sshpam_const ಸಂರಚನಾ pam_message **ಸಂದೇಶ,
    ಸಂರಚನಾ pam_response **resp, ಶೂನ್ಯ *data)
{
	ಸಂರಚನಾ sshbuf *buffer;
	ಸಂರಚನಾ pam_ctxt *ctxt;
	ಸಂರಚನಾ pam_response *reply;
	ಪೂರ್ಣಾಙ್ಕ r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ರಿಕ್ತ;

	ಯದಿ (data == ರಿಕ್ತ) {
		error("PAM: conversation function passed a null context");
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);
	}
	ctxt = data;
	ಯದಿ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);

	ಯದಿ ((reply = calloc(n, ಪರಿಮಾಣ(*reply))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ PAM_CONV_ERR;
	ಯದಿ ((buffer = sshbuf_new()) == ರಿಕ್ತ) {
		ಮುಕ್ತ(reply);
		ಪ್ರತ್ಯಾಗಮ PAM_CONV_ERR;
	}

	ಪ್ರತಿ (i = 0; i < n; ++i) {
		ವಿಕಲ್ಪ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಪಕ್ಷ PAM_PROMPT_ECHO_OFF:
		ಪಕ್ಷ PAM_PROMPT_ECHO_ON:
			ಯದಿ ((r = sshbuf_put_cstring(buffer,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಯದಿ (ssh_ಸಂದೇಶ_send(ctxt->pam_csock,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style), buffer) == -1)
				ಗಚ್ಛ fail;

			ಯದಿ (ssh_ಸಂದೇಶ_recv(ctxt->pam_csock, buffer) == -1)
				ಗಚ್ಛ fail;
			ಯದಿ ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಯದಿ (status != PAM_AUTHTOK)
				ಗಚ್ಛ fail;
			ಯದಿ ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, ರಿಕ್ತ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಭಙ್ಗ;
		ಪಕ್ಷ PAM_ERROR_ಸಂದೇಶ:
		ಪಕ್ಷ PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style),
			       PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ));
			ಯದಿ ((r = sshbuf_put_cstring(buffer,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಯದಿ (ssh_ಸಂದೇಶ_send(ctxt->pam_csock,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style), buffer) == -1)
				ಗಚ್ಛ fail;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಗಚ್ಛ fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	ಪ್ರತ್ಯಾಗಮ (PAM_SUCCESS);

 fail:
	ಪ್ರತಿ(i = 0; i < n; i++) {
		ಮುಕ್ತ(reply[i].resp);
	}
	ಮುಕ್ತ(reply);
	sshbuf_free(buffer);
	ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_pam_user(Authctxt *authctxt)
{
	ಧ್ರುವ ವರ್ಣ *pam_user;

	ಯದಿ (authctxt == ರಿಕ್ತ || authctxt->pw == ರಿಕ್ತ ||
	    authctxt->pw->pw_name == ರಿಕ್ತ)
		fatal_f("PAM authctxt user not initialized");

	ಯದಿ ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ಶೂನ್ಯ **) &pam_user)) != PAM_SUCCESS)
		ಪ್ರತ್ಯಾಗಮ sshpam_err;

	ಯದಿ (pam_user == ರಿಕ್ತ) {
		debug("PAM error: PAM_USER is NULL");
		ಪ್ರತ್ಯಾಗಮ PAM_USER_UNKNOWN;
	}

	ಯದಿ (sshpam_initial_user == ರಿಕ್ತ)
		fatal_f("internal error: sshpam_initial_user NULL");
	ಯದಿ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		ಪ್ರತ್ಯಾಗಮ PAM_USER_UNKNOWN;
	}
	ಪ್ರತ್ಯಾಗಮ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ಸ್ಥಿರ ಶೂನ್ಯ *
sshpam_thread(ಶೂನ್ಯ *ctxtp)
{
	ಸಂರಚನಾ pam_ctxt *ctxt = ctxtp;
	ಸಂರಚನಾ sshbuf *buffer = ರಿಕ್ತ;
	ಸಂರಚನಾ pam_conv sshpam_conv;
	ಪೂರ್ಣಾಙ್ಕ r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ವರ್ಣ **env_from_pam;
	u_int i;
	ಧ್ರುವ ವರ್ಣ *pam_user;
	ಧ್ರುವ ವರ್ಣ **ptr_pam_user = &pam_user;
	ವರ್ಣ *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ಶೂನ್ಯ **)ptr_pam_user);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		ಗಚ್ಛ auth_fail;

	environ[0] = ರಿಕ್ತ;
	ಯದಿ (tz != ರಿಕ್ತ)
		ಯದಿ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ಯದಿ (sshpam_authctxt != ರಿಕ್ತ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ಯದಿ (sshpam_authctxt == ರಿಕ್ತ)
		fatal_f("PAM authctxt not initialized");

	ಯದಿ ((buffer = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ಧ್ರುವ ಶೂನ್ಯ *)&sshpam_conv);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		ಗಚ್ಛ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ಯದಿ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		ಗಚ್ಛ auth_fail;
	ಯದಿ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		ಗಚ್ಛ auth_fail;

	ಯದಿ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		ಗಚ್ಛ auth_fail;
	}
	ಯದಿ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ಯದಿ (sshpam_err != PAM_SUCCESS)
			ಗಚ್ಛ auth_fail;
		sshpam_password_change_required(0);
	}

	ಯದಿ ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	ಯದಿ ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	ಪ್ರತಿ (i = 0; environ[i] != ರಿಕ್ತ; i++) {
		/*ಎಣಿಕೆ*/
		ಯದಿ (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	ಯದಿ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	ಪ್ರತಿ (i = 0; environ[i] != ರಿಕ್ತ; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	ಪ್ರತಿ (i = 0; env_from_pam != ರಿಕ್ತ && env_from_pam[i] != ರಿಕ್ತ; i++) {
		/*ಎಣಿಕೆ*/
		ಯದಿ (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	ಯದಿ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	ಪ್ರತಿ (i = 0; env_from_pam != ರಿಕ್ತ && env_from_pam[i] != ರಿಕ್ತ; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_ಸಂದೇಶ_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(ರಿಕ್ತ);

 auth_fail:
	ಯದಿ ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ಯದಿ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	ಅನ್ಯಥಾ ಯದಿ (sshpam_maxtries_reached)
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	ಅನ್ಯಥಾ
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(ರಿಕ್ತ);

	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ); /* Avoid warning for non-pthread case */
}

ಶೂನ್ಯ
sshpam_thread_cleanup(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ಯದಿ (ctxt != ರಿಕ್ತ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ರಿಕ್ತ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, ಪರಿಮಾಣ(*ctxt));
		cleanup_ctxt = ರಿಕ್ತ;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_null_conv(ಪೂರ್ಣಾಙ್ಕ n, sshpam_const ಸಂರಚನಾ pam_message **ಸಂದೇಶ,
    ಸಂರಚನಾ pam_response **resp, ಶೂನ್ಯ *data)
{
	debug3_f("PAM: entering, %d messages", n);
	ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ಸಂರಚನಾ pam_conv null_conv = { sshpam_null_conv, ರಿಕ್ತ };

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_store_conv(ಪೂರ್ಣಾಙ್ಕ n, sshpam_const ಸಂರಚನಾ pam_message **ಸಂದೇಶ,
    ಸಂರಚನಾ pam_response **resp, ಶೂನ್ಯ *data)
{
	ಸಂರಚನಾ pam_response *reply;
	ಪೂರ್ಣಾಙ್ಕ r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ರಿಕ್ತ;

	ಯದಿ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);

	ಯದಿ ((reply = calloc(n, ಪರಿಮಾಣ(*reply))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);

	ಪ್ರತಿ (i = 0; i < n; ++i) {
		ವಿಕಲ್ಪ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಪಕ್ಷ PAM_ERROR_ಸಂದೇಶ:
		ಪಕ್ಷ PAM_TEXT_INFO:
			ಯದಿ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಗಚ್ಛ fail;
		}
	}
	*resp = reply;
	ಪ್ರತ್ಯಾಗಮ (PAM_SUCCESS);

 fail:
	ಪ್ರತಿ(i = 0; i < n; i++) {
		ಮುಕ್ತ(reply[i].resp);
	}
	ಮುಕ್ತ(reply);
	ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ಸಂರಚನಾ pam_conv store_conv = { sshpam_store_conv, ರಿಕ್ತ };

ಶೂನ್ಯ
sshpam_cleanup(ಶೂನ್ಯ)
{
	ಯದಿ (sshpam_handle == ರಿಕ್ತ || !mm_is_monitor())
		ಪ್ರತ್ಯಾಗಮ;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (ಧ್ರುವ ಶೂನ್ಯ *)&null_conv);
	ಯದಿ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ಯದಿ (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = ರಿಕ್ತ;
	ಮುಕ್ತ(sshpam_initial_user);
	sshpam_initial_user = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_init(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	ಧ್ರುವ ವರ್ಣ *user = authctxt->user;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (options.pam_service_name == ರಿಕ್ತ)
		fatal_f("internal error: NULL PAM service name");
#ಯದಿ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	ಯದಿ (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	ಯದಿ (sshpam_handle == ರಿಕ್ತ && ssh == ರಿಕ್ತ)
		fatal("%s: called initially with no packet context", __func__);
	ಯದಿ (sshpam_handle != ರಿಕ್ತ) {
		/* We already have a PAM context; check if the user matches */
		ಯದಿ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ಯದಿ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಯದಿ (ssh != ರಿಕ್ತ && sshpam_rhost == ರಿಕ್ತ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	ಯದಿ (sshpam_rhost != ರಿಕ್ತ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ಯದಿ (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = ರಿಕ್ತ;
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	}
	ಯದಿ (ssh != ರಿಕ್ತ && sshpam_laddr != ರಿಕ್ತ) {
		ವರ್ಣ *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		ಯದಿ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		ಮುಕ್ತ(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	ಯದಿ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
#endif
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
expose_authinfo(ಧ್ರುವ ವರ್ಣ *caller)
{
	ವರ್ಣ *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ಯದಿ (sshpam_authctxt->session_info == ರಿಕ್ತ)
		auth_info = xstrdup("");
	ಅನ್ಯಥಾ ಯದಿ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	ಮುಕ್ತ(auth_info);
}

ಸ್ಥಿರ ಶೂನ್ಯ *
sshpam_init_ctx(Authctxt *authctxt)
{
	ಸಂರಚನಾ pam_ctxt *ctxt;
	ಪೂರ್ಣಾಙ್ಕ result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ಯದಿ (!options.use_pam || sshpam_account_status == 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* Initialize PAM */
	ಯದಿ (sshpam_init(ರಿಕ್ತ, authctxt) == -1) {
		error("PAM: initialization failed");
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, ಪರಿಮಾಣ *ctxt);

	/* Start the authentication thread */
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		ಮುಕ್ತ(ctxt);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, ರಿಕ್ತ, sshpam_thread, ctxt);
	ಯದಿ (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		ಮುಕ್ತ(ctxt);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	cleanup_ctxt = ctxt;
	ಪ್ರತ್ಯಾಗಮ (ctxt);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_query(ಶೂನ್ಯ *ctx, ವರ್ಣ **name, ವರ್ಣ **info,
    u_int *ಅಂಕೆ, ವರ್ಣ ***prompts, u_int **echo_on)
{
	ಸಂರಚನಾ sshbuf *buffer;
	ಸಂರಚನಾ pam_ctxt *ctxt = ctx;
	u_char type;
	ವರ್ಣ *ಸಂದೇಶ;
	size_t mlen, nmesg = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ ((buffer = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ರಿಕ್ತ;
	*ಅಂಕೆ = 0;
	ctxt->pam_done = SshPamNone;

	ಯಾವತ್ (ssh_ಸಂದೇಶ_recv(ctxt->pam_psock, buffer) == 0) {
		ಯದಿ (++nmesg > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
			fatal_f("too many query messages");
		ಯದಿ ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &ಸಂದೇಶ, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ PAM_PROMPT_ECHO_ON:
		ಪಕ್ಷ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, ಪರಿಮಾಣ(ವರ್ಣ *));
			*echo_on = xcalloc(1, ಪರಿಮಾಣ(u_int));
			(*prompts)[0] = ಸಂದೇಶ;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*ಅಂಕೆ = 1;
			sshbuf_free(buffer);
			ಪ್ರತ್ಯಾಗಮ (0);
		ಪಕ್ಷ PAM_ERROR_ಸಂದೇಶ:
		ಪಕ್ಷ PAM_TEXT_INFO:
			ಮುಕ್ತ(*info);
			*info = ಸಂದೇಶ; /* transfer ownership */
			ಸಂದೇಶ = ರಿಕ್ತ;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			ಪ್ರತ್ಯಾಗಮ (0);
		ಪಕ್ಷ PAM_ACCT_EXPIRED:
		ಪಕ್ಷ PAM_MAXTRIES:
			ಯದಿ (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			ಯದಿ (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		ಪಕ್ಷ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		ಪಕ್ಷ PAM_SUCCESS:
			ಯದಿ (type == PAM_SUCCESS) {
				ಯದಿ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_ಬೇರು_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				ಮುಕ್ತ(ಸಂದೇಶ);
				sshbuf_free(buffer);
				ಪ್ರತ್ಯಾಗಮ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", ಸಂದೇಶ,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		ಸ್ವಭಾವ:
			ಮುಕ್ತ(ಸಂದೇಶ);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	}
	sshbuf_free(buffer);
	ಪ್ರತ್ಯಾಗಮ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ಸ್ಥಿರ ವರ್ಣ *
fake_password(ಧ್ರುವ ವರ್ಣ *wire_password)
{
	ಧ್ರುವ ವರ್ಣ junk[] = "\b\n\r\177INCORRECT";
	ವರ್ಣ *ret = ರಿಕ್ತ;
	size_t i, l = wire_password != ರಿಕ್ತ ? strlen(wire_password) : 0;

	ಯದಿ (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	ಯದಿ (ret == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತಿ (i = 0; i < l; i++)
		ret[i] = junk[i % (ಪರಿಮಾಣ(junk) - 1)];
	ret[i] = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_respond(ಶೂನ್ಯ *ctx, u_int ಅಂಕೆ, ವರ್ಣ **resp)
{
	ಸಂರಚನಾ sshbuf *buffer;
	ಸಂರಚನಾ pam_ctxt *ctxt = ctx;
	ವರ್ಣ *fake;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2_f("PAM: entering, %u responses", ಅಂಕೆ);
	ವಿಕಲ್ಪ (ctxt->pam_done) {
	ಪಕ್ಷ SshPamAuthenticated:
		sshpam_authenticated = 1;
		ಪ್ರತ್ಯಾಗಮ (0);
	ಪಕ್ಷ SshPamNone:
		ಭಙ್ಗ;
	ಪಕ್ಷ SshPamAgain:
		ಪ್ರತ್ಯಾಗಮ 1;	/* KbdintResultAgain */
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (ಅಂಕೆ != 1) {
		error("PAM: expected one response, got %u", ಅಂಕೆ);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ ((buffer = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_ಬೇರು_login == PERMIT_YES)) {
		ಯದಿ ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ಅನ್ಯಥಾ {
		fake = fake_password(*resp);
		ಯದಿ ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		ಮುಕ್ತ(fake);
	}
	ಯದಿ (ssh_ಸಂದೇಶ_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	sshbuf_free(buffer);
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_free_ctx(ಶೂನ್ಯ *ctxtp)
{
	ಸಂರಚನಾ pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	ಮುಕ್ತ(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

ಪೂರ್ಣಾಙ್ಕ
sshpam_priv_kbdint_authdone(ಶೂನ್ಯ *ctxtp)
{
	ಸಂರಚನಾ pam_ctxt *ctxt = ctxtp;

	ಪ್ರತ್ಯಾಗಮ ctxt->pam_done == SshPamAuthenticated;
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
ಶೂನ್ಯ
start_pam(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ಯದಿ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ಯದಿ (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

ಶೂನ್ಯ
finish_pam(ಶೂನ್ಯ)
{
	sshpam_cleanup();
}


u_int
do_pam_account(ಶೂನ್ಯ)
{
	debug_f("called");
	ಯದಿ (sshpam_account_status != -1)
		ಪ್ರತ್ಯಾಗಮ (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ಯದಿ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		ಪ್ರತ್ಯಾಗಮ (sshpam_account_status);
	}

	ಯದಿ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	ಪ್ರತ್ಯಾಗಮ (sshpam_account_status);
}

ಶೂನ್ಯ
do_pam_setcred(ಶೂನ್ಯ)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ಧ್ರುವ ಶೂನ್ಯ *)&store_conv);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ಯದಿ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ಅನ್ಯಥಾ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

ಶೂನ್ಯ
do_pam_session(ಸಂರಚನಾ ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ಧ್ರುವ ಶೂನ್ಯ *)&store_conv);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ಯದಿ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ಅನ್ಯಥಾ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

ಪೂರ್ಣಾಙ್ಕ
is_pam_session_open(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
ಪೂರ್ಣಾಙ್ಕ
do_pam_putenv(ವರ್ಣ *name, ವರ್ಣ *ಮೌಲ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ ret = 1;
	ವರ್ಣ *compound;
	size_t len;

	len = strlen(name) + strlen(ಮೌಲ್ಯ) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, ಮೌಲ್ಯ);
	ret = pam_putenv(sshpam_handle, compound);
	ಮುಕ್ತ(compound);

	ಪ್ರತ್ಯಾಗಮ (ret);
}

ವರ್ಣ **
fetch_pam_child_environment(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ sshpam_env;
}

ವರ್ಣ **
fetch_pam_environment(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ (pam_getenvlist(sshpam_handle));
}

ಶೂನ್ಯ
free_pam_environment(ವರ್ಣ **env)
{
	ವರ್ಣ **envp;

	ಯದಿ (env == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ (envp = env; *envp; envp++)
		ಮುಕ್ತ(*envp);
	ಮುಕ್ತ(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshpam_passwd_conv(ಪೂರ್ಣಾಙ್ಕ n, sshpam_const ಸಂರಚನಾ pam_message **ಸಂದೇಶ,
    ಸಂರಚನಾ pam_response **resp, ಶೂನ್ಯ *data)
{
	ಸಂರಚನಾ pam_response *reply;
	ಪೂರ್ಣಾಙ್ಕ r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ರಿಕ್ತ;

	ಯದಿ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);

	ಯದಿ ((reply = calloc(n, ಪರಿಮಾಣ(*reply))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);

	ಪ್ರತಿ (i = 0; i < n; ++i) {
		ವಿಕಲ್ಪ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಪಕ್ಷ PAM_PROMPT_ECHO_OFF:
			ಯದಿ (sshpam_password == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			ಯದಿ ((reply[i].resp = strdup(sshpam_password)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ಭಙ್ಗ;
		ಪಕ್ಷ PAM_ERROR_ಸಂದೇಶ:
		ಪಕ್ಷ PAM_TEXT_INFO:
			len = strlen(PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ));
			ಯದಿ (len > 0) {
				ಯದಿ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ಯದಿ ((reply[i].resp = strdup("")) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಗಚ್ಛ fail;
		}
	}
	*resp = reply;
	ಪ್ರತ್ಯಾಗಮ (PAM_SUCCESS);

 fail:
	ಪ್ರತಿ(i = 0; i < n; i++) {
		ಮುಕ್ತ(reply[i].resp);
	}
	ಮುಕ್ತ(reply);
	ಪ್ರತ್ಯಾಗಮ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ಸಂರಚನಾ pam_conv passwd_conv = { sshpam_passwd_conv, ರಿಕ್ತ };

/*
 * Attempt password authentication via PAM
 */
ಪೂರ್ಣಾಙ್ಕ
sshpam_auth_passwd(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *password)
{
	ಪೂರ್ಣಾಙ್ಕ flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	ವರ್ಣ *fake = ರಿಕ್ತ;

	ಯದಿ (!options.use_pam || sshpam_handle == ರಿಕ್ತ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ಯದಿ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_ಬೇರು_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (ಧ್ರುವ ಶೂನ್ಯ *)&passwd_conv);
	ಯದಿ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ರಿಕ್ತ;
	ಮುಕ್ತ(fake);
	ಯದಿ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ಯದಿ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	ಯದಿ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		ಪ್ರತ್ಯಾಗಮ 1;
	} ಅನ್ಯಥಾ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

ಪೂರ್ಣಾಙ್ಕ
sshpam_get_maxtries_reached(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ sshpam_maxtries_reached;
}

ಶೂನ್ಯ
sshpam_set_maxtries_reached(ಪೂರ್ಣಾಙ್ಕ reached)
{
	ಯದಿ (reached == 0 || sshpam_maxtries_reached)
		ಪ್ರತ್ಯಾಗಮ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
