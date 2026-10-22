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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
#ಆದರೆ defined(HAVE_SECURITY_PAM_APPL_H)
#ಅನ್ತರ್ಭಾವ <security/pam_appl.h>
#ಅಥವಾಆದರೆ defined (HAVE_PAM_PAM_APPL_H)
#ಅನ್ತರ್ಭಾವ <pam/pam_appl.h>
#ಆದರೆ_ಅಂತ್ಯ

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ಇಲ್ಲದಿದ್ದರೆ
# define sshpam_const	ಸ್ಥಿರಾಂಕ	/* LinuxPAM, OpenPAM, AIX */
#ಆದರೆ_ಅಂತ್ಯ

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PAM_SUN_CODEBASE
# define PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, n, member) ((*(ಸಂದೇಶ))[(n)].member)
#ಇಲ್ಲದಿದ್ದರೆ
# define PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, n, member) ((ಸಂದೇಶ)[(n)]->member)
#ಆದರೆ_ಅಂತ್ಯ

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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"

ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ u_int utmp_len;

/* so we don't silently change behaviour */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_POSIX_ಎಳೆಗಳು
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ UNSUPPORTED_POSIX_ಎಳೆಗಳು_HACK
#ಅನ್ತರ್ಭಾವ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ pthread_t sp_pthread_t;
#ಇಲ್ಲದಿದ್ದರೆ
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ pid_t sp_pthread_t;
#ವ್ಯಾಖ್ಯಾನಿಸು pthread_exit	fake_pthread_exit
#ವ್ಯಾಖ್ಯಾನಿಸು pthread_create	fake_pthread_create
#ವ್ಯಾಖ್ಯಾನಿಸು pthread_cancel	fake_pthread_cancel
#ವ್ಯಾಖ್ಯಾನಿಸು pthread_join	fake_pthread_join
#ಆದರೆ_ಅಂತ್ಯ

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ Ssh_Pam_ಮುಗಿದ;
#ವ್ಯಾಖ್ಯಾನಿಸು SshPamError -1
#ವ್ಯಾಖ್ಯಾನಿಸು SshPamNone 0
#ವ್ಯಾಖ್ಯಾನಿಸು SshPamAuthenticated 1
#ವ್ಯಾಖ್ಯಾನಿಸು SshPamAgain 2

ರಚನೆ pam_ctxt {
	sp_pthread_t	 pam_thread;
	ಪೂರ್ಣಾಂಕ		 pam_psock;
	ಪೂರ್ಣಾಂಕ		 pam_csock;
	Ssh_Pam_ಮುಗಿದ	 pam_ಮುಗಿದ;
};

ಸ್ಥಿರ ಶೂನ್ಯ sshpam_free_ctx(ಶೂನ್ಯ *);
ಸ್ಥಿರ ರಚನೆ pam_ctxt *cleanup_ctxt;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UNSUPPORTED_POSIX_ಎಳೆಗಳು_HACK
/*
 * Simulate threads with processes.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_thread_ಸ್ಥಿತಿ = -1;
ಸ್ಥಿರ sshsig_t sshpam_oldsig;

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_sigchld_handler(ಪೂರ್ಣಾಂಕ sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ (cleanup_ctxt == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;	/* handler called after PAM cleanup, shouldn't happen */
	ಆದರೆ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_ಸ್ಥಿತಿ, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ಆಗ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_ಸ್ಥಿತಿ, 0) == -1) {
			ಆದರೆ (errno == EINTR)
				ಮುಂದುವರಿ;
			ಹಿಂತಿರುಗಿ;
		}
	}
	ಆದರೆ (sshpam_thread_ಸ್ಥಿತಿ == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (WIFSIGNALED(sshpam_thread_ಸ್ಥಿತಿ)) {
		ಆದರೆ (signal_is_crash(WTERMSIG(sshpam_thread_ಸ್ಥಿತಿ)))
			_exit(EXIT_ಮಗು_CRASH);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!WIFEXITED(sshpam_thread_ಸ್ಥಿತಿ))
		_exit(EXIT_ಮಗು_CRASH);
}

/* ARGSUSED */
ಸ್ಥಿರ ಶೂನ್ಯ
pthread_exit(ಶೂನ್ಯ *ಮೌಲ್ಯ)
{
	_exit(0);
}

/* ARGSUSED */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pthread_create(sp_pthread_t *thread, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *attr,
    ಶೂನ್ಯ *(*thread_ಆರಂಭ)(ಶೂನ್ಯ *), ಶೂನ್ಯ *arg)
{
	pid_t pid;
	ರಚನೆ pam_ctxt *ctx = arg;

	sshpam_thread_ಸ್ಥಿತಿ = -1;
	ಆಯ್ಕೆ ((pid = fork())) {
	ಸ್ಥಿತಿ -1:
		error("fork(): %s", strerror(errno));
		ಹಿಂತಿರುಗಿ errno;
	ಸ್ಥಿತಿ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_ಆರಂಭ(arg);
		_exit(1);
	ಪೂರ್ವನಿಯೋಜಿತ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		ಹಿಂತಿರುಗಿ (0);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ಹಿಂತಿರುಗಿ (kill(thread, SIGTERM));
}

/* ARGSUSED */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pthread_join(sp_pthread_t thread, ಶೂನ್ಯ **ಮೌಲ್ಯ)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆದರೆ (sshpam_thread_ಸ್ಥಿತಿ != -1)
		ಹಿಂತಿರುಗಿ (sshpam_thread_ಸ್ಥಿತಿ);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ಆಗ (waitpid(thread, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno == EINTR)
			ಮುಂದುವರಿ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ಹಿಂತಿರುಗಿ (ಸ್ಥಿತಿ_2);
}
#ಆದರೆ_ಅಂತ್ಯ


ಸ್ಥಿರ pam_handle_t *sshpam_handle = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *sshpam_initial_user;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_err = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_authenticated = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_session_open = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_cred_established = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_account_ಸ್ಥಿತಿ = -1;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshpam_maxtries_reached = 0;
ಸ್ಥಿರ ಅಕ್ಷರ **sshpam_env = ಖಾಲಿ;
ಸ್ಥಿರ Authctxt *sshpam_authctxt = ಖಾಲಿ;
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sshpam_password = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *sshpam_rhost = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *sshpam_laddr = ಖಾಲಿ;

/* Some PAM implementations don't implement this */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PAM_GETENVLIST
ಸ್ಥಿರ ಅಕ್ಷರ **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PAM_PUTENV
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pam_putenv(pam_handle_t *pamh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name_ಮೌಲ್ಯ)
{
	ಹಿಂತಿರುಗಿ PAM_SUCCESS;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_PAM_PUTENV */

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_password_change_required(ಪೂರ್ಣಾಂಕ reqd)
{
	ಬಾಹ್ಯ ರಚನೆ sshauthopt *auth_opts;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ saved_ಪೋರ್ಟ್, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ಆದರೆ (sshpam_authctxt == ಖಾಲಿ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ಆದರೆ (reqd) {
		saved_ಪೋರ್ಟ್ = auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (saved_ಪೋರ್ಟ್)
			auth_opts->permit_ಪೋರ್ಟ್_forwarding_flag = saved_ಪೋರ್ಟ್;
		ಆದರೆ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ಆದರೆ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ಸ್ಥಿರ ಶೂನ್ಯ
import_environments(ರಚನೆ sshbuf *b)
{
	ಅಕ್ಷರ *env;
	u_int n, i, ಅಂಕೆ_env;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UNSUPPORTED_POSIX_ಎಳೆಗಳು_HACK
	/* Import variables set by do_pam_account */
	ಆದರೆ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (n > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_ಸ್ಥಿತಿ = (ಪೂರ್ಣಾಂಕ)n;
	ಆದರೆ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ಆದರೆ ((r = sshbuf_get_u32(b, &ಅಂಕೆ_env)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (ಅಂಕೆ_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    ಅಂಕೆ_env);
	}
	sshpam_env = xcalloc(ಅಂಕೆ_env + 1, ಗಾತ್ರ(*sshpam_env));
	debug3("PAM: num env strings %u", ಅಂಕೆ_env);
	ಗಾಗಿ(i = 0; i < ಅಂಕೆ_env; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ಖಾಲಿ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[ಅಂಕೆ_env] = ಖಾಲಿ;

	/* Import PAM environment from subprocess */
	ಆದರೆ ((r = sshbuf_get_u32(b, &ಅಂಕೆ_env)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (ಅಂಕೆ_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    ಅಂಕೆ_env);
	}
	debug("PAM: num PAM env strings %u", ಅಂಕೆ_env);
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_env; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(b, &env, ಖಾಲಿ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ಆದರೆ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
			error("PAM: pam_putenv: %s",
			    pam_strerror(sshpam_handle, r));
		}
		/*
		 * XXX this possibly leaks env because it is not documented
		 * what pam_putenv() does with it. Does it copy it? Does it
		 * take ownership? We don't know, so it's safest just to leak.
		 */
	}
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Conversation function for authentication thread.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_thread_conv(ಪೂರ್ಣಾಂಕ n, sshpam_const ರಚನೆ pam_ಸಂದೇಶ **ಸಂದೇಶ,
    ರಚನೆ pam_response **resp, ಶೂನ್ಯ *ದತ್ತಾಂಶ)
{
	ರಚನೆ sshbuf *ಬಫರ್;
	ರಚನೆ pam_ctxt *ctxt;
	ರಚನೆ pam_response *ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r, i;
	u_char ಸ್ಥಿತಿ_2;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ಖಾಲಿ;

	ಆದರೆ (ದತ್ತಾಂಶ == ಖಾಲಿ) {
		error("PAM: conversation function passed a null context");
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);
	}
	ctxt = ದತ್ತಾಂಶ;
	ಆದರೆ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);

	ಆದರೆ ((ಉತ್ತರ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(n, ಗಾತ್ರ(*ಉತ್ತರ))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ PAM_CONV_ERR;
	ಆದರೆ ((ಬಫರ್ = sshbuf_new()) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ಉತ್ತರ);
		ಹಿಂತಿರುಗಿ PAM_CONV_ERR;
	}

	ಗಾಗಿ (i = 0; i < n; ++i) {
		ಆಯ್ಕೆ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಸ್ಥಿತಿ PAM_PROMPT_ECHO_OFF:
		ಸ್ಥಿತಿ PAM_PROMPT_ECHO_ON:
			ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಆದರೆ (ssh_ಸಂದೇಶ_send(ctxt->pam_csock,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style), ಬಫರ್) == -1)
				ಹೋಗು fail;

			ಆದರೆ (ssh_ಸಂದೇಶ_recv(ctxt->pam_csock, ಬಫರ್) == -1)
				ಹೋಗು fail;
			ಆದರೆ ((r = sshbuf_get_u8(ಬಫರ್, &ಸ್ಥಿತಿ_2)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಆದರೆ (ಸ್ಥಿತಿ_2 != PAM_AUTHTOK)
				ಹೋಗು fail;
			ಆದರೆ ((r = sshbuf_get_cstring(ಬಫರ್,
			    &ಉತ್ತರ[i].resp, ಖಾಲಿ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PAM_ERROR_ಸಂದೇಶ:
		ಸ್ಥಿತಿ PAM_ಪಠ್ಯ_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style),
			       PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ));
			ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಆದರೆ (ssh_ಸಂದೇಶ_send(ctxt->pam_csock,
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style), ಬಫರ್) == -1)
				ಹೋಗು fail;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹೋಗು fail;
		}
		sshbuf_reset(ಬಫರ್);
	}
	sshbuf_free(ಬಫರ್);
	*resp = ಉತ್ತರ;
	ಹಿಂತಿರುಗಿ (PAM_SUCCESS);

 fail:
	ಗಾಗಿ(i = 0; i < n; i++) {
		ಬಿಡುಗಡೆ(ಉತ್ತರ[i].resp);
	}
	ಬಿಡುಗಡೆ(ಉತ್ತರ);
	sshbuf_free(ಬಫರ್);
	ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_pam_user(Authctxt *authctxt)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pam_user;

	ಆದರೆ (authctxt == ಖಾಲಿ || authctxt->pw == ಖಾಲಿ ||
	    authctxt->pw->pw_name == ಖಾಲಿ)
		fatal_f("PAM authctxt user not initialized");

	ಆದರೆ ((sshpam_err = pam_get_ಅಂಶ(sshpam_handle, PAM_USER,
	    (sshpam_const ಶೂನ್ಯ **) &pam_user)) != PAM_SUCCESS)
		ಹಿಂತಿರುಗಿ sshpam_err;

	ಆದರೆ (pam_user == ಖಾಲಿ) {
		debug("PAM error: PAM_USER is NULL");
		ಹಿಂತಿರುಗಿ PAM_USER_UNKNOWN;
	}

	ಆದರೆ (sshpam_initial_user == ಖಾಲಿ)
		fatal_f("internal error: sshpam_initial_user NULL");
	ಆದರೆ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		ಹಿಂತಿರುಗಿ PAM_USER_UNKNOWN;
	}
	ಹಿಂತಿರುಗಿ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ಸ್ಥಿರ ಶೂನ್ಯ *
sshpam_thread(ಶೂನ್ಯ *ctxtp)
{
	ರಚನೆ pam_ctxt *ctxt = ctxtp;
	ರಚನೆ sshbuf *ಬಫರ್ = ಖಾಲಿ;
	ರಚನೆ pam_conv sshpam_conv;
	ಪೂರ್ಣಾಂಕ r, flags = (options.permit_ಖಾಲಿಗಳು_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UNSUPPORTED_POSIX_ಎಳೆಗಳು_HACK
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಅಕ್ಷರ **env_from_pam;
	u_int i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pam_user;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **ptr_pam_user = &pam_user;
	ಅಕ್ಷರ *tz = getenv("TZ");

	sshpam_err = pam_get_ಅಂಶ(sshpam_handle, PAM_USER,
	    (sshpam_const ಶೂನ್ಯ **)ptr_pam_user);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		ಹೋಗು auth_fail;

	environ[0] = ಖಾಲಿ;
	ಆದರೆ (tz != ಖಾಲಿ)
		ಆದರೆ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ಆದರೆ (sshpam_authctxt != ಖಾಲಿ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#ಆದರೆ_ಅಂತ್ಯ

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ಆದರೆ (sshpam_authctxt == ಖಾಲಿ)
		fatal_f("PAM authctxt not initialized");

	ಆದರೆ ((ಬಫರ್ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_CONV,
	    (ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)&sshpam_conv);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		ಹೋಗು auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ಆದರೆ (sshpam_err == PAM_MAXTRIES)
		sshpam_ಗಣ_maxtries_reached(1);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		ಹೋಗು auth_fail;
	ಆದರೆ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		ಹೋಗು auth_fail;

	ಆದರೆ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		ಹೋಗು auth_fail;
	}
	ಆದರೆ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ಆದರೆ (sshpam_err != PAM_SUCCESS)
			ಹೋಗು auth_fail;
		sshpam_password_change_required(0);
	}

	ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UNSUPPORTED_POSIX_ಎಳೆಗಳು_HACK
	/* Export variables set by do_pam_account */
	ಆದರೆ ((r = sshbuf_put_u32(ಬಫರ್, sshpam_account_ಸ್ಥಿತಿ)) != 0 ||
	    (r = sshbuf_put_u32(ಬಫರ್, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	ಗಾಗಿ (i = 0; environ[i] != ಖಾಲಿ; i++) {
		/*ಎಣಿಕೆ*/
		ಆದರೆ (i > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			fatal_f("too many environment strings");
	}
	ಆದರೆ ((r = sshbuf_put_u32(ಬಫರ್, i)) != 0)
		fatal_fr(r, "buffer error");
	ಗಾಗಿ (i = 0; environ[i] != ಖಾಲಿ; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	ಗಾಗಿ (i = 0; env_from_pam != ಖಾಲಿ && env_from_pam[i] != ಖಾಲಿ; i++) {
		/*ಎಣಿಕೆ*/
		ಆದರೆ (i > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			fatal_f("too many PAM environment strings");
	}
	ಆದರೆ ((r = sshbuf_put_u32(ಬಫರ್, i)) != 0)
		fatal_fr(r, "buffer error");
	ಗಾಗಿ (i = 0; env_from_pam != ಖಾಲಿ && env_from_pam[i] != ಖಾಲಿ; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#ಆದರೆ_ಅಂತ್ಯ /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_ಸಂದೇಶ_send(ctxt->pam_csock, sshpam_err, ಬಫರ್);
	sshbuf_free(ಬಫರ್);
	pthread_exit(ಖಾಲಿ);

 auth_fail:
	ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ಆದರೆ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, ಬಫರ್);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshpam_maxtries_reached)
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_MAXTRIES, ಬಫರ್);
	ಇಲ್ಲದಿದ್ದರೆ
		ssh_ಸಂದೇಶ_send(ctxt->pam_csock, PAM_AUTH_ERR, ಬಫರ್);
	sshbuf_free(ಬಫರ್);
	pthread_exit(ಖಾಲಿ);

	ಹಿಂತಿರುಗಿ (ಖಾಲಿ); /* Avoid warning for non-pthread case */
}

ಶೂನ್ಯ
sshpam_thread_cleanup(ಶೂನ್ಯ)
{
	ರಚನೆ pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ಆದರೆ (ctxt != ಖಾಲಿ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ಖಾಲಿ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, ಗಾತ್ರ(*ctxt));
		cleanup_ctxt = ಖಾಲಿ;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_null_conv(ಪೂರ್ಣಾಂಕ n, sshpam_const ರಚನೆ pam_ಸಂದೇಶ **ಸಂದೇಶ,
    ರಚನೆ pam_response **resp, ಶೂನ್ಯ *ದತ್ತಾಂಶ)
{
	debug3_f("PAM: entering, %d messages", n);
	ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ರಚನೆ pam_conv null_conv = { sshpam_null_conv, ಖಾಲಿ };

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_store_conv(ಪೂರ್ಣಾಂಕ n, sshpam_const ರಚನೆ pam_ಸಂದೇಶ **ಸಂದೇಶ,
    ರಚನೆ pam_response **resp, ಶೂನ್ಯ *ದತ್ತಾಂಶ)
{
	ರಚನೆ pam_response *ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ಖಾಲಿ;

	ಆದರೆ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);

	ಆದರೆ ((ಉತ್ತರ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(n, ಗಾತ್ರ(*ಉತ್ತರ))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);

	ಗಾಗಿ (i = 0; i < n; ++i) {
		ಆಯ್ಕೆ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಸ್ಥಿತಿ PAM_ERROR_ಸಂದೇಶ:
		ಸ್ಥಿತಿ PAM_ಪಠ್ಯ_INFO:
			ಆದರೆ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ಉತ್ತರ[i].resp_retcode = PAM_SUCCESS;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹೋಗು fail;
		}
	}
	*resp = ಉತ್ತರ;
	ಹಿಂತಿರುಗಿ (PAM_SUCCESS);

 fail:
	ಗಾಗಿ(i = 0; i < n; i++) {
		ಬಿಡುಗಡೆ(ಉತ್ತರ[i].resp);
	}
	ಬಿಡುಗಡೆ(ಉತ್ತರ);
	ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ರಚನೆ pam_conv store_conv = { sshpam_store_conv, ಖಾಲಿ };

ಶೂನ್ಯ
sshpam_cleanup(ಶೂನ್ಯ)
{
	ಆದರೆ (sshpam_handle == ಖಾಲಿ || !mm_is_monitor())
		ಹಿಂತಿರುಗಿ;
	debug("PAM: cleanup");
	pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_CONV, (ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)&null_conv);
	ಆದರೆ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ಆದರೆ (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_ಕೊನೆ(sshpam_handle, sshpam_err);
	sshpam_handle = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(sshpam_initial_user);
	sshpam_initial_user = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_init(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user = authctxt->user;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (options.pam_service_name == ಖಾಲಿ)
		fatal_f("internal error: NULL PAM service name");
#ಆದರೆ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_ಗಾತ್ರ)
	/* Protect buggy PAM implementations from excessively long usernames */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(user) >= PAM_MAX_RESP_ಗಾತ್ರ)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (sshpam_handle == ಖಾಲಿ && ssh == ಖಾಲಿ)
		fatal("%s: called initially with no packet context", __func__);
	ಆದರೆ (sshpam_handle != ಖಾಲಿ) {
		/* We already have a PAM context; check if the user matches */
		ಆದರೆ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		ಹಿಂತಿರುಗಿ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_ಆರಂಭ(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ಆದರೆ (sshpam_err != PAM_SUCCESS) {
		pam_ಕೊನೆ(sshpam_handle, sshpam_err);
		sshpam_handle = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಆದರೆ (ssh != ಖಾಲಿ && sshpam_rhost == ಖಾಲಿ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_ಒಳ(ssh));
	}
	ಆದರೆ (sshpam_rhost != ಖಾಲಿ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ಆದರೆ (sshpam_err != PAM_SUCCESS) {
			pam_ಕೊನೆ(sshpam_handle, sshpam_err);
			sshpam_handle = ಖಾಲಿ;
			ಹಿಂತಿರುಗಿ (-1);
		}
	}
	ಆದರೆ (ssh != ಖಾಲಿ && sshpam_laddr != ಖಾಲಿ) {
		ಅಕ್ಷರ *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
		    sshpam_laddr, ssh_local_ಪೋರ್ಟ್(ssh));
		ಆದರೆ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		ಬಿಡುಗಡೆ(conninfo);
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_TTY, "ssh");
	ಆದರೆ (sshpam_err != PAM_SUCCESS) {
		pam_ಕೊನೆ(sshpam_handle, sshpam_err);
		sshpam_handle = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ (-1);
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
expose_authinfo(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *caller)
{
	ಅಕ್ಷರ *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ಆದರೆ (sshpam_authctxt->session_info == ಖಾಲಿ)
		auth_info = xstrdup("");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	ಬಿಡುಗಡೆ(auth_info);
}

ಸ್ಥಿರ ಶೂನ್ಯ *
sshpam_init_ctx(Authctxt *authctxt)
{
	ರಚನೆ pam_ctxt *ctxt;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ಆದರೆ (!options.use_pam || sshpam_account_ಸ್ಥಿತಿ == 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* Initialize PAM */
	ಆದರೆ (sshpam_init(ಖಾಲಿ, authctxt) == -1) {
		error("PAM: initialization failed");
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, ಗಾತ್ರ *ctxt);

	/* Start the authentication thread */
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		ಬಿಡುಗಡೆ(ctxt);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	ಫಲಿತಾಂಶ = pthread_create(&ctxt->pam_thread, ಖಾಲಿ, sshpam_thread, ctxt);
	ಆದರೆ (ಫಲಿತಾಂಶ != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(ಫಲಿತಾಂಶ));
		close(socks[0]);
		close(socks[1]);
		ಬಿಡುಗಡೆ(ctxt);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	cleanup_ctxt = ctxt;
	ಹಿಂತಿರುಗಿ (ctxt);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_query(ಶೂನ್ಯ *ctx, ಅಕ್ಷರ **name, ಅಕ್ಷರ **info,
    u_int *ಅಂಕೆ, ಅಕ್ಷರ ***prompts, u_int **echo_on)
{
	ರಚನೆ sshbuf *ಬಫರ್;
	ರಚನೆ pam_ctxt *ctxt = ctx;
	u_char type;
	ಅಕ್ಷರ *ಸಂದೇಶ;
	ಗಾತ್ರ_t mlen, nmesg = 0;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ ((ಬಫರ್ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ಖಾಲಿ;
	*ಅಂಕೆ = 0;
	ctxt->pam_ಮುಗಿದ = SshPamNone;

	ಆಗ (ssh_ಸಂದೇಶ_recv(ctxt->pam_psock, ಬಫರ್) == 0) {
		ಆದರೆ (++nmesg > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
			fatal_f("too many query messages");
		ಆದರೆ ((r = sshbuf_get_u8(ಬಫರ್, &type)) != 0 ||
		    (r = sshbuf_get_cstring(ಬಫರ್, &ಸಂದೇಶ, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ PAM_PROMPT_ECHO_ON:
		ಸ್ಥಿತಿ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, ಗಾತ್ರ(ಅಕ್ಷರ *));
			*echo_on = xcalloc(1, ಗಾತ್ರ(u_int));
			(*prompts)[0] = ಸಂದೇಶ;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*ಅಂಕೆ = 1;
			sshbuf_free(ಬಫರ್);
			ಹಿಂತಿರುಗಿ (0);
		ಸ್ಥಿತಿ PAM_ERROR_ಸಂದೇಶ:
		ಸ್ಥಿತಿ PAM_ಪಠ್ಯ_INFO:
			ಬಿಡುಗಡೆ(*info);
			*info = ಸಂದೇಶ; /* transfer ownership */
			ಸಂದೇಶ = ಖಾಲಿ;
			ctxt->pam_ಮುಗಿದ = SshPamAgain;
			sshbuf_free(ಬಫರ್);
			ಹಿಂತಿರುಗಿ (0);
		ಸ್ಥಿತಿ PAM_ACCT_EXPIRED:
		ಸ್ಥಿತಿ PAM_MAXTRIES:
			ಆದರೆ (type == PAM_ACCT_EXPIRED)
				sshpam_account_ಸ್ಥಿತಿ = 0;
			ಆದರೆ (type == PAM_MAXTRIES)
				sshpam_ಗಣ_maxtries_reached(1);
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ PAM_SUCCESS:
			ಆದರೆ (type == PAM_SUCCESS) {
				ಆದರೆ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_ಬೇರು_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(ಬಫರ್);
				ctxt->pam_ಮುಗಿದ = SshPamAuthenticated;
				ಬಿಡುಗಡೆ(ಸಂದೇಶ);
				sshbuf_free(ಬಫರ್);
				ಹಿಂತಿರುಗಿ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", ಸಂದೇಶ,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಬಿಡುಗಡೆ(ಸಂದೇಶ);
			ctxt->pam_ಮುಗಿದ = SshPamError;
			sshbuf_free(ಬಫರ್);
			ಹಿಂತಿರುಗಿ (-1);
		}
	}
	sshbuf_free(ಬಫರ್);
	ಹಿಂತಿರುಗಿ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
fake_password(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *wire_password)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ junk[] = "\b\n\r\177INCORRECT";
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಗಾತ್ರ_t i, l = wire_password != ಖಾಲಿ ? ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(wire_password) : 0;

	ಆದರೆ (l >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal_f("password length too long: %zu", l);

	ret = ಸ್ಮರಣೆ_ಕೊಡು(l + 1);
	ಆದರೆ (ret == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಗಾಗಿ (i = 0; i < l; i++)
		ret[i] = junk[i % (ಗಾತ್ರ(junk) - 1)];
	ret[i] = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_respond(ಶೂನ್ಯ *ctx, u_int ಅಂಕೆ, ಅಕ್ಷರ **resp)
{
	ರಚನೆ sshbuf *ಬಫರ್;
	ರಚನೆ pam_ctxt *ctxt = ctx;
	ಅಕ್ಷರ *fake;
	ಪೂರ್ಣಾಂಕ r;

	debug2_f("PAM: entering, %u responses", ಅಂಕೆ);
	ಆಯ್ಕೆ (ctxt->pam_ಮುಗಿದ) {
	ಸ್ಥಿತಿ SshPamAuthenticated:
		sshpam_authenticated = 1;
		ಹಿಂತಿರುಗಿ (0);
	ಸ್ಥಿತಿ SshPamNone:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SshPamAgain:
		ಹಿಂತಿರುಗಿ 1;	/* KbdintResultAgain */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (ಅಂಕೆ != 1) {
		error("PAM: expected one response, got %u", ಅಂಕೆ);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ ((ಬಫರ್ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_ಬೇರು_login == PERMIT_YES)) {
		ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ಇಲ್ಲದಿದ್ದರೆ {
		fake = fake_password(*resp);
		ಆದರೆ ((r = sshbuf_put_cstring(ಬಫರ್, fake)) != 0)
			fatal_fr(r, "buffer error");
		ಬಿಡುಗಡೆ(fake);
	}
	ಆದರೆ (ssh_ಸಂದೇಶ_send(ctxt->pam_psock, PAM_AUTHTOK, ಬಫರ್) == -1) {
		sshbuf_free(ಬಫರ್);
		ಹಿಂತಿರುಗಿ (-1);
	}
	sshbuf_free(ಬಫರ್);
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshpam_free_ctx(ಶೂನ್ಯ *ctxtp)
{
	ರಚನೆ pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	ಬಿಡುಗಡೆ(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

ಪೂರ್ಣಾಂಕ
sshpam_priv_kbdint_authdone(ಶೂನ್ಯ *ctxtp)
{
	ರಚನೆ pam_ctxt *ctxt = ctxtp;

	ಹಿಂತಿರುಗಿ ctxt->pam_ಮುಗಿದ == SshPamAuthenticated;
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
ಆರಂಭ_pam(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ಆದರೆ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ಆದರೆ (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

ಶೂನ್ಯ
ಮುಕ್ತಾಯ_pam(ಶೂನ್ಯ)
{
	sshpam_cleanup();
}


u_int
do_pam_account(ಶೂನ್ಯ)
{
	debug_f("called");
	ಆದರೆ (sshpam_account_ಸ್ಥಿತಿ != -1)
		ಹಿಂತಿರುಗಿ (sshpam_account_ಸ್ಥಿತಿ);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ಆದರೆ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_ಸ್ಥಿತಿ = 0;
		ಹಿಂತಿರುಗಿ (sshpam_account_ಸ್ಥಿತಿ);
	}

	ಆದರೆ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_ಸ್ಥಿತಿ = 1;
	ಹಿಂತಿರುಗಿ (sshpam_account_ಸ್ಥಿತಿ);
}

ಶೂನ್ಯ
do_pam_setcred(ಶೂನ್ಯ)
{
	sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_CONV,
	    (ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)&store_conv);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ಆದರೆ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ಇಲ್ಲದಿದ್ದರೆ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

ಶೂನ್ಯ
do_pam_session(ರಚನೆ ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_CONV,
	    (ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)&store_conv);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ಆದರೆ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ಇಲ್ಲದಿದ್ದರೆ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

ಪೂರ್ಣಾಂಕ
is_pam_session_open(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
ಪೂರ್ಣಾಂಕ
do_pam_putenv(ಅಕ್ಷರ *name, ಅಕ್ಷರ *ಮೌಲ್ಯ)
{
	ಪೂರ್ಣಾಂಕ ret = 1;
	ಅಕ್ಷರ *compound;
	ಗಾತ್ರ_t len;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name) + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮೌಲ್ಯ) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, ಮೌಲ್ಯ);
	ret = pam_putenv(sshpam_handle, compound);
	ಬಿಡುಗಡೆ(compound);

	ಹಿಂತಿರುಗಿ (ret);
}

ಅಕ್ಷರ **
fetch_pam_ಮಗು_environment(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ sshpam_env;
}

ಅಕ್ಷರ **
fetch_pam_environment(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ (pam_getenvlist(sshpam_handle));
}

ಶೂನ್ಯ
free_pam_environment(ಅಕ್ಷರ **env)
{
	ಅಕ್ಷರ **envp;

	ಆದರೆ (env == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ (envp = env; *envp; envp++)
		ಬಿಡುಗಡೆ(*envp);
	ಬಿಡುಗಡೆ(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshpam_passwd_conv(ಪೂರ್ಣಾಂಕ n, sshpam_const ರಚನೆ pam_ಸಂದೇಶ **ಸಂದೇಶ,
    ರಚನೆ pam_response **resp, ಶೂನ್ಯ *ದತ್ತಾಂಶ)
{
	ರಚನೆ pam_response *ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r, i;
	ಗಾತ್ರ_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ಖಾಲಿ;

	ಆದರೆ (n <= 0 || n > PAM_MAX_ಅಂಕೆ_ಸಂದೇಶ)
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);

	ಆದರೆ ((ಉತ್ತರ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(n, ಗಾತ್ರ(*ಉತ್ತರ))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);

	ಗಾಗಿ (i = 0; i < n; ++i) {
		ಆಯ್ಕೆ (PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ_style)) {
		ಸ್ಥಿತಿ PAM_PROMPT_ECHO_OFF:
			ಆದರೆ (sshpam_password == ಖಾಲಿ)
				ಹೋಗು fail;
			ಆದರೆ ((ಉತ್ತರ[i].resp = strdup(sshpam_password)) == ಖಾಲಿ)
				ಹೋಗು fail;
			ಉತ್ತರ[i].resp_retcode = PAM_SUCCESS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PAM_ERROR_ಸಂದೇಶ:
		ಸ್ಥಿತಿ PAM_ಪಠ್ಯ_INFO:
			len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ));
			ಆದರೆ (len > 0) {
				ಆದರೆ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_ಸಂದೇಶ_MEMBER(ಸಂದೇಶ, i, ಸಂದೇಶ))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ಆದರೆ ((ಉತ್ತರ[i].resp = strdup("")) == ಖಾಲಿ)
				ಹೋಗು fail;
			ಉತ್ತರ[i].resp_retcode = PAM_SUCCESS;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹೋಗು fail;
		}
	}
	*resp = ಉತ್ತರ;
	ಹಿಂತಿರುಗಿ (PAM_SUCCESS);

 fail:
	ಗಾಗಿ(i = 0; i < n; i++) {
		ಬಿಡುಗಡೆ(ಉತ್ತರ[i].resp);
	}
	ಬಿಡುಗಡೆ(ಉತ್ತರ);
	ಹಿಂತಿರುಗಿ (PAM_CONV_ERR);
}

ಸ್ಥಿರ ರಚನೆ pam_conv passwd_conv = { sshpam_passwd_conv, ಖಾಲಿ };

/*
 * Attempt password authentication via PAM
 */
ಪೂರ್ಣಾಂಕ
sshpam_auth_passwd(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	ಪೂರ್ಣಾಂಕ flags = (options.permit_ಖಾಲಿಗಳು_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	ಅಕ್ಷರ *fake = ಖಾಲಿ;

	ಆದರೆ (!options.use_pam || sshpam_handle == ಖಾಲಿ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ಆದರೆ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_ಬೇರು_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_ಗಣ_ಅಂಶ(sshpam_handle, PAM_CONV,
	    (ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *)&passwd_conv);
	ಆದರೆ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(fake);
	ಆದರೆ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ಆದರೆ (sshpam_err == PAM_MAXTRIES)
		sshpam_ಗಣ_maxtries_reached(1);
	ಆದರೆ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		ಹಿಂತಿರುಗಿ 0;
	}
}

ಪೂರ್ಣಾಂಕ
sshpam_get_maxtries_reached(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ sshpam_maxtries_reached;
}

ಶೂನ್ಯ
sshpam_ಗಣ_maxtries_reached(ಪೂರ್ಣಾಂಕ reached)
{
	ಆದರೆ (reached == 0 || sshpam_maxtries_reached)
		ಹಿಂತಿರುಗಿ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */
