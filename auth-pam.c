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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
#ਜੇ defined(HAVE_SECURITY_PAM_APPL_H)
#ਅਨ੍ਤਰ੍ਭਾਵ <security/pam_appl.h>
#ਜਾਂਜੇ defined (HAVE_PAM_PAM_APPL_H)
#ਅਨ੍ਤਰ੍ਭਾਵ <pam/pam_appl.h>
#ਜੇ_ਅੰਤ

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#ਨਹੀਂਤਾਂ
# define sshpam_const	ਅਚਲ	/* LinuxPAM, OpenPAM, AIX */
#ਜੇ_ਅੰਤ

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PAM_SUN_CODEBASE
# define PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, n, member) ((*(ਸੁਨੇਹਾ))[(n)].member)
#ਨਹੀਂਤਾਂ
# define PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, n, member) ((ਸੁਨੇਹਾ)[(n)]->member)
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-pam.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"

ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ u_int utmp_len;

/* so we don't silently change behaviour */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_POSIX_ਧਾਗੇ
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#ਜੇ_ਅੰਤ

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ UNSUPPORTED_POSIX_ਧਾਗੇ_HACK
#ਅਨ੍ਤਰ੍ਭਾਵ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ pthread_t sp_pthread_t;
#ਨਹੀਂਤਾਂ
ਕਿਸਮਪਰਿਭਾਸ਼ਾ pid_t sp_pthread_t;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ pthread_exit	fake_pthread_exit
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ pthread_create	fake_pthread_create
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ pthread_cancel	fake_pthread_cancel
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ pthread_join	fake_pthread_join
#ਜੇ_ਅੰਤ

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ Ssh_Pam_ਪੂਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SshPamError -1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SshPamNone 0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SshPamAuthenticated 1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SshPamAgain 2

ਬਣਤਰ pam_ctxt {
	sp_pthread_t	 pam_thread;
	ਪੂਰਨ		 pam_psock;
	ਪੂਰਨ		 pam_csock;
	Ssh_Pam_ਪੂਰਾ	 pam_ਪੂਰਾ;
};

ਸਥਿਰ ਖਾਲੀ sshpam_free_ctx(ਖਾਲੀ *);
ਸਥਿਰ ਬਣਤਰ pam_ctxt *cleanup_ctxt;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UNSUPPORTED_POSIX_ਧਾਗੇ_HACK
/*
 * Simulate threads with processes.
 */

ਸਥਿਰ ਪੂਰਨ sshpam_thread_ਸਥਿਤੀ = -1;
ਸਥਿਰ sshsig_t sshpam_oldsig;

ਸਥਿਰ ਖਾਲੀ
sshpam_sigchld_handler(ਪੂਰਨ sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ (cleanup_ctxt == ਨਿਰਾ)
		ਵਾਪਸ;	/* handler called after PAM cleanup, shouldn't happen */
	ਜੇ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_ਸਥਿਤੀ, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ਜਦੋਂ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_ਸਥਿਤੀ, 0) == -1) {
			ਜੇ (errno == EINTR)
				ਜਾਰੀ;
			ਵਾਪਸ;
		}
	}
	ਜੇ (sshpam_thread_ਸਥਿਤੀ == -1)
		ਵਾਪਸ;
	ਜੇ (WIFSIGNALED(sshpam_thread_ਸਥਿਤੀ)) {
		ਜੇ (signal_is_crash(WTERMSIG(sshpam_thread_ਸਥਿਤੀ)))
			_exit(EXIT_ਬੱਚਾ_CRASH);
	} ਨਹੀਂਤਾਂ ਜੇ (!WIFEXITED(sshpam_thread_ਸਥਿਤੀ))
		_exit(EXIT_ਬੱਚਾ_CRASH);
}

/* ARGSUSED */
ਸਥਿਰ ਖਾਲੀ
pthread_exit(ਖਾਲੀ *ਮੁੱਲ)
{
	_exit(0);
}

/* ARGSUSED */
ਸਥਿਰ ਪੂਰਨ
pthread_create(sp_pthread_t *thread, ਅਚਲ ਖਾਲੀ *attr,
    ਖਾਲੀ *(*thread_ਸ਼ੁਰੂ)(ਖਾਲੀ *), ਖਾਲੀ *arg)
{
	pid_t pid;
	ਬਣਤਰ pam_ctxt *ctx = arg;

	sshpam_thread_ਸਥਿਤੀ = -1;
	ਚੋਣ ((pid = fork())) {
	ਹਾਲਤ -1:
		error("fork(): %s", strerror(errno));
		ਵਾਪਸ errno;
	ਹਾਲਤ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_ਸ਼ੁਰੂ(arg);
		_exit(1);
	ਮੂਲ:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		ਵਾਪਸ (0);
	}
}

ਸਥਿਰ ਪੂਰਨ
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ਵਾਪਸ (kill(thread, SIGTERM));
}

/* ARGSUSED */
ਸਥਿਰ ਪੂਰਨ
pthread_join(sp_pthread_t thread, ਖਾਲੀ **ਮੁੱਲ)
{
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜੇ (sshpam_thread_ਸਥਿਤੀ != -1)
		ਵਾਪਸ (sshpam_thread_ਸਥਿਤੀ);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ਜਦੋਂ (waitpid(thread, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno == EINTR)
			ਜਾਰੀ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	ਵਾਪਸ (ਸਥਿਤੀ);
}
#ਜੇ_ਅੰਤ


ਸਥਿਰ pam_handle_t *sshpam_handle = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *sshpam_initial_user;
ਸਥਿਰ ਪੂਰਨ sshpam_err = 0;
ਸਥਿਰ ਪੂਰਨ sshpam_authenticated = 0;
ਸਥਿਰ ਪੂਰਨ sshpam_session_open = 0;
ਸਥਿਰ ਪੂਰਨ sshpam_cred_established = 0;
ਸਥਿਰ ਪੂਰਨ sshpam_account_ਸਥਿਤੀ = -1;
ਸਥਿਰ ਪੂਰਨ sshpam_maxtries_reached = 0;
ਸਥਿਰ ਅੱਖਰ **sshpam_env = ਨਿਰਾ;
ਸਥਿਰ Authctxt *sshpam_authctxt = ਨਿਰਾ;
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *sshpam_password = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *sshpam_rhost = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *sshpam_laddr = ਨਿਰਾ;

/* Some PAM implementations don't implement this */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PAM_GETENVLIST
ਸਥਿਰ ਅੱਖਰ **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 ਵਾਪਸ ਨਿਰਾ;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PAM_PUTENV
ਸਥਿਰ ਪੂਰਨ
pam_putenv(pam_handle_t *pamh, ਅਚਲ ਅੱਖਰ *name_ਮੁੱਲ)
{
	ਵਾਪਸ PAM_SUCCESS;
}
#ਜੇ_ਅੰਤ /* HAVE_PAM_PUTENV */

ਸਥਿਰ ਖਾਲੀ
sshpam_password_change_required(ਪੂਰਨ reqd)
{
	ਬਾਹਰੀ ਬਣਤਰ sshauthopt *auth_opts;
	ਸਥਿਰ ਪੂਰਨ saved_ਪੋਰਟ, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	ਜੇ (sshpam_authctxt == ਨਿਰਾ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	ਜੇ (reqd) {
		saved_ਪੋਰਟ = auth_opts->permit_ਪੋਰਟ_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_ਪੋਰਟ_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (saved_ਪੋਰਟ)
			auth_opts->permit_ਪੋਰਟ_forwarding_flag = saved_ਪੋਰਟ;
		ਜੇ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		ਜੇ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
ਸਥਿਰ ਖਾਲੀ
import_environments(ਬਣਤਰ sshbuf *b)
{
	ਅੱਖਰ *env;
	u_int n, i, ਅੰਕ_env;
	ਪੂਰਨ r;

	debug3_f("entering");

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UNSUPPORTED_POSIX_ਧਾਗੇ_HACK
	/* Import variables set by do_pam_account */
	ਜੇ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (n > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_ਸਥਿਤੀ = (ਪੂਰਨ)n;
	ਜੇ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	ਜੇ ((r = sshbuf_get_u32(b, &ਅੰਕ_env)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (ਅੰਕ_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    ਅੰਕ_env);
	}
	sshpam_env = xcalloc(ਅੰਕ_env + 1, ਆਕਾਰ(*sshpam_env));
	debug3("PAM: num env strings %u", ਅੰਕ_env);
	ਲਈ(i = 0; i < ਅੰਕ_env; i++) {
		ਜੇ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ਨਿਰਾ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[ਅੰਕ_env] = ਨਿਰਾ;

	/* Import PAM environment from subprocess */
	ਜੇ ((r = sshbuf_get_u32(b, &ਅੰਕ_env)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (ਅੰਕ_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    ਅੰਕ_env);
	}
	debug("PAM: num PAM env strings %u", ਅੰਕ_env);
	ਲਈ (i = 0; i < ਅੰਕ_env; i++) {
		ਜੇ ((r = sshbuf_get_cstring(b, &env, ਨਿਰਾ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		ਜੇ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
			error("PAM: pam_putenv: %s",
			    pam_strerror(sshpam_handle, r));
		}
		/*
		 * XXX this possibly leaks env because it is not documented
		 * what pam_putenv() does with it. Does it copy it? Does it
		 * take ownership? We don't know, so it's safest just to leak.
		 */
	}
#ਜੇ_ਅੰਤ
}

/*
 * Conversation function for authentication thread.
 */
ਸਥਿਰ ਪੂਰਨ
sshpam_thread_conv(ਪੂਰਨ n, sshpam_const ਬਣਤਰ pam_ਸੁਨੇਹਾ **ਸੁਨੇਹਾ,
    ਬਣਤਰ pam_response **resp, ਖਾਲੀ *ਅੰਕੜੇ)
{
	ਬਣਤਰ sshbuf *ਬਫਰ;
	ਬਣਤਰ pam_ctxt *ctxt;
	ਬਣਤਰ pam_response *ਜਵਾਬ;
	ਪੂਰਨ r, i;
	u_char ਸਥਿਤੀ;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ਨਿਰਾ;

	ਜੇ (ਅੰਕੜੇ == ਨਿਰਾ) {
		error("PAM: conversation function passed a null context");
		ਵਾਪਸ (PAM_CONV_ERR);
	}
	ctxt = ਅੰਕੜੇ;
	ਜੇ (n <= 0 || n > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ)
		ਵਾਪਸ (PAM_CONV_ERR);

	ਜੇ ((ਜਵਾਬ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(n, ਆਕਾਰ(*ਜਵਾਬ))) == ਨਿਰਾ)
		ਵਾਪਸ PAM_CONV_ERR;
	ਜੇ ((ਬਫਰ = sshbuf_new()) == ਨਿਰਾ) {
		ਮੁਕਤ(ਜਵਾਬ);
		ਵਾਪਸ PAM_CONV_ERR;
	}

	ਲਈ (i = 0; i < n; ++i) {
		ਚੋਣ (PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style)) {
		ਹਾਲਤ PAM_PROMPT_ECHO_OFF:
		ਹਾਲਤ PAM_PROMPT_ECHO_ON:
			ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ,
			    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ਜੇ (ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock,
			    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style), ਬਫਰ) == -1)
				ਜਾਓ fail;

			ਜੇ (ssh_ਸੁਨੇਹਾ_recv(ctxt->pam_csock, ਬਫਰ) == -1)
				ਜਾਓ fail;
			ਜੇ ((r = sshbuf_get_u8(ਬਫਰ, &ਸਥਿਤੀ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ਜੇ (ਸਥਿਤੀ != PAM_AUTHTOK)
				ਜਾਓ fail;
			ਜੇ ((r = sshbuf_get_cstring(ਬਫਰ,
			    &ਜਵਾਬ[i].resp, ਨਿਰਾ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ਰੋਕੋ;
		ਹਾਲਤ PAM_ERROR_ਸੁਨੇਹਾ:
		ਹਾਲਤ PAM_ਪਾਠ_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style),
			       PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ));
			ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ,
			    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ਜੇ (ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock,
			    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style), ਬਫਰ) == -1)
				ਜਾਓ fail;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਓ fail;
		}
		sshbuf_reset(ਬਫਰ);
	}
	sshbuf_free(ਬਫਰ);
	*resp = ਜਵਾਬ;
	ਵਾਪਸ (PAM_SUCCESS);

 fail:
	ਲਈ(i = 0; i < n; i++) {
		ਮੁਕਤ(ਜਵਾਬ[i].resp);
	}
	ਮੁਕਤ(ਜਵਾਬ);
	sshbuf_free(ਬਫਰ);
	ਵਾਪਸ (PAM_CONV_ERR);
}

ਸਥਿਰ ਪੂਰਨ
check_pam_user(Authctxt *authctxt)
{
	ਅਚਲ ਅੱਖਰ *pam_user;

	ਜੇ (authctxt == ਨਿਰਾ || authctxt->pw == ਨਿਰਾ ||
	    authctxt->pw->pw_name == ਨਿਰਾ)
		fatal_f("PAM authctxt user not initialized");

	ਜੇ ((sshpam_err = pam_get_ਵਸਤੂ(sshpam_handle, PAM_USER,
	    (sshpam_const ਖਾਲੀ **) &pam_user)) != PAM_SUCCESS)
		ਵਾਪਸ sshpam_err;

	ਜੇ (pam_user == ਨਿਰਾ) {
		debug("PAM error: PAM_USER is NULL");
		ਵਾਪਸ PAM_USER_UNKNOWN;
	}

	ਜੇ (sshpam_initial_user == ਨਿਰਾ)
		fatal_f("internal error: sshpam_initial_user NULL");
	ਜੇ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		ਵਾਪਸ PAM_USER_UNKNOWN;
	}
	ਵਾਪਸ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
ਸਥਿਰ ਖਾਲੀ *
sshpam_thread(ਖਾਲੀ *ctxtp)
{
	ਬਣਤਰ pam_ctxt *ctxt = ctxtp;
	ਬਣਤਰ sshbuf *ਬਫਰ = ਨਿਰਾ;
	ਬਣਤਰ pam_conv sshpam_conv;
	ਪੂਰਨ r, flags = (options.permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UNSUPPORTED_POSIX_ਧਾਗੇ_HACK
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਅੱਖਰ **env_from_pam;
	u_int i;
	ਅਚਲ ਅੱਖਰ *pam_user;
	ਅਚਲ ਅੱਖਰ **ptr_pam_user = &pam_user;
	ਅੱਖਰ *tz = getenv("TZ");

	sshpam_err = pam_get_ਵਸਤੂ(sshpam_handle, PAM_USER,
	    (sshpam_const ਖਾਲੀ **)ptr_pam_user);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		ਜਾਓ auth_fail;

	environ[0] = ਨਿਰਾ;
	ਜੇ (tz != ਨਿਰਾ)
		ਜੇ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	ਜੇ (sshpam_authctxt != ਨਿਰਾ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#ਜੇ_ਅੰਤ

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	ਜੇ (sshpam_authctxt == ਨਿਰਾ)
		fatal_f("PAM authctxt not initialized");

	ਜੇ ((ਬਫਰ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_CONV,
	    (ਅਚਲ ਖਾਲੀ *)&sshpam_conv);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		ਜਾਓ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	ਜੇ (sshpam_err == PAM_MAXTRIES)
		sshpam_ਸੈੱਟ_maxtries_reached(1);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		ਜਾਓ auth_fail;
	ਜੇ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		ਜਾਓ auth_fail;

	ਜੇ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		ਜਾਓ auth_fail;
	}
	ਜੇ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		ਜੇ (sshpam_err != PAM_SUCCESS)
			ਜਾਓ auth_fail;
		sshpam_password_change_required(0);
	}

	ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UNSUPPORTED_POSIX_ਧਾਗੇ_HACK
	/* Export variables set by do_pam_account */
	ਜੇ ((r = sshbuf_put_u32(ਬਫਰ, sshpam_account_ਸਥਿਤੀ)) != 0 ||
	    (r = sshbuf_put_u32(ਬਫਰ, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	ਲਈ (i = 0; environ[i] != ਨਿਰਾ; i++) {
		/*ਗਿਣਤੀ*/
		ਜੇ (i > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			fatal_f("too many environment strings");
	}
	ਜੇ ((r = sshbuf_put_u32(ਬਫਰ, i)) != 0)
		fatal_fr(r, "buffer error");
	ਲਈ (i = 0; environ[i] != ਨਿਰਾ; i++) {
		ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	ਲਈ (i = 0; env_from_pam != ਨਿਰਾ && env_from_pam[i] != ਨਿਰਾ; i++) {
		/*ਗਿਣਤੀ*/
		ਜੇ (i > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			fatal_f("too many PAM environment strings");
	}
	ਜੇ ((r = sshbuf_put_u32(ਬਫਰ, i)) != 0)
		fatal_fr(r, "buffer error");
	ਲਈ (i = 0; env_from_pam != ਨਿਰਾ && env_from_pam[i] != ਨਿਰਾ; i++) {
		ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#ਜੇ_ਅੰਤ /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock, sshpam_err, ਬਫਰ);
	sshbuf_free(ਬਫਰ);
	pthread_exit(ਨਿਰਾ);

 auth_fail:
	ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	ਜੇ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, ਬਫਰ);
	ਨਹੀਂਤਾਂ ਜੇ (sshpam_maxtries_reached)
		ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock, PAM_MAXTRIES, ਬਫਰ);
	ਨਹੀਂਤਾਂ
		ssh_ਸੁਨੇਹਾ_send(ctxt->pam_csock, PAM_AUTH_ERR, ਬਫਰ);
	sshbuf_free(ਬਫਰ);
	pthread_exit(ਨਿਰਾ);

	ਵਾਪਸ (ਨਿਰਾ); /* Avoid warning for non-pthread case */
}

ਖਾਲੀ
sshpam_thread_cleanup(ਖਾਲੀ)
{
	ਬਣਤਰ pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	ਜੇ (ctxt != ਨਿਰਾ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ਨਿਰਾ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, ਆਕਾਰ(*ctxt));
		cleanup_ctxt = ਨਿਰਾ;
	}
}

ਸਥਿਰ ਪੂਰਨ
sshpam_null_conv(ਪੂਰਨ n, sshpam_const ਬਣਤਰ pam_ਸੁਨੇਹਾ **ਸੁਨੇਹਾ,
    ਬਣਤਰ pam_response **resp, ਖਾਲੀ *ਅੰਕੜੇ)
{
	debug3_f("PAM: entering, %d messages", n);
	ਵਾਪਸ (PAM_CONV_ERR);
}

ਸਥਿਰ ਬਣਤਰ pam_conv null_conv = { sshpam_null_conv, ਨਿਰਾ };

ਸਥਿਰ ਪੂਰਨ
sshpam_store_conv(ਪੂਰਨ n, sshpam_const ਬਣਤਰ pam_ਸੁਨੇਹਾ **ਸੁਨੇਹਾ,
    ਬਣਤਰ pam_response **resp, ਖਾਲੀ *ਅੰਕੜੇ)
{
	ਬਣਤਰ pam_response *ਜਵਾਬ;
	ਪੂਰਨ r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ਨਿਰਾ;

	ਜੇ (n <= 0 || n > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ)
		ਵਾਪਸ (PAM_CONV_ERR);

	ਜੇ ((ਜਵਾਬ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(n, ਆਕਾਰ(*ਜਵਾਬ))) == ਨਿਰਾ)
		ਵਾਪਸ (PAM_CONV_ERR);

	ਲਈ (i = 0; i < n; ++i) {
		ਚੋਣ (PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style)) {
		ਹਾਲਤ PAM_ERROR_ਸੁਨੇਹਾ:
		ਹਾਲਤ PAM_ਪਾਠ_INFO:
			ਜੇ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			ਜਵਾਬ[i].resp_retcode = PAM_SUCCESS;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਓ fail;
		}
	}
	*resp = ਜਵਾਬ;
	ਵਾਪਸ (PAM_SUCCESS);

 fail:
	ਲਈ(i = 0; i < n; i++) {
		ਮੁਕਤ(ਜਵਾਬ[i].resp);
	}
	ਮੁਕਤ(ਜਵਾਬ);
	ਵਾਪਸ (PAM_CONV_ERR);
}

ਸਥਿਰ ਬਣਤਰ pam_conv store_conv = { sshpam_store_conv, ਨਿਰਾ };

ਖਾਲੀ
sshpam_cleanup(ਖਾਲੀ)
{
	ਜੇ (sshpam_handle == ਨਿਰਾ || !mm_is_monitor())
		ਵਾਪਸ;
	debug("PAM: cleanup");
	pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_CONV, (ਅਚਲ ਖਾਲੀ *)&null_conv);
	ਜੇ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	ਜੇ (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_ਸਿਰਾ(sshpam_handle, sshpam_err);
	sshpam_handle = ਨਿਰਾ;
	ਮੁਕਤ(sshpam_initial_user);
	sshpam_initial_user = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
sshpam_init(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	ਅਚਲ ਅੱਖਰ *user = authctxt->user;
	ਪੂਰਨ r;

	ਜੇ (options.pam_service_name == ਨਿਰਾ)
		fatal_f("internal error: NULL PAM service name");
#ਜੇ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_ਮਾਪ)
	/* Protect buggy PAM implementations from excessively long usernames */
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(user) >= PAM_MAX_RESP_ਮਾਪ)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
#ਜੇ_ਅੰਤ
	ਜੇ (sshpam_handle == ਨਿਰਾ && ssh == ਨਿਰਾ)
		fatal("%s: called initially with no packet context", __func__);
	ਜੇ (sshpam_handle != ਨਿਰਾ) {
		/* We already have a PAM context; check if the user matches */
		ਜੇ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		ਵਾਪਸ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_ਸ਼ੁਰੂ(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	ਜੇ (sshpam_err != PAM_SUCCESS) {
		pam_ਸਿਰਾ(sshpam_handle, sshpam_err);
		sshpam_handle = ਨਿਰਾ;
		ਵਾਪਸ (-1);
	}

	ਜੇ (ssh != ਨਿਰਾ && sshpam_rhost == ਨਿਰਾ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_ਵਿੱਚ(ssh));
	}
	ਜੇ (sshpam_rhost != ਨਿਰਾ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		ਜੇ (sshpam_err != PAM_SUCCESS) {
			pam_ਸਿਰਾ(sshpam_handle, sshpam_err);
			sshpam_handle = ਨਿਰਾ;
			ਵਾਪਸ (-1);
		}
	}
	ਜੇ (ssh != ਨਿਰਾ && sshpam_laddr != ਨਿਰਾ) {
		ਅੱਖਰ *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
		    sshpam_laddr, ssh_local_ਪੋਰਟ(ssh));
		ਜੇ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		ਮੁਕਤ(conninfo);
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_TTY, "ssh");
	ਜੇ (sshpam_err != PAM_SUCCESS) {
		pam_ਸਿਰਾ(sshpam_handle, sshpam_err);
		sshpam_handle = ਨਿਰਾ;
		ਵਾਪਸ (-1);
	}
#ਜੇ_ਅੰਤ
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਖਾਲੀ
expose_authinfo(ਅਚਲ ਅੱਖਰ *caller)
{
	ਅੱਖਰ *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	ਜੇ (sshpam_authctxt->session_info == ਨਿਰਾ)
		auth_info = xstrdup("");
	ਨਹੀਂਤਾਂ ਜੇ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	ਮੁਕਤ(auth_info);
}

ਸਥਿਰ ਖਾਲੀ *
sshpam_init_ctx(Authctxt *authctxt)
{
	ਬਣਤਰ pam_ctxt *ctxt;
	ਪੂਰਨ ਨਤੀਜਾ, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	ਜੇ (!options.use_pam || sshpam_account_ਸਥਿਤੀ == 0)
		ਵਾਪਸ ਨਿਰਾ;

	/* Initialize PAM */
	ਜੇ (sshpam_init(ਨਿਰਾ, authctxt) == -1) {
		error("PAM: initialization failed");
		ਵਾਪਸ (ਨਿਰਾ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, ਆਕਾਰ *ctxt);

	/* Start the authentication thread */
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		ਮੁਕਤ(ctxt);
		ਵਾਪਸ (ਨਿਰਾ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	ਨਤੀਜਾ = pthread_create(&ctxt->pam_thread, ਨਿਰਾ, sshpam_thread, ctxt);
	ਜੇ (ਨਤੀਜਾ != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(ਨਤੀਜਾ));
		close(socks[0]);
		close(socks[1]);
		ਮੁਕਤ(ctxt);
		ਵਾਪਸ (ਨਿਰਾ);
	}
	cleanup_ctxt = ctxt;
	ਵਾਪਸ (ctxt);
}

ਸਥਿਰ ਪੂਰਨ
sshpam_query(ਖਾਲੀ *ctx, ਅੱਖਰ **name, ਅੱਖਰ **info,
    u_int *ਅੰਕ, ਅੱਖਰ ***prompts, u_int **echo_on)
{
	ਬਣਤਰ sshbuf *ਬਫਰ;
	ਬਣਤਰ pam_ctxt *ctxt = ctx;
	u_char type;
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	ਮਾਪ_t mlen, nmesg = 0;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ ((ਬਫਰ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ਨਿਰਾ;
	*ਅੰਕ = 0;
	ctxt->pam_ਪੂਰਾ = SshPamNone;

	ਜਦੋਂ (ssh_ਸੁਨੇਹਾ_recv(ctxt->pam_psock, ਬਫਰ) == 0) {
		ਜੇ (++nmesg > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ)
			fatal_f("too many query messages");
		ਜੇ ((r = sshbuf_get_u8(ਬਫਰ, &type)) != 0 ||
		    (r = sshbuf_get_cstring(ਬਫਰ, &ਸੁਨੇਹਾ, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		ਚੋਣ (type) {
		ਹਾਲਤ PAM_PROMPT_ECHO_ON:
		ਹਾਲਤ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, ਆਕਾਰ(ਅੱਖਰ *));
			*echo_on = xcalloc(1, ਆਕਾਰ(u_int));
			(*prompts)[0] = ਸੁਨੇਹਾ;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*ਅੰਕ = 1;
			sshbuf_free(ਬਫਰ);
			ਵਾਪਸ (0);
		ਹਾਲਤ PAM_ERROR_ਸੁਨੇਹਾ:
		ਹਾਲਤ PAM_ਪਾਠ_INFO:
			ਮੁਕਤ(*info);
			*info = ਸੁਨੇਹਾ; /* transfer ownership */
			ਸੁਨੇਹਾ = ਨਿਰਾ;
			ctxt->pam_ਪੂਰਾ = SshPamAgain;
			sshbuf_free(ਬਫਰ);
			ਵਾਪਸ (0);
		ਹਾਲਤ PAM_ACCT_EXPIRED:
		ਹਾਲਤ PAM_MAXTRIES:
			ਜੇ (type == PAM_ACCT_EXPIRED)
				sshpam_account_ਸਥਿਤੀ = 0;
			ਜੇ (type == PAM_MAXTRIES)
				sshpam_ਸੈੱਟ_maxtries_reached(1);
			/* FALLTHROUGH */
		ਹਾਲਤ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		ਹਾਲਤ PAM_SUCCESS:
			ਜੇ (type == PAM_SUCCESS) {
				ਜੇ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_ਜੜ੍ਹ_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(ਬਫਰ);
				ctxt->pam_ਪੂਰਾ = SshPamAuthenticated;
				ਮੁਕਤ(ਸੁਨੇਹਾ);
				sshbuf_free(ਬਫਰ);
				ਵਾਪਸ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", ਸੁਨੇਹਾ,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		ਮੂਲ:
			ਮੁਕਤ(ਸੁਨੇਹਾ);
			ctxt->pam_ਪੂਰਾ = SshPamError;
			sshbuf_free(ਬਫਰ);
			ਵਾਪਸ (-1);
		}
	}
	sshbuf_free(ਬਫਰ);
	ਵਾਪਸ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
ਸਥਿਰ ਅੱਖਰ *
fake_password(ਅਚਲ ਅੱਖਰ *wire_password)
{
	ਅਚਲ ਅੱਖਰ junk[] = "\b\n\r\177INCORRECT";
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਮਾਪ_t i, l = wire_password != ਨਿਰਾ ? ਲੜੀ_ਲੰਬਾਈ(wire_password) : 0;

	ਜੇ (l >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal_f("password length too long: %zu", l);

	ret = ਸਮ੍ਰਿਤੀ_ਦਿਓ(l + 1);
	ਜੇ (ret == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਲਈ (i = 0; i < l; i++)
		ret[i] = junk[i % (ਆਕਾਰ(junk) - 1)];
	ret[i] = '\0';
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
sshpam_respond(ਖਾਲੀ *ctx, u_int ਅੰਕ, ਅੱਖਰ **resp)
{
	ਬਣਤਰ sshbuf *ਬਫਰ;
	ਬਣਤਰ pam_ctxt *ctxt = ctx;
	ਅੱਖਰ *fake;
	ਪੂਰਨ r;

	debug2_f("PAM: entering, %u responses", ਅੰਕ);
	ਚੋਣ (ctxt->pam_ਪੂਰਾ) {
	ਹਾਲਤ SshPamAuthenticated:
		sshpam_authenticated = 1;
		ਵਾਪਸ (0);
	ਹਾਲਤ SshPamNone:
		ਰੋਕੋ;
	ਹਾਲਤ SshPamAgain:
		ਵਾਪਸ 1;	/* KbdintResultAgain */
	ਮੂਲ:
		ਵਾਪਸ (-1);
	}
	ਜੇ (ਅੰਕ != 1) {
		error("PAM: expected one response, got %u", ਅੰਕ);
		ਵਾਪਸ (-1);
	}
	ਜੇ ((ਬਫਰ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_ਜੜ੍ਹ_login == PERMIT_YES)) {
		ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} ਨਹੀਂਤਾਂ {
		fake = fake_password(*resp);
		ਜੇ ((r = sshbuf_put_cstring(ਬਫਰ, fake)) != 0)
			fatal_fr(r, "buffer error");
		ਮੁਕਤ(fake);
	}
	ਜੇ (ssh_ਸੁਨੇਹਾ_send(ctxt->pam_psock, PAM_AUTHTOK, ਬਫਰ) == -1) {
		sshbuf_free(ਬਫਰ);
		ਵਾਪਸ (-1);
	}
	sshbuf_free(ਬਫਰ);
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਖਾਲੀ
sshpam_free_ctx(ਖਾਲੀ *ctxtp)
{
	ਬਣਤਰ pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	ਮੁਕਤ(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

ਪੂਰਨ
sshpam_priv_kbdint_authdone(ਖਾਲੀ *ctxtp)
{
	ਬਣਤਰ pam_ctxt *ctxt = ctxtp;

	ਵਾਪਸ ctxt->pam_ਪੂਰਾ == SshPamAuthenticated;
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
ਖਾਲੀ
ਸ਼ੁਰੂ_pam(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ਜੇ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	ਜੇ (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

ਖਾਲੀ
ਅੰਤ_pam(ਖਾਲੀ)
{
	sshpam_cleanup();
}


u_int
do_pam_account(ਖਾਲੀ)
{
	debug_f("called");
	ਜੇ (sshpam_account_ਸਥਿਤੀ != -1)
		ਵਾਪਸ (sshpam_account_ਸਥਿਤੀ);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	ਜੇ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_ਸਥਿਤੀ = 0;
		ਵਾਪਸ (sshpam_account_ਸਥਿਤੀ);
	}

	ਜੇ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_ਸਥਿਤੀ = 1;
	ਵਾਪਸ (sshpam_account_ਸਥਿਤੀ);
}

ਖਾਲੀ
do_pam_setcred(ਖਾਲੀ)
{
	sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_CONV,
	    (ਅਚਲ ਖਾਲੀ *)&store_conv);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	ਜੇ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		ਵਾਪਸ;
	}
	ਜੇ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	ਨਹੀਂਤਾਂ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

ਖਾਲੀ
do_pam_session(ਬਣਤਰ ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_CONV,
	    (ਅਚਲ ਖਾਲੀ *)&store_conv);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	ਜੇ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	ਨਹੀਂਤਾਂ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

ਪੂਰਨ
is_pam_session_open(ਖਾਲੀ)
{
	ਵਾਪਸ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
ਪੂਰਨ
do_pam_putenv(ਅੱਖਰ *name, ਅੱਖਰ *ਮੁੱਲ)
{
	ਪੂਰਨ ret = 1;
	ਅੱਖਰ *compound;
	ਮਾਪ_t len;

	len = ਲੜੀ_ਲੰਬਾਈ(name) + ਲੜੀ_ਲੰਬਾਈ(ਮੁੱਲ) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, ਮੁੱਲ);
	ret = pam_putenv(sshpam_handle, compound);
	ਮੁਕਤ(compound);

	ਵਾਪਸ (ret);
}

ਅੱਖਰ **
fetch_pam_ਬੱਚਾ_environment(ਖਾਲੀ)
{
	ਵਾਪਸ sshpam_env;
}

ਅੱਖਰ **
fetch_pam_environment(ਖਾਲੀ)
{
	ਵਾਪਸ (pam_getenvlist(sshpam_handle));
}

ਖਾਲੀ
free_pam_environment(ਅੱਖਰ **env)
{
	ਅੱਖਰ **envp;

	ਜੇ (env == ਨਿਰਾ)
		ਵਾਪਸ;

	ਲਈ (envp = env; *envp; envp++)
		ਮੁਕਤ(*envp);
	ਮੁਕਤ(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
ਸਥਿਰ ਪੂਰਨ
sshpam_passwd_conv(ਪੂਰਨ n, sshpam_const ਬਣਤਰ pam_ਸੁਨੇਹਾ **ਸੁਨੇਹਾ,
    ਬਣਤਰ pam_response **resp, ਖਾਲੀ *ਅੰਕੜੇ)
{
	ਬਣਤਰ pam_response *ਜਵਾਬ;
	ਪੂਰਨ r, i;
	ਮਾਪ_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ਨਿਰਾ;

	ਜੇ (n <= 0 || n > PAM_MAX_ਅੰਕ_ਸੁਨੇਹਾ)
		ਵਾਪਸ (PAM_CONV_ERR);

	ਜੇ ((ਜਵਾਬ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(n, ਆਕਾਰ(*ਜਵਾਬ))) == ਨਿਰਾ)
		ਵਾਪਸ (PAM_CONV_ERR);

	ਲਈ (i = 0; i < n; ++i) {
		ਚੋਣ (PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ_style)) {
		ਹਾਲਤ PAM_PROMPT_ECHO_OFF:
			ਜੇ (sshpam_password == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜੇ ((ਜਵਾਬ[i].resp = strdup(sshpam_password)) == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜਵਾਬ[i].resp_retcode = PAM_SUCCESS;
			ਰੋਕੋ;
		ਹਾਲਤ PAM_ERROR_ਸੁਨੇਹਾ:
		ਹਾਲਤ PAM_ਪਾਠ_INFO:
			len = ਲੜੀ_ਲੰਬਾਈ(PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ));
			ਜੇ (len > 0) {
				ਜੇ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_ਸੁਨੇਹਾ_MEMBER(ਸੁਨੇਹਾ, i, ਸੁਨੇਹਾ))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			ਜੇ ((ਜਵਾਬ[i].resp = strdup("")) == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜਵਾਬ[i].resp_retcode = PAM_SUCCESS;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਓ fail;
		}
	}
	*resp = ਜਵਾਬ;
	ਵਾਪਸ (PAM_SUCCESS);

 fail:
	ਲਈ(i = 0; i < n; i++) {
		ਮੁਕਤ(ਜਵਾਬ[i].resp);
	}
	ਮੁਕਤ(ਜਵਾਬ);
	ਵਾਪਸ (PAM_CONV_ERR);
}

ਸਥਿਰ ਬਣਤਰ pam_conv passwd_conv = { sshpam_passwd_conv, ਨਿਰਾ };

/*
 * Attempt password authentication via PAM
 */
ਪੂਰਨ
sshpam_auth_passwd(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *password)
{
	ਪੂਰਨ flags = (options.permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	ਅੱਖਰ *fake = ਨਿਰਾ;

	ਜੇ (!options.use_pam || sshpam_handle == ਨਿਰਾ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	ਜੇ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_ਜੜ੍ਹ_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_ਸੈੱਟ_ਵਸਤੂ(sshpam_handle, PAM_CONV,
	    (ਅਚਲ ਖਾਲੀ *)&passwd_conv);
	ਜੇ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ਨਿਰਾ;
	ਮੁਕਤ(fake);
	ਜੇ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	ਜੇ (sshpam_err == PAM_MAXTRIES)
		sshpam_ਸੈੱਟ_maxtries_reached(1);
	ਜੇ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		ਵਾਪਸ 0;
	}
}

ਪੂਰਨ
sshpam_get_maxtries_reached(ਖਾਲੀ)
{
	ਵਾਪਸ sshpam_maxtries_reached;
}

ਖਾਲੀ
sshpam_ਸੈੱਟ_maxtries_reached(ਪੂਰਨ reached)
{
	ਜੇ (reached == 0 || sshpam_maxtries_reached)
		ਵਾਪਸ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#ਜੇ_ਅੰਤ /* USE_PAM */
