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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef USE_PAM
#જો defined(HAVE_SECURITY_PAM_APPL_H)
#અન્તર્ભાવ <security/pam_appl.h>
#અથવાજો defined (HAVE_PAM_PAM_APPL_H)
#અન્તર્ભાવ <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#નહીંતર
# define sshpam_const	અચલ	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_સંદેશ_MEMBER(સંદેશ, n, member) ((*(સંદેશ))[(n)].member)
#નહીંતર
# define PAM_સંદેશ_MEMBER(સંદેશ, n, member) ((સંદેશ)[(n)]->member)
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-pam.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "auth-options.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "srclimit.h"

બાહ્ય ServerOptions options;
બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય u_int utmp_len;

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
#અન્તર્ભાવ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
પ્રકારવ્યાખ્યા pthread_t sp_pthread_t;
#નહીંતર
પ્રકારવ્યાખ્યા pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

પ્રકારવ્યાખ્યા પૂર્ણાંક SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

સંરચના pam_ctxt {
	sp_pthread_t	 pam_thread;
	પૂર્ણાંક		 pam_psock;
	પૂર્ણાંક		 pam_csock;
	SshPamDone	 pam_done;
};

સ્થિર શૂન્ય sshpam_free_ctx(શૂન્ય *);
સ્થિર સંરચના pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

સ્થિર પૂર્ણાંક sshpam_thread_status = -1;
સ્થિર sshsig_t sshpam_oldsig;

સ્થિર શૂન્ય
sshpam_sigchld_handler(પૂર્ણાંક sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	જો (cleanup_ctxt == ખાલી)
		પાછા;	/* handler called after PAM cleanup, shouldn't happen */
	જો (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		જ્યારે (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			જો (errno == EINTR)
				ચાલુ;
			પાછા;
		}
	}
	જો (sshpam_thread_status == -1)
		પાછા;
	જો (WIFSIGNALED(sshpam_thread_status)) {
		જો (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} નહીંતર જો (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
સ્થિર શૂન્ય
pthread_exit(શૂન્ય *કિંમત)
{
	_exit(0);
}

/* ARGSUSED */
સ્થિર પૂર્ણાંક
pthread_create(sp_pthread_t *thread, અચલ શૂન્ય *attr,
    શૂન્ય *(*thread_start)(શૂન્ય *), શૂન્ય *arg)
{
	pid_t pid;
	સંરચના pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	પસંદગી ((pid = fork())) {
	સ્થિતિ -1:
		error("fork(): %s", strerror(errno));
		પાછા errno;
	સ્થિતિ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	મૂળભૂત:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		પાછા (0);
	}
}

સ્થિર પૂર્ણાંક
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	પાછા (kill(thread, SIGTERM));
}

/* ARGSUSED */
સ્થિર પૂર્ણાંક
pthread_join(sp_pthread_t thread, શૂન્ય **કિંમત)
{
	પૂર્ણાંક status;

	જો (sshpam_thread_status != -1)
		પાછા (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	જ્યારે (waitpid(thread, &status, 0) == -1) {
		જો (errno == EINTR)
			ચાલુ;
		fatal_f("waitpid: %s", strerror(errno));
	}
	પાછા (status);
}
#endif


સ્થિર pam_handle_t *sshpam_handle = ખાલી;
સ્થિર અક્ષર *sshpam_initial_user;
સ્થિર પૂર્ણાંક sshpam_err = 0;
સ્થિર પૂર્ણાંક sshpam_authenticated = 0;
સ્થિર પૂર્ણાંક sshpam_session_open = 0;
સ્થિર પૂર્ણાંક sshpam_cred_established = 0;
સ્થિર પૂર્ણાંક sshpam_account_status = -1;
સ્થિર પૂર્ણાંક sshpam_maxtries_reached = 0;
સ્થિર અક્ષર **sshpam_env = ખાલી;
સ્થિર Authctxt *sshpam_authctxt = ખાલી;
સ્થિર અચલ અક્ષર *sshpam_password = ખાલી;
સ્થિર અક્ષર *sshpam_rhost = ખાલી;
સ્થિર અક્ષર *sshpam_laddr = ખાલી;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
સ્થિર અક્ષર **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 પાછા ખાલી;
}
#endif

#ifndef HAVE_PAM_PUTENV
સ્થિર પૂર્ણાંક
pam_putenv(pam_handle_t *pamh, અચલ અક્ષર *name_કિંમત)
{
	પાછા PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

સ્થિર શૂન્ય
sshpam_password_change_required(પૂર્ણાંક reqd)
{
	બાહ્ય સંરચના sshauthopt *auth_opts;
	સ્થિર પૂર્ણાંક saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	જો (sshpam_authctxt == ખાલી)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	જો (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} નહીંતર {
		જો (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		જો (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		જો (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
સ્થિર શૂન્ય
import_environments(સંરચના sshbuf *b)
{
	અક્ષર *env;
	u_int n, i, અંક_env;
	પૂર્ણાંક r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	જો ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	જો (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (પૂર્ણાંક)n;
	જો ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	જો ((r = sshbuf_get_u32(b, &અંક_env)) != 0)
		fatal_fr(r, "buffer error");
	જો (અંક_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    અંક_env);
	}
	sshpam_env = xcalloc(અંક_env + 1, કદ(*sshpam_env));
	debug3("PAM: num env strings %u", અંક_env);
	માટે(i = 0; i < અંક_env; i++) {
		જો ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ખાલી)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[અંક_env] = ખાલી;

	/* Import PAM environment from subprocess */
	જો ((r = sshbuf_get_u32(b, &અંક_env)) != 0)
		fatal_fr(r, "buffer error");
	જો (અંક_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    અંક_env);
	}
	debug("PAM: num PAM env strings %u", અંક_env);
	માટે (i = 0; i < અંક_env; i++) {
		જો ((r = sshbuf_get_cstring(b, &env, ખાલી)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		જો ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
સ્થિર પૂર્ણાંક
sshpam_thread_conv(પૂર્ણાંક n, sshpam_const સંરચના pam_message **સંદેશ,
    સંરચના pam_response **resp, શૂન્ય *data)
{
	સંરચના sshbuf *buffer;
	સંરચના pam_ctxt *ctxt;
	સંરચના pam_response *reply;
	પૂર્ણાંક r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ખાલી;

	જો (data == ખાલી) {
		error("PAM: conversation function passed a null context");
		પાછા (PAM_CONV_ERR);
	}
	ctxt = data;
	જો (n <= 0 || n > PAM_MAX_અંક_સંદેશ)
		પાછા (PAM_CONV_ERR);

	જો ((reply = calloc(n, કદ(*reply))) == ખાલી)
		પાછા PAM_CONV_ERR;
	જો ((buffer = sshbuf_new()) == ખાલી) {
		મુક્ત(reply);
		પાછા PAM_CONV_ERR;
	}

	માટે (i = 0; i < n; ++i) {
		પસંદગી (PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style)) {
		સ્થિતિ PAM_PROMPT_ECHO_OFF:
		સ્થિતિ PAM_PROMPT_ECHO_ON:
			જો ((r = sshbuf_put_cstring(buffer,
			    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			જો (ssh_સંદેશ_send(ctxt->pam_csock,
			    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style), buffer) == -1)
				જાઓ fail;

			જો (ssh_સંદેશ_recv(ctxt->pam_csock, buffer) == -1)
				જાઓ fail;
			જો ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			જો (status != PAM_AUTHTOK)
				જાઓ fail;
			જો ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, ખાલી)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			તોડો;
		સ્થિતિ PAM_ERROR_સંદેશ:
		સ્થિતિ PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style),
			       PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ));
			જો ((r = sshbuf_put_cstring(buffer,
			    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			જો (ssh_સંદેશ_send(ctxt->pam_csock,
			    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style), buffer) == -1)
				જાઓ fail;
			તોડો;
		મૂળભૂત:
			જાઓ fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	પાછા (PAM_SUCCESS);

 fail:
	માટે(i = 0; i < n; i++) {
		મુક્ત(reply[i].resp);
	}
	મુક્ત(reply);
	sshbuf_free(buffer);
	પાછા (PAM_CONV_ERR);
}

સ્થિર પૂર્ણાંક
check_pam_user(Authctxt *authctxt)
{
	અચલ અક્ષર *pam_user;

	જો (authctxt == ખાલી || authctxt->pw == ખાલી ||
	    authctxt->pw->pw_name == ખાલી)
		fatal_f("PAM authctxt user not initialized");

	જો ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const શૂન્ય **) &pam_user)) != PAM_SUCCESS)
		પાછા sshpam_err;

	જો (pam_user == ખાલી) {
		debug("PAM error: PAM_USER is NULL");
		પાછા PAM_USER_UNKNOWN;
	}

	જો (sshpam_initial_user == ખાલી)
		fatal_f("internal error: sshpam_initial_user NULL");
	જો (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		પાછા PAM_USER_UNKNOWN;
	}
	પાછા PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
સ્થિર શૂન્ય *
sshpam_thread(શૂન્ય *ctxtp)
{
	સંરચના pam_ctxt *ctxt = ctxtp;
	સંરચના sshbuf *buffer = ખાલી;
	સંરચના pam_conv sshpam_conv;
	પૂર્ણાંક r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	બાહ્ય અક્ષર **environ;
	અક્ષર **env_from_pam;
	u_int i;
	અચલ અક્ષર *pam_user;
	અચલ અક્ષર **ptr_pam_user = &pam_user;
	અક્ષર *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const શૂન્ય **)ptr_pam_user);
	જો (sshpam_err != PAM_SUCCESS)
		જાઓ auth_fail;

	environ[0] = ખાલી;
	જો (tz != ખાલી)
		જો (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	જો (sshpam_authctxt != ખાલી) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	જો (sshpam_authctxt == ખાલી)
		fatal_f("PAM authctxt not initialized");

	જો ((buffer = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (અચલ શૂન્ય *)&sshpam_conv);
	જો (sshpam_err != PAM_SUCCESS)
		જાઓ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	જો (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	જો (sshpam_err != PAM_SUCCESS)
		જાઓ auth_fail;
	જો ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		જાઓ auth_fail;

	જો (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		જાઓ auth_fail;
	}
	જો (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		જો (sshpam_err != PAM_SUCCESS)
			જાઓ auth_fail;
		sshpam_password_change_required(0);
	}

	જો ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	જો ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	માટે (i = 0; environ[i] != ખાલી; i++) {
		/*ગણતરી*/
		જો (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	જો ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	માટે (i = 0; environ[i] != ખાલી; i++) {
		જો ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	માટે (i = 0; env_from_pam != ખાલી && env_from_pam[i] != ખાલી; i++) {
		/*ગણતરી*/
		જો (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	જો ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	માટે (i = 0; env_from_pam != ખાલી && env_from_pam[i] != ખાલી; i++) {
		જો ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_સંદેશ_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(ખાલી);

 auth_fail:
	જો ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	જો (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_સંદેશ_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	નહીંતર જો (sshpam_maxtries_reached)
		ssh_સંદેશ_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	નહીંતર
		ssh_સંદેશ_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(ખાલી);

	પાછા (ખાલી); /* Avoid warning for non-pthread case */
}

શૂન્ય
sshpam_thread_cleanup(શૂન્ય)
{
	સંરચના pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	જો (ctxt != ખાલી && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ખાલી);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, કદ(*ctxt));
		cleanup_ctxt = ખાલી;
	}
}

સ્થિર પૂર્ણાંક
sshpam_null_conv(પૂર્ણાંક n, sshpam_const સંરચના pam_message **સંદેશ,
    સંરચના pam_response **resp, શૂન્ય *data)
{
	debug3_f("PAM: entering, %d messages", n);
	પાછા (PAM_CONV_ERR);
}

સ્થિર સંરચના pam_conv null_conv = { sshpam_null_conv, ખાલી };

સ્થિર પૂર્ણાંક
sshpam_store_conv(પૂર્ણાંક n, sshpam_const સંરચના pam_message **સંદેશ,
    સંરચના pam_response **resp, શૂન્ય *data)
{
	સંરચના pam_response *reply;
	પૂર્ણાંક r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ખાલી;

	જો (n <= 0 || n > PAM_MAX_અંક_સંદેશ)
		પાછા (PAM_CONV_ERR);

	જો ((reply = calloc(n, કદ(*reply))) == ખાલી)
		પાછા (PAM_CONV_ERR);

	માટે (i = 0; i < n; ++i) {
		પસંદગી (PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style)) {
		સ્થિતિ PAM_ERROR_સંદેશ:
		સ્થિતિ PAM_TEXT_INFO:
			જો ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			તોડો;
		મૂળભૂત:
			જાઓ fail;
		}
	}
	*resp = reply;
	પાછા (PAM_SUCCESS);

 fail:
	માટે(i = 0; i < n; i++) {
		મુક્ત(reply[i].resp);
	}
	મુક્ત(reply);
	પાછા (PAM_CONV_ERR);
}

સ્થિર સંરચના pam_conv store_conv = { sshpam_store_conv, ખાલી };

શૂન્ય
sshpam_cleanup(શૂન્ય)
{
	જો (sshpam_handle == ખાલી || !mm_is_monitor())
		પાછા;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (અચલ શૂન્ય *)&null_conv);
	જો (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	જો (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = ખાલી;
	મુક્ત(sshpam_initial_user);
	sshpam_initial_user = ખાલી;
}

સ્થિર પૂર્ણાંક
sshpam_init(સંરચના ssh *ssh, Authctxt *authctxt)
{
	અચલ અક્ષર *user = authctxt->user;
	પૂર્ણાંક r;

	જો (options.pam_service_name == ખાલી)
		fatal_f("internal error: NULL PAM service name");
#જો defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	જો (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	જો (sshpam_handle == ખાલી && ssh == ખાલી)
		fatal("%s: called initially with no packet context", __func__);
	જો (sshpam_handle != ખાલી) {
		/* We already have a PAM context; check if the user matches */
		જો ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		પાછા 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	જો (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ખાલી;
		પાછા (-1);
	}

	જો (ssh != ખાલી && sshpam_rhost == ખાલી) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	જો (sshpam_rhost != ખાલી && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		જો (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = ખાલી;
			પાછા (-1);
		}
	}
	જો (ssh != ખાલી && sshpam_laddr != ખાલી) {
		અક્ષર *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		જો ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		મુક્ત(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	જો (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ખાલી;
		પાછા (-1);
	}
#endif
	પાછા (0);
}

સ્થિર શૂન્ય
expose_authinfo(અચલ અક્ષર *caller)
{
	અક્ષર *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	જો (sshpam_authctxt->session_info == ખાલી)
		auth_info = xstrdup("");
	નહીંતર જો ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	મુક્ત(auth_info);
}

સ્થિર શૂન્ય *
sshpam_init_ctx(Authctxt *authctxt)
{
	સંરચના pam_ctxt *ctxt;
	પૂર્ણાંક result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	જો (!options.use_pam || sshpam_account_status == 0)
		પાછા ખાલી;

	/* Initialize PAM */
	જો (sshpam_init(ખાલી, authctxt) == -1) {
		error("PAM: initialization failed");
		પાછા (ખાલી);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, કદ *ctxt);

	/* Start the authentication thread */
	જો (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		મુક્ત(ctxt);
		પાછા (ખાલી);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, ખાલી, sshpam_thread, ctxt);
	જો (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		મુક્ત(ctxt);
		પાછા (ખાલી);
	}
	cleanup_ctxt = ctxt;
	પાછા (ctxt);
}

સ્થિર પૂર્ણાંક
sshpam_query(શૂન્ય *ctx, અક્ષર **name, અક્ષર **info,
    u_int *અંક, અક્ષર ***prompts, u_int **echo_on)
{
	સંરચના sshbuf *buffer;
	સંરચના pam_ctxt *ctxt = ctx;
	u_char type;
	અક્ષર *સંદેશ;
	size_t mlen, nmesg = 0;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો ((buffer = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ખાલી;
	*અંક = 0;
	ctxt->pam_done = SshPamNone;

	જ્યારે (ssh_સંદેશ_recv(ctxt->pam_psock, buffer) == 0) {
		જો (++nmesg > PAM_MAX_અંક_સંદેશ)
			fatal_f("too many query messages");
		જો ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &સંદેશ, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		પસંદગી (type) {
		સ્થિતિ PAM_PROMPT_ECHO_ON:
		સ્થિતિ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, કદ(અક્ષર *));
			*echo_on = xcalloc(1, કદ(u_int));
			(*prompts)[0] = સંદેશ;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*અંક = 1;
			sshbuf_free(buffer);
			પાછા (0);
		સ્થિતિ PAM_ERROR_સંદેશ:
		સ્થિતિ PAM_TEXT_INFO:
			મુક્ત(*info);
			*info = સંદેશ; /* transfer ownership */
			સંદેશ = ખાલી;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			પાછા (0);
		સ્થિતિ PAM_ACCT_EXPIRED:
		સ્થિતિ PAM_MAXTRIES:
			જો (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			જો (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		સ્થિતિ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		સ્થિતિ PAM_SUCCESS:
			જો (type == PAM_SUCCESS) {
				જો (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_મૂળ_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				મુક્ત(સંદેશ);
				sshbuf_free(buffer);
				પાછા (0);
			}
			error("PAM: %s for %s%.100s from %.100s", સંદેશ,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		મૂળભૂત:
			મુક્ત(સંદેશ);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			પાછા (-1);
		}
	}
	sshbuf_free(buffer);
	પાછા (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
સ્થિર અક્ષર *
fake_password(અચલ અક્ષર *wire_password)
{
	અચલ અક્ષર junk[] = "\b\n\r\177INCORRECT";
	અક્ષર *ret = ખાલી;
	size_t i, l = wire_password != ખાલી ? strlen(wire_password) : 0;

	જો (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	જો (ret == ખાલી)
		પાછા ખાલી;
	માટે (i = 0; i < l; i++)
		ret[i] = junk[i % (કદ(junk) - 1)];
	ret[i] = '\0';
	પાછા ret;
}

સ્થિર પૂર્ણાંક
sshpam_respond(શૂન્ય *ctx, u_int અંક, અક્ષર **resp)
{
	સંરચના sshbuf *buffer;
	સંરચના pam_ctxt *ctxt = ctx;
	અક્ષર *fake;
	પૂર્ણાંક r;

	debug2_f("PAM: entering, %u responses", અંક);
	પસંદગી (ctxt->pam_done) {
	સ્થિતિ SshPamAuthenticated:
		sshpam_authenticated = 1;
		પાછા (0);
	સ્થિતિ SshPamNone:
		તોડો;
	સ્થિતિ SshPamAgain:
		પાછા 1;	/* KbdintResultAgain */
	મૂળભૂત:
		પાછા (-1);
	}
	જો (અંક != 1) {
		error("PAM: expected one response, got %u", અંક);
		પાછા (-1);
	}
	જો ((buffer = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_મૂળ_login == PERMIT_YES)) {
		જો ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} નહીંતર {
		fake = fake_password(*resp);
		જો ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		મુક્ત(fake);
	}
	જો (ssh_સંદેશ_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		પાછા (-1);
	}
	sshbuf_free(buffer);
	પાછા (1);
}

સ્થિર શૂન્ય
sshpam_free_ctx(શૂન્ય *ctxtp)
{
	સંરચના pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	મુક્ત(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

પૂર્ણાંક
sshpam_priv_kbdint_authdone(શૂન્ય *ctxtp)
{
	સંરચના pam_ctxt *ctxt = ctxtp;

	પાછા ctxt->pam_done == SshPamAuthenticated;
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
શૂન્ય
start_pam(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	જો (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	જો (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

શૂન્ય
finish_pam(શૂન્ય)
{
	sshpam_cleanup();
}


u_int
do_pam_account(શૂન્ય)
{
	debug_f("called");
	જો (sshpam_account_status != -1)
		પાછા (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	જો (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		પાછા (sshpam_account_status);
	}

	જો (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	પાછા (sshpam_account_status);
}

શૂન્ય
do_pam_setcred(શૂન્ય)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (અચલ શૂન્ય *)&store_conv);
	જો (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	જો (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		પાછા;
	}
	જો (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	નહીંતર
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

શૂન્ય
do_pam_session(સંરચના ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (અચલ શૂન્ય *)&store_conv);
	જો (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	જો (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	નહીંતર {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

પૂર્ણાંક
is_pam_session_open(શૂન્ય)
{
	પાછા sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
પૂર્ણાંક
do_pam_putenv(અક્ષર *name, અક્ષર *કિંમત)
{
	પૂર્ણાંક ret = 1;
	અક્ષર *compound;
	size_t len;

	len = strlen(name) + strlen(કિંમત) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, કિંમત);
	ret = pam_putenv(sshpam_handle, compound);
	મુક્ત(compound);

	પાછા (ret);
}

અક્ષર **
fetch_pam_child_environment(શૂન્ય)
{
	પાછા sshpam_env;
}

અક્ષર **
fetch_pam_environment(શૂન્ય)
{
	પાછા (pam_getenvlist(sshpam_handle));
}

શૂન્ય
free_pam_environment(અક્ષર **env)
{
	અક્ષર **envp;

	જો (env == ખાલી)
		પાછા;

	માટે (envp = env; *envp; envp++)
		મુક્ત(*envp);
	મુક્ત(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
સ્થિર પૂર્ણાંક
sshpam_passwd_conv(પૂર્ણાંક n, sshpam_const સંરચના pam_message **સંદેશ,
    સંરચના pam_response **resp, શૂન્ય *data)
{
	સંરચના pam_response *reply;
	પૂર્ણાંક r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ખાલી;

	જો (n <= 0 || n > PAM_MAX_અંક_સંદેશ)
		પાછા (PAM_CONV_ERR);

	જો ((reply = calloc(n, કદ(*reply))) == ખાલી)
		પાછા (PAM_CONV_ERR);

	માટે (i = 0; i < n; ++i) {
		પસંદગી (PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ_style)) {
		સ્થિતિ PAM_PROMPT_ECHO_OFF:
			જો (sshpam_password == ખાલી)
				જાઓ fail;
			જો ((reply[i].resp = strdup(sshpam_password)) == ખાલી)
				જાઓ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			તોડો;
		સ્થિતિ PAM_ERROR_સંદેશ:
		સ્થિતિ PAM_TEXT_INFO:
			len = strlen(PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ));
			જો (len > 0) {
				જો ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_સંદેશ_MEMBER(સંદેશ, i, સંદેશ))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			જો ((reply[i].resp = strdup("")) == ખાલી)
				જાઓ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			તોડો;
		મૂળભૂત:
			જાઓ fail;
		}
	}
	*resp = reply;
	પાછા (PAM_SUCCESS);

 fail:
	માટે(i = 0; i < n; i++) {
		મુક્ત(reply[i].resp);
	}
	મુક્ત(reply);
	પાછા (PAM_CONV_ERR);
}

સ્થિર સંરચના pam_conv passwd_conv = { sshpam_passwd_conv, ખાલી };

/*
 * Attempt password authentication via PAM
 */
પૂર્ણાંક
sshpam_auth_passwd(Authctxt *authctxt, અચલ અક્ષર *password)
{
	પૂર્ણાંક flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	અક્ષર *fake = ખાલી;

	જો (!options.use_pam || sshpam_handle == ખાલી)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	જો (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_મૂળ_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (અચલ શૂન્ય *)&passwd_conv);
	જો (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ખાલી;
	મુક્ત(fake);
	જો (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	જો (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	જો (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		પાછા 1;
	} નહીંતર {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		પાછા 0;
	}
}

પૂર્ણાંક
sshpam_get_maxtries_reached(શૂન્ય)
{
	પાછા sshpam_maxtries_reached;
}

શૂન્ય
sshpam_set_maxtries_reached(પૂર્ણાંક reached)
{
	જો (reached == 0 || sshpam_maxtries_reached)
		પાછા;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
