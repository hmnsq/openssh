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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef USE_PAM
#എങ്കിൽ defined(HAVE_SECURITY_PAM_APPL_H)
#അന്തര്ഭാവ <security/pam_appl.h>
#അല്ലെങ്കിലെങ്കിൽ defined (HAVE_PAM_PAM_APPL_H)
#അന്തര്ഭാവ <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#അല്ലെങ്കിൽ
# define sshpam_const	സ്ഥിരം	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_സന്ദേശം_MEMBER(സന്ദേശം, n, member) ((*(സന്ദേശം))[(n)].member)
#അല്ലെങ്കിൽ
# define PAM_സന്ദേശം_MEMBER(സന്ദേശം, n, member) ((സന്ദേശം)[(n)]->member)
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-pam.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "auth-options.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "srclimit.h"

ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ u_int utmp_len;

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
#അന്തര്ഭാവ <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
തരനിർവചനം pthread_t sp_pthread_t;
#അല്ലെങ്കിൽ
തരനിർവചനം pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

തരനിർവചനം പൂർണ്ണസംഖ്യ SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

ഘടന pam_ctxt {
	sp_pthread_t	 pam_thread;
	പൂർണ്ണസംഖ്യ		 pam_psock;
	പൂർണ്ണസംഖ്യ		 pam_csock;
	SshPamDone	 pam_done;
};

സ്ഥിതം ശൂന്യം sshpam_free_ctx(ശൂന്യം *);
സ്ഥിതം ഘടന pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_thread_status = -1;
സ്ഥിതം sshsig_t sshpam_oldsig;

സ്ഥിതം ശൂന്യം
sshpam_sigchld_handler(പൂർണ്ണസംഖ്യ sig)
{
	ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ (cleanup_ctxt == ശൂന്യ)
		തിരികെ;	/* handler called after PAM cleanup, shouldn't happen */
	എങ്കിൽ (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		ആകുമ്പോൾ (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			എങ്കിൽ (errno == EINTR)
				തുടരുക;
			തിരികെ;
		}
	}
	എങ്കിൽ (sshpam_thread_status == -1)
		തിരികെ;
	എങ്കിൽ (WIFSIGNALED(sshpam_thread_status)) {
		എങ്കിൽ (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} അല്ലെങ്കിൽ എങ്കിൽ (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
സ്ഥിതം ശൂന്യം
pthread_exit(ശൂന്യം *മൂല്യം)
{
	_exit(0);
}

/* ARGSUSED */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pthread_create(sp_pthread_t *thread, സ്ഥിരം ശൂന്യം *attr,
    ശൂന്യം *(*thread_start)(ശൂന്യം *), ശൂന്യം *arg)
{
	pid_t pid;
	ഘടന pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	തിരഞ്ഞെടുപ്പ് ((pid = fork())) {
	അവസ്ഥ -1:
		error("fork(): %s", strerror(errno));
		തിരികെ errno;
	അവസ്ഥ 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	സ്ഥിരസ്ഥിതി:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		തിരികെ (0);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	തിരികെ (kill(thread, SIGTERM));
}

/* ARGSUSED */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pthread_join(sp_pthread_t thread, ശൂന്യം **മൂല്യം)
{
	പൂർണ്ണസംഖ്യ status;

	എങ്കിൽ (sshpam_thread_status != -1)
		തിരികെ (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	ആകുമ്പോൾ (waitpid(thread, &status, 0) == -1) {
		എങ്കിൽ (errno == EINTR)
			തുടരുക;
		fatal_f("waitpid: %s", strerror(errno));
	}
	തിരികെ (status);
}
#endif


സ്ഥിതം pam_handle_t *sshpam_handle = ശൂന്യ;
സ്ഥിതം അക്ഷരം *sshpam_initial_user;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_err = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_authenticated = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_session_open = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_cred_established = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_account_status = -1;
സ്ഥിതം പൂർണ്ണസംഖ്യ sshpam_maxtries_reached = 0;
സ്ഥിതം അക്ഷരം **sshpam_env = ശൂന്യ;
സ്ഥിതം Authctxt *sshpam_authctxt = ശൂന്യ;
സ്ഥിതം സ്ഥിരം അക്ഷരം *sshpam_password = ശൂന്യ;
സ്ഥിതം അക്ഷരം *sshpam_rhost = ശൂന്യ;
സ്ഥിതം അക്ഷരം *sshpam_laddr = ശൂന്യ;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
സ്ഥിതം അക്ഷരം **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 തിരികെ ശൂന്യ;
}
#endif

#ifndef HAVE_PAM_PUTENV
സ്ഥിതം പൂർണ്ണസംഖ്യ
pam_putenv(pam_handle_t *pamh, സ്ഥിരം അക്ഷരം *name_മൂല്യം)
{
	തിരികെ PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

സ്ഥിതം ശൂന്യം
sshpam_password_change_required(പൂർണ്ണസംഖ്യ reqd)
{
	ബാഹ്യ ഘടന sshauthopt *auth_opts;
	സ്ഥിതം പൂർണ്ണസംഖ്യ saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	എങ്കിൽ (sshpam_authctxt == ശൂന്യ)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	എങ്കിൽ (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		എങ്കിൽ (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		എങ്കിൽ (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
സ്ഥിതം ശൂന്യം
import_environments(ഘടന sshbuf *b)
{
	അക്ഷരം *env;
	u_int n, i, അക്കം_env;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	എങ്കിൽ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (n > INT_MAX)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (പൂർണ്ണസംഖ്യ)n;
	എങ്കിൽ ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	എങ്കിൽ ((r = sshbuf_get_u32(b, &അക്കം_env)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (അക്കം_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    അക്കം_env);
	}
	sshpam_env = xcalloc(അക്കം_env + 1, വലുപ്പം(*sshpam_env));
	debug3("PAM: num env strings %u", അക്കം_env);
	വേണ്ടി(i = 0; i < അക്കം_env; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), ശൂന്യ)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[അക്കം_env] = ശൂന്യ;

	/* Import PAM environment from subprocess */
	എങ്കിൽ ((r = sshbuf_get_u32(b, &അക്കം_env)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (അക്കം_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    അക്കം_env);
	}
	debug("PAM: num PAM env strings %u", അക്കം_env);
	വേണ്ടി (i = 0; i < അക്കം_env; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(b, &env, ശൂന്യ)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		എങ്കിൽ ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_thread_conv(പൂർണ്ണസംഖ്യ n, sshpam_const ഘടന pam_message **സന്ദേശം,
    ഘടന pam_response **resp, ശൂന്യം *data)
{
	ഘടന sshbuf *buffer;
	ഘടന pam_ctxt *ctxt;
	ഘടന pam_response *reply;
	പൂർണ്ണസംഖ്യ r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = ശൂന്യ;

	എങ്കിൽ (data == ശൂന്യ) {
		error("PAM: conversation function passed a null context");
		തിരികെ (PAM_CONV_ERR);
	}
	ctxt = data;
	എങ്കിൽ (n <= 0 || n > PAM_MAX_അക്കം_സന്ദേശം)
		തിരികെ (PAM_CONV_ERR);

	എങ്കിൽ ((reply = calloc(n, വലുപ്പം(*reply))) == ശൂന്യ)
		തിരികെ PAM_CONV_ERR;
	എങ്കിൽ ((buffer = sshbuf_new()) == ശൂന്യ) {
		സ്വതന്ത്രം(reply);
		തിരികെ PAM_CONV_ERR;
	}

	വേണ്ടി (i = 0; i < n; ++i) {
		തിരഞ്ഞെടുപ്പ് (PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style)) {
		അവസ്ഥ PAM_PROMPT_ECHO_OFF:
		അവസ്ഥ PAM_PROMPT_ECHO_ON:
			എങ്കിൽ ((r = sshbuf_put_cstring(buffer,
			    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			എങ്കിൽ (ssh_സന്ദേശം_send(ctxt->pam_csock,
			    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style), buffer) == -1)
				പോകുക fail;

			എങ്കിൽ (ssh_സന്ദേശം_recv(ctxt->pam_csock, buffer) == -1)
				പോകുക fail;
			എങ്കിൽ ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			എങ്കിൽ (status != PAM_AUTHTOK)
				പോകുക fail;
			എങ്കിൽ ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, ശൂന്യ)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			നിർത്തുക;
		അവസ്ഥ PAM_ERROR_സന്ദേശം:
		അവസ്ഥ PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style),
			       PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം));
			എങ്കിൽ ((r = sshbuf_put_cstring(buffer,
			    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			എങ്കിൽ (ssh_സന്ദേശം_send(ctxt->pam_csock,
			    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style), buffer) == -1)
				പോകുക fail;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			പോകുക fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	തിരികെ (PAM_SUCCESS);

 fail:
	വേണ്ടി(i = 0; i < n; i++) {
		സ്വതന്ത്രം(reply[i].resp);
	}
	സ്വതന്ത്രം(reply);
	sshbuf_free(buffer);
	തിരികെ (PAM_CONV_ERR);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_pam_user(Authctxt *authctxt)
{
	സ്ഥിരം അക്ഷരം *pam_user;

	എങ്കിൽ (authctxt == ശൂന്യ || authctxt->pw == ശൂന്യ ||
	    authctxt->pw->pw_name == ശൂന്യ)
		fatal_f("PAM authctxt user not initialized");

	എങ്കിൽ ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ശൂന്യം **) &pam_user)) != PAM_SUCCESS)
		തിരികെ sshpam_err;

	എങ്കിൽ (pam_user == ശൂന്യ) {
		debug("PAM error: PAM_USER is NULL");
		തിരികെ PAM_USER_UNKNOWN;
	}

	എങ്കിൽ (sshpam_initial_user == ശൂന്യ)
		fatal_f("internal error: sshpam_initial_user NULL");
	എങ്കിൽ (strcmp(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		തിരികെ PAM_USER_UNKNOWN;
	}
	തിരികെ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
സ്ഥിതം ശൂന്യം *
sshpam_thread(ശൂന്യം *ctxtp)
{
	ഘടന pam_ctxt *ctxt = ctxtp;
	ഘടന sshbuf *buffer = ശൂന്യ;
	ഘടന pam_conv sshpam_conv;
	പൂർണ്ണസംഖ്യ r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	ബാഹ്യ അക്ഷരം **environ;
	അക്ഷരം **env_from_pam;
	u_int i;
	സ്ഥിരം അക്ഷരം *pam_user;
	സ്ഥിരം അക്ഷരം **ptr_pam_user = &pam_user;
	അക്ഷരം *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const ശൂന്യം **)ptr_pam_user);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		പോകുക auth_fail;

	environ[0] = ശൂന്യ;
	എങ്കിൽ (tz != ശൂന്യ)
		എങ്കിൽ (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    strerror(errno));

	എങ്കിൽ (sshpam_authctxt != ശൂന്യ) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	എങ്കിൽ (sshpam_authctxt == ശൂന്യ)
		fatal_f("PAM authctxt not initialized");

	എങ്കിൽ ((buffer = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (സ്ഥിരം ശൂന്യം *)&sshpam_conv);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		പോകുക auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	എങ്കിൽ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		പോകുക auth_fail;
	എങ്കിൽ ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		പോകുക auth_fail;

	എങ്കിൽ (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		പോകുക auth_fail;
	}
	എങ്കിൽ (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		എങ്കിൽ (sshpam_err != PAM_SUCCESS)
			പോകുക auth_fail;
		sshpam_password_change_required(0);
	}

	എങ്കിൽ ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	എങ്കിൽ ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	വേണ്ടി (i = 0; environ[i] != ശൂന്യ; i++) {
		/*എണ്ണം*/
		എങ്കിൽ (i > INT_MAX)
			fatal_f("too many environment strings");
	}
	എങ്കിൽ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	വേണ്ടി (i = 0; environ[i] != ശൂന്യ; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	വേണ്ടി (i = 0; env_from_pam != ശൂന്യ && env_from_pam[i] != ശൂന്യ; i++) {
		/*എണ്ണം*/
		എങ്കിൽ (i > INT_MAX)
			fatal_f("too many PAM environment strings");
	}
	എങ്കിൽ ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	വേണ്ടി (i = 0; env_from_pam != ശൂന്യ && env_from_pam[i] != ശൂന്യ; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_സന്ദേശം_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(ശൂന്യ);

 auth_fail:
	എങ്കിൽ ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	എങ്കിൽ (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_സന്ദേശം_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	അല്ലെങ്കിൽ എങ്കിൽ (sshpam_maxtries_reached)
		ssh_സന്ദേശം_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	അല്ലെങ്കിൽ
		ssh_സന്ദേശം_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(ശൂന്യ);

	തിരികെ (ശൂന്യ); /* Avoid warning for non-pthread case */
}

ശൂന്യം
sshpam_thread_cleanup(ശൂന്യം)
{
	ഘടന pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	എങ്കിൽ (ctxt != ശൂന്യ && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, ശൂന്യ);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, വലുപ്പം(*ctxt));
		cleanup_ctxt = ശൂന്യ;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_null_conv(പൂർണ്ണസംഖ്യ n, sshpam_const ഘടന pam_message **സന്ദേശം,
    ഘടന pam_response **resp, ശൂന്യം *data)
{
	debug3_f("PAM: entering, %d messages", n);
	തിരികെ (PAM_CONV_ERR);
}

സ്ഥിതം ഘടന pam_conv null_conv = { sshpam_null_conv, ശൂന്യ };

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_store_conv(പൂർണ്ണസംഖ്യ n, sshpam_const ഘടന pam_message **സന്ദേശം,
    ഘടന pam_response **resp, ശൂന്യം *data)
{
	ഘടന pam_response *reply;
	പൂർണ്ണസംഖ്യ r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = ശൂന്യ;

	എങ്കിൽ (n <= 0 || n > PAM_MAX_അക്കം_സന്ദേശം)
		തിരികെ (PAM_CONV_ERR);

	എങ്കിൽ ((reply = calloc(n, വലുപ്പം(*reply))) == ശൂന്യ)
		തിരികെ (PAM_CONV_ERR);

	വേണ്ടി (i = 0; i < n; ++i) {
		തിരഞ്ഞെടുപ്പ് (PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style)) {
		അവസ്ഥ PAM_ERROR_സന്ദേശം:
		അവസ്ഥ PAM_TEXT_INFO:
			എങ്കിൽ ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			പോകുക fail;
		}
	}
	*resp = reply;
	തിരികെ (PAM_SUCCESS);

 fail:
	വേണ്ടി(i = 0; i < n; i++) {
		സ്വതന്ത്രം(reply[i].resp);
	}
	സ്വതന്ത്രം(reply);
	തിരികെ (PAM_CONV_ERR);
}

സ്ഥിതം ഘടന pam_conv store_conv = { sshpam_store_conv, ശൂന്യ };

ശൂന്യം
sshpam_cleanup(ശൂന്യം)
{
	എങ്കിൽ (sshpam_handle == ശൂന്യ || !mm_is_monitor())
		തിരികെ;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (സ്ഥിരം ശൂന്യം *)&null_conv);
	എങ്കിൽ (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	എങ്കിൽ (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = ശൂന്യ;
	സ്വതന്ത്രം(sshpam_initial_user);
	sshpam_initial_user = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_init(ഘടന ssh *ssh, Authctxt *authctxt)
{
	സ്ഥിരം അക്ഷരം *user = authctxt->user;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (options.pam_service_name == ശൂന്യ)
		fatal_f("internal error: NULL PAM service name");
#എങ്കിൽ defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	എങ്കിൽ (strlen(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	എങ്കിൽ (sshpam_handle == ശൂന്യ && ssh == ശൂന്യ)
		fatal("%s: called initially with no packet context", __func__);
	എങ്കിൽ (sshpam_handle != ശൂന്യ) {
		/* We already have a PAM context; check if the user matches */
		എങ്കിൽ ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		തിരികെ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	എങ്കിൽ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ശൂന്യ;
		തിരികെ (-1);
	}

	എങ്കിൽ (ssh != ശൂന്യ && sshpam_rhost == ശൂന്യ) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	എങ്കിൽ (sshpam_rhost != ശൂന്യ && strcmp(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		എങ്കിൽ (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = ശൂന്യ;
			തിരികെ (-1);
		}
	}
	എങ്കിൽ (ssh != ശൂന്യ && sshpam_laddr != ശൂന്യ) {
		അക്ഷരം *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		എങ്കിൽ ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		സ്വതന്ത്രം(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	എങ്കിൽ (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = ശൂന്യ;
		തിരികെ (-1);
	}
#endif
	തിരികെ (0);
}

സ്ഥിതം ശൂന്യം
expose_authinfo(സ്ഥിരം അക്ഷരം *caller)
{
	അക്ഷരം *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	എങ്കിൽ (sshpam_authctxt->session_info == ശൂന്യ)
		auth_info = xstrdup("");
	അല്ലെങ്കിൽ എങ്കിൽ ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	സ്വതന്ത്രം(auth_info);
}

സ്ഥിതം ശൂന്യം *
sshpam_init_ctx(Authctxt *authctxt)
{
	ഘടന pam_ctxt *ctxt;
	പൂർണ്ണസംഖ്യ result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	എങ്കിൽ (!options.use_pam || sshpam_account_status == 0)
		തിരികെ ശൂന്യ;

	/* Initialize PAM */
	എങ്കിൽ (sshpam_init(ശൂന്യ, authctxt) == -1) {
		error("PAM: initialization failed");
		തിരികെ (ശൂന്യ);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, വലുപ്പം *ctxt);

	/* Start the authentication thread */
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		സ്വതന്ത്രം(ctxt);
		തിരികെ (ശൂന്യ);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, ശൂന്യ, sshpam_thread, ctxt);
	എങ്കിൽ (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    strerror(result));
		close(socks[0]);
		close(socks[1]);
		സ്വതന്ത്രം(ctxt);
		തിരികെ (ശൂന്യ);
	}
	cleanup_ctxt = ctxt;
	തിരികെ (ctxt);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_query(ശൂന്യം *ctx, അക്ഷരം **name, അക്ഷരം **info,
    u_int *അക്കം, അക്ഷരം ***prompts, u_int **echo_on)
{
	ഘടന sshbuf *buffer;
	ഘടന pam_ctxt *ctxt = ctx;
	u_char type;
	അക്ഷരം *സന്ദേശം;
	size_t mlen, nmesg = 0;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ ((buffer = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = ശൂന്യ;
	*അക്കം = 0;
	ctxt->pam_done = SshPamNone;

	ആകുമ്പോൾ (ssh_സന്ദേശം_recv(ctxt->pam_psock, buffer) == 0) {
		എങ്കിൽ (++nmesg > PAM_MAX_അക്കം_സന്ദേശം)
			fatal_f("too many query messages");
		എങ്കിൽ ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &സന്ദേശം, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ PAM_PROMPT_ECHO_ON:
		അവസ്ഥ PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, വലുപ്പം(അക്ഷരം *));
			*echo_on = xcalloc(1, വലുപ്പം(u_int));
			(*prompts)[0] = സന്ദേശം;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*അക്കം = 1;
			sshbuf_free(buffer);
			തിരികെ (0);
		അവസ്ഥ PAM_ERROR_സന്ദേശം:
		അവസ്ഥ PAM_TEXT_INFO:
			സ്വതന്ത്രം(*info);
			*info = സന്ദേശം; /* transfer ownership */
			സന്ദേശം = ശൂന്യ;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			തിരികെ (0);
		അവസ്ഥ PAM_ACCT_EXPIRED:
		അവസ്ഥ PAM_MAXTRIES:
			എങ്കിൽ (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			എങ്കിൽ (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		അവസ്ഥ PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		അവസ്ഥ PAM_SUCCESS:
			എങ്കിൽ (type == PAM_SUCCESS) {
				എങ്കിൽ (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_വേര്_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				സ്വതന്ത്രം(സന്ദേശം);
				sshbuf_free(buffer);
				തിരികെ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", സന്ദേശം,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		സ്ഥിരസ്ഥിതി:
			സ്വതന്ത്രം(സന്ദേശം);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			തിരികെ (-1);
		}
	}
	sshbuf_free(buffer);
	തിരികെ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
സ്ഥിതം അക്ഷരം *
fake_password(സ്ഥിരം അക്ഷരം *wire_password)
{
	സ്ഥിരം അക്ഷരം junk[] = "\b\n\r\177INCORRECT";
	അക്ഷരം *ret = ശൂന്യ;
	size_t i, l = wire_password != ശൂന്യ ? strlen(wire_password) : 0;

	എങ്കിൽ (l >= INT_MAX)
		fatal_f("password length too long: %zu", l);

	ret = malloc(l + 1);
	എങ്കിൽ (ret == ശൂന്യ)
		തിരികെ ശൂന്യ;
	വേണ്ടി (i = 0; i < l; i++)
		ret[i] = junk[i % (വലുപ്പം(junk) - 1)];
	ret[i] = '\0';
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_respond(ശൂന്യം *ctx, u_int അക്കം, അക്ഷരം **resp)
{
	ഘടന sshbuf *buffer;
	ഘടന pam_ctxt *ctxt = ctx;
	അക്ഷരം *fake;
	പൂർണ്ണസംഖ്യ r;

	debug2_f("PAM: entering, %u responses", അക്കം);
	തിരഞ്ഞെടുപ്പ് (ctxt->pam_done) {
	അവസ്ഥ SshPamAuthenticated:
		sshpam_authenticated = 1;
		തിരികെ (0);
	അവസ്ഥ SshPamNone:
		നിർത്തുക;
	അവസ്ഥ SshPamAgain:
		തിരികെ 1;	/* KbdintResultAgain */
	സ്ഥിരസ്ഥിതി:
		തിരികെ (-1);
	}
	എങ്കിൽ (അക്കം != 1) {
		error("PAM: expected one response, got %u", അക്കം);
		തിരികെ (-1);
	}
	എങ്കിൽ ((buffer = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_വേര്_login == PERMIT_YES)) {
		എങ്കിൽ ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} അല്ലെങ്കിൽ {
		fake = fake_password(*resp);
		എങ്കിൽ ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		സ്വതന്ത്രം(fake);
	}
	എങ്കിൽ (ssh_സന്ദേശം_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		തിരികെ (-1);
	}
	sshbuf_free(buffer);
	തിരികെ (1);
}

സ്ഥിതം ശൂന്യം
sshpam_free_ctx(ശൂന്യം *ctxtp)
{
	ഘടന pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	സ്വതന്ത്രം(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

പൂർണ്ണസംഖ്യ
sshpam_priv_kbdint_authdone(ശൂന്യം *ctxtp)
{
	ഘടന pam_ctxt *ctxt = ctxtp;

	തിരികെ ctxt->pam_done == SshPamAuthenticated;
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
ശൂന്യം
start_pam(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	എങ്കിൽ (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	എങ്കിൽ (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

ശൂന്യം
finish_pam(ശൂന്യം)
{
	sshpam_cleanup();
}


u_int
do_pam_account(ശൂന്യം)
{
	debug_f("called");
	എങ്കിൽ (sshpam_account_status != -1)
		തിരികെ (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	എങ്കിൽ (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		തിരികെ (sshpam_account_status);
	}

	എങ്കിൽ (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	തിരികെ (sshpam_account_status);
}

ശൂന്യം
do_pam_setcred(ശൂന്യം)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (സ്ഥിരം ശൂന്യം *)&store_conv);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	എങ്കിൽ (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		തിരികെ;
	}
	എങ്കിൽ (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	അല്ലെങ്കിൽ
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

ശൂന്യം
do_pam_session(ഘടന ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (സ്ഥിരം ശൂന്യം *)&store_conv);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	എങ്കിൽ (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	അല്ലെങ്കിൽ {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

പൂർണ്ണസംഖ്യ
is_pam_session_open(ശൂന്യം)
{
	തിരികെ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
പൂർണ്ണസംഖ്യ
do_pam_putenv(അക്ഷരം *name, അക്ഷരം *മൂല്യം)
{
	പൂർണ്ണസംഖ്യ ret = 1;
	അക്ഷരം *compound;
	size_t len;

	len = strlen(name) + strlen(മൂല്യം) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, മൂല്യം);
	ret = pam_putenv(sshpam_handle, compound);
	സ്വതന്ത്രം(compound);

	തിരികെ (ret);
}

അക്ഷരം **
fetch_pam_child_environment(ശൂന്യം)
{
	തിരികെ sshpam_env;
}

അക്ഷരം **
fetch_pam_environment(ശൂന്യം)
{
	തിരികെ (pam_getenvlist(sshpam_handle));
}

ശൂന്യം
free_pam_environment(അക്ഷരം **env)
{
	അക്ഷരം **envp;

	എങ്കിൽ (env == ശൂന്യ)
		തിരികെ;

	വേണ്ടി (envp = env; *envp; envp++)
		സ്വതന്ത്രം(*envp);
	സ്വതന്ത്രം(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshpam_passwd_conv(പൂർണ്ണസംഖ്യ n, sshpam_const ഘടന pam_message **സന്ദേശം,
    ഘടന pam_response **resp, ശൂന്യം *data)
{
	ഘടന pam_response *reply;
	പൂർണ്ണസംഖ്യ r, i;
	size_t len;

	debug3_f("PAM: called with %d messages", n);

	*resp = ശൂന്യ;

	എങ്കിൽ (n <= 0 || n > PAM_MAX_അക്കം_സന്ദേശം)
		തിരികെ (PAM_CONV_ERR);

	എങ്കിൽ ((reply = calloc(n, വലുപ്പം(*reply))) == ശൂന്യ)
		തിരികെ (PAM_CONV_ERR);

	വേണ്ടി (i = 0; i < n; ++i) {
		തിരഞ്ഞെടുപ്പ് (PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം_style)) {
		അവസ്ഥ PAM_PROMPT_ECHO_OFF:
			എങ്കിൽ (sshpam_password == ശൂന്യ)
				പോകുക fail;
			എങ്കിൽ ((reply[i].resp = strdup(sshpam_password)) == ശൂന്യ)
				പോകുക fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			നിർത്തുക;
		അവസ്ഥ PAM_ERROR_സന്ദേശം:
		അവസ്ഥ PAM_TEXT_INFO:
			len = strlen(PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം));
			എങ്കിൽ (len > 0) {
				എങ്കിൽ ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_സന്ദേശം_MEMBER(സന്ദേശം, i, സന്ദേശം))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			എങ്കിൽ ((reply[i].resp = strdup("")) == ശൂന്യ)
				പോകുക fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			പോകുക fail;
		}
	}
	*resp = reply;
	തിരികെ (PAM_SUCCESS);

 fail:
	വേണ്ടി(i = 0; i < n; i++) {
		സ്വതന്ത്രം(reply[i].resp);
	}
	സ്വതന്ത്രം(reply);
	തിരികെ (PAM_CONV_ERR);
}

സ്ഥിതം ഘടന pam_conv passwd_conv = { sshpam_passwd_conv, ശൂന്യ };

/*
 * Attempt password authentication via PAM
 */
പൂർണ്ണസംഖ്യ
sshpam_auth_passwd(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *password)
{
	പൂർണ്ണസംഖ്യ flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	അക്ഷരം *fake = ശൂന്യ;

	എങ്കിൽ (!options.use_pam || sshpam_handle == ശൂന്യ)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	എങ്കിൽ (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_വേര്_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (സ്ഥിരം ശൂന്യം *)&passwd_conv);
	എങ്കിൽ (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = ശൂന്യ;
	സ്വതന്ത്രം(fake);
	എങ്കിൽ (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	എങ്കിൽ (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	എങ്കിൽ (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		തിരികെ 1;
	} അല്ലെങ്കിൽ {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		തിരികെ 0;
	}
}

പൂർണ്ണസംഖ്യ
sshpam_get_maxtries_reached(ശൂന്യം)
{
	തിരികെ sshpam_maxtries_reached;
}

ശൂന്യം
sshpam_set_maxtries_reached(പൂർണ്ണസംഖ്യ reached)
{
	എങ്കിൽ (reached == 0 || sshpam_maxtries_reached)
		തിരികെ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
