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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#ifdef USE_PAM
#यदि defined(HAVE_SECURITY_PAM_APPL_H)
#अन्तर्भाव <security/pam_appl.h>
#अथवायदि defined (HAVE_PAM_PAM_APPL_H)
#अन्तर्भाव <pam/pam_appl.h>
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#ifdef PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#अन्यथा
# define sshpam_const	अचर	/* LinuxPAM, OpenPAM, AIX */
#endif

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#ifdef PAM_SUN_CODEBASE
# define PAM_सन्देश_MEMBER(सन्देश, n, member) ((*(सन्देश))[(n)].member)
#अन्यथा
# define PAM_सन्देश_MEMBER(सन्देश, n, member) ((सन्देश)[(n)]->member)
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "auth-options.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "srclimit.h"

बाह्य ServerOptions options;
बाह्य संरचना sshbuf *loginmsg;
बाह्य u_int utmp_len;

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
#अन्तर्भाव <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
प्रकारनिर्देश pthread_t sp_pthread_t;
#अन्यथा
प्रकारनिर्देश pid_t sp_pthread_t;
#define pthread_exit	fake_pthread_exit
#define pthread_create	fake_pthread_create
#define pthread_cancel	fake_pthread_cancel
#define pthread_join	fake_pthread_join
#endif

प्रकारनिर्देश पूर्णाङ्क SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1
#define SshPamAgain 2

संरचना pam_ctxt {
	sp_pthread_t	 pam_thread;
	पूर्णाङ्क		 pam_psock;
	पूर्णाङ्क		 pam_csock;
	SshPamDone	 pam_done;
};

स्थिर शून्य sshpam_free_ctx(शून्य *);
स्थिर संरचना pam_ctxt *cleanup_ctxt;

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

स्थिर पूर्णाङ्क sshpam_thread_status = -1;
स्थिर sshsig_t sshpam_oldsig;

स्थिर शून्य
sshpam_sigchld_handler(पूर्णाङ्क sig)
{
	ssh_signal(SIGCHLD, संक_पूर्व);
	यदि (cleanup_ctxt == रिक्त)
		फर्काऊ;	/* handler called after PAM cleanup, shouldn't happen */
	यदि (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		समाप्त(cleanup_ctxt->pam_thread, संक_इति);
		जबसम्म (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			यदि (त्रुटि_सं == EINTR)
				जारी;
			फर्काऊ;
		}
	}
	यदि (sshpam_thread_status == -1)
		फर्काऊ;
	यदि (WIFSIGNALED(sshpam_thread_status)) {
		यदि (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_exit(EXIT_CHILD_CRASH);
	} अन्यथा यदि (!WIFEXITED(sshpam_thread_status))
		_exit(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
स्थिर शून्य
pthread_exit(शून्य *मान)
{
	_exit(0);
}

/* ARGSUSED */
स्थिर पूर्णाङ्क
pthread_create(sp_pthread_t *thread, अचर शून्य *attr,
    शून्य *(*thread_start)(शून्य *), शून्य *arg)
{
	pid_t pid;
	संरचना pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	विकल्प ((pid = विभाजन())) {
	पक्ष -1:
		error("fork(): %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ त्रुटि_सं;
	पक्ष 0:
		बंद(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	स्वभाव:
		*thread = pid;
		बंद(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		फर्काऊ (0);
	}
}

स्थिर पूर्णाङ्क
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	फर्काऊ (समाप्त(thread, संक_इति));
}

/* ARGSUSED */
स्थिर पूर्णाङ्क
pthread_join(sp_pthread_t thread, शून्य **मान)
{
	पूर्णाङ्क status;

	यदि (sshpam_thread_status != -1)
		फर्काऊ (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	जबसम्म (waitpid(thread, &status, 0) == -1) {
		यदि (त्रुटि_सं == EINTR)
			जारी;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	फर्काऊ (status);
}
#endif


स्थिर pam_handle_t *sshpam_handle = रिक्त;
स्थिर वर्ण *sshpam_initial_user;
स्थिर पूर्णाङ्क sshpam_err = 0;
स्थिर पूर्णाङ्क sshpam_authenticated = 0;
स्थिर पूर्णाङ्क sshpam_session_open = 0;
स्थिर पूर्णाङ्क sshpam_cred_established = 0;
स्थिर पूर्णाङ्क sshpam_account_status = -1;
स्थिर पूर्णाङ्क sshpam_maxtries_reached = 0;
स्थिर वर्ण **sshpam_env = रिक्त;
स्थिर Authctxt *sshpam_authctxt = रिक्त;
स्थिर अचर वर्ण *sshpam_password = रिक्त;
स्थिर वर्ण *sshpam_rhost = रिक्त;
स्थिर वर्ण *sshpam_laddr = रिक्त;

/* Some PAM implementations don't implement this */
#ifndef HAVE_PAM_GETENVLIST
स्थिर वर्ण **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 फर्काऊ रिक्त;
}
#endif

#ifndef HAVE_PAM_PUTENV
स्थिर पूर्णाङ्क
pam_putenv(pam_handle_t *pamh, अचर वर्ण *name_मान)
{
	फर्काऊ PAM_SUCCESS;
}
#endif /* HAVE_PAM_PUTENV */

स्थिर शून्य
sshpam_password_change_required(पूर्णाङ्क reqd)
{
	बाह्य संरचना sshauthopt *auth_opts;
	स्थिर पूर्णाङ्क saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	यदि (sshpam_authctxt == रिक्त)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	यदि (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} अन्यथा {
		यदि (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		यदि (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		यदि (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
स्थिर शून्य
import_environments(संरचना sshbuf *b)
{
	वर्ण *env;
	u_int n, i, अङ्क_env;
	पूर्णाङ्क r;

	debug3_f("entering");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	यदि ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	यदि (n > पूर्णांक_उच्च)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (पूर्णाङ्क)n;
	यदि ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	यदि ((r = sshbuf_get_u32(b, &अङ्क_env)) != 0)
		fatal_fr(r, "buffer error");
	यदि (अङ्क_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    अङ्क_env);
	}
	sshpam_env = xcalloc(अङ्क_env + 1, परिमाण(*sshpam_env));
	debug3("PAM: num env strings %u", अङ्क_env);
	लागि(i = 0; i < अङ्क_env; i++) {
		यदि ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), रिक्त)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[अङ्क_env] = रिक्त;

	/* Import PAM environment from subprocess */
	यदि ((r = sshbuf_get_u32(b, &अङ्क_env)) != 0)
		fatal_fr(r, "buffer error");
	यदि (अङ्क_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    अङ्क_env);
	}
	debug("PAM: num PAM env strings %u", अङ्क_env);
	लागि (i = 0; i < अङ्क_env; i++) {
		यदि ((r = sshbuf_get_cstring(b, &env, रिक्त)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		यदि ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
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
स्थिर पूर्णाङ्क
sshpam_thread_conv(पूर्णाङ्क n, sshpam_const संरचना pam_message **सन्देश,
    संरचना pam_response **resp, शून्य *data)
{
	संरचना sshbuf *buffer;
	संरचना pam_ctxt *ctxt;
	संरचना pam_response *reply;
	पूर्णाङ्क r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = रिक्त;

	यदि (data == रिक्त) {
		error("PAM: conversation function passed a null context");
		फर्काऊ (PAM_CONV_ERR);
	}
	ctxt = data;
	यदि (n <= 0 || n > PAM_MAX_अङ्क_सन्देश)
		फर्काऊ (PAM_CONV_ERR);

	यदि ((reply = सुस्मृति(n, परिमाण(*reply))) == रिक्त)
		फर्काऊ PAM_CONV_ERR;
	यदि ((buffer = sshbuf_new()) == रिक्त) {
		मुक्त(reply);
		फर्काऊ PAM_CONV_ERR;
	}

	लागि (i = 0; i < n; ++i) {
		विकल्प (PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style)) {
		पक्ष PAM_PROMPT_ECHO_OFF:
		पक्ष PAM_PROMPT_ECHO_ON:
			यदि ((r = sshbuf_put_cstring(buffer,
			    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			यदि (ssh_सन्देश_send(ctxt->pam_csock,
			    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style), buffer) == -1)
				गच्छ fail;

			यदि (ssh_सन्देश_recv(ctxt->pam_csock, buffer) == -1)
				गच्छ fail;
			यदि ((r = sshbuf_get_u8(buffer, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			यदि (status != PAM_AUTHTOK)
				गच्छ fail;
			यदि ((r = sshbuf_get_cstring(buffer,
			    &reply[i].resp, रिक्त)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			रोक;
		पक्ष PAM_ERROR_सन्देश:
		पक्ष PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style),
			       PAM_सन्देश_MEMBER(सन्देश, i, सन्देश));
			यदि ((r = sshbuf_put_cstring(buffer,
			    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			यदि (ssh_सन्देश_send(ctxt->pam_csock,
			    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style), buffer) == -1)
				गच्छ fail;
			रोक;
		स्वभाव:
			गच्छ fail;
		}
		sshbuf_reset(buffer);
	}
	sshbuf_free(buffer);
	*resp = reply;
	फर्काऊ (PAM_SUCCESS);

 fail:
	लागि(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	sshbuf_free(buffer);
	फर्काऊ (PAM_CONV_ERR);
}

स्थिर पूर्णाङ्क
check_pam_user(Authctxt *authctxt)
{
	अचर वर्ण *pam_user;

	यदि (authctxt == रिक्त || authctxt->pw == रिक्त ||
	    authctxt->pw->pw_name == रिक्त)
		fatal_f("PAM authctxt user not initialized");

	यदि ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const शून्य **) &pam_user)) != PAM_SUCCESS)
		फर्काऊ sshpam_err;

	यदि (pam_user == रिक्त) {
		debug("PAM error: PAM_USER is NULL");
		फर्काऊ PAM_USER_UNKNOWN;
	}

	यदि (sshpam_initial_user == रिक्त)
		fatal_f("internal error: sshpam_initial_user NULL");
	यदि (म_भेद(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		फर्काऊ PAM_USER_UNKNOWN;
	}
	फर्काऊ PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
स्थिर शून्य *
sshpam_thread(शून्य *ctxtp)
{
	संरचना pam_ctxt *ctxt = ctxtp;
	संरचना sshbuf *buffer = रिक्त;
	संरचना pam_conv sshpam_conv;
	पूर्णाङ्क r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	बाह्य वर्ण **environ;
	वर्ण **env_from_pam;
	u_int i;
	अचर वर्ण *pam_user;
	अचर वर्ण **ptr_pam_user = &pam_user;
	वर्ण *tz = दो_पर्या("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const शून्य **)ptr_pam_user);
	यदि (sshpam_err != PAM_SUCCESS)
		गच्छ auth_fail;

	environ[0] = रिक्त;
	यदि (tz != रिक्त)
		यदि (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    म_त्रुटि(त्रुटि_सं));

	यदि (sshpam_authctxt != रिक्त) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#endif

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	यदि (sshpam_authctxt == रिक्त)
		fatal_f("PAM authctxt not initialized");

	यदि ((buffer = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (अचर शून्य *)&sshpam_conv);
	यदि (sshpam_err != PAM_SUCCESS)
		गच्छ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	यदि (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	यदि (sshpam_err != PAM_SUCCESS)
		गच्छ auth_fail;
	यदि ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		गच्छ auth_fail;

	यदि (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		गच्छ auth_fail;
	}
	यदि (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		यदि (sshpam_err != PAM_SUCCESS)
			गच्छ auth_fail;
		sshpam_password_change_required(0);
	}

	यदि ((r = sshbuf_put_cstring(buffer, "OK")) != 0)
		fatal_fr(r, "buffer error");

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	यदि ((r = sshbuf_put_u32(buffer, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(buffer, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	लागि (i = 0; environ[i] != रिक्त; i++) {
		/*गन्ती*/
		यदि (i > पूर्णांक_उच्च)
			fatal_f("too many environment strings");
	}
	यदि ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	लागि (i = 0; environ[i] != रिक्त; i++) {
		यदि ((r = sshbuf_put_cstring(buffer, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	लागि (i = 0; env_from_pam != रिक्त && env_from_pam[i] != रिक्त; i++) {
		/*गन्ती*/
		यदि (i > पूर्णांक_उच्च)
			fatal_f("too many PAM environment strings");
	}
	यदि ((r = sshbuf_put_u32(buffer, i)) != 0)
		fatal_fr(r, "buffer error");
	लागि (i = 0; env_from_pam != रिक्त && env_from_pam[i] != रिक्त; i++) {
		यदि ((r = sshbuf_put_cstring(buffer, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#endif /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_सन्देश_send(ctxt->pam_csock, sshpam_err, buffer);
	sshbuf_free(buffer);
	pthread_exit(रिक्त);

 auth_fail:
	यदि ((r = sshbuf_put_cstring(buffer,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	यदि (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_सन्देश_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, buffer);
	अन्यथा यदि (sshpam_maxtries_reached)
		ssh_सन्देश_send(ctxt->pam_csock, PAM_MAXTRIES, buffer);
	अन्यथा
		ssh_सन्देश_send(ctxt->pam_csock, PAM_AUTH_ERR, buffer);
	sshbuf_free(buffer);
	pthread_exit(रिक्त);

	फर्काऊ (रिक्त); /* Avoid warning for non-pthread case */
}

शून्य
sshpam_thread_cleanup(शून्य)
{
	संरचना pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	यदि (ctxt != रिक्त && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, रिक्त);
		बंद(ctxt->pam_psock);
		बंद(ctxt->pam_csock);
		स_रखो(ctxt, 0, परिमाण(*ctxt));
		cleanup_ctxt = रिक्त;
	}
}

स्थिर पूर्णाङ्क
sshpam_null_conv(पूर्णाङ्क n, sshpam_const संरचना pam_message **सन्देश,
    संरचना pam_response **resp, शून्य *data)
{
	debug3_f("PAM: entering, %d messages", n);
	फर्काऊ (PAM_CONV_ERR);
}

स्थिर संरचना pam_conv null_conv = { sshpam_null_conv, रिक्त };

स्थिर पूर्णाङ्क
sshpam_store_conv(पूर्णाङ्क n, sshpam_const संरचना pam_message **सन्देश,
    संरचना pam_response **resp, शून्य *data)
{
	संरचना pam_response *reply;
	पूर्णाङ्क r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = रिक्त;

	यदि (n <= 0 || n > PAM_MAX_अङ्क_सन्देश)
		फर्काऊ (PAM_CONV_ERR);

	यदि ((reply = सुस्मृति(n, परिमाण(*reply))) == रिक्त)
		फर्काऊ (PAM_CONV_ERR);

	लागि (i = 0; i < n; ++i) {
		विकल्प (PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style)) {
		पक्ष PAM_ERROR_सन्देश:
		पक्ष PAM_TEXT_INFO:
			यदि ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			रोक;
		स्वभाव:
			गच्छ fail;
		}
	}
	*resp = reply;
	फर्काऊ (PAM_SUCCESS);

 fail:
	लागि(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	फर्काऊ (PAM_CONV_ERR);
}

स्थिर संरचना pam_conv store_conv = { sshpam_store_conv, रिक्त };

शून्य
sshpam_cleanup(शून्य)
{
	यदि (sshpam_handle == रिक्त || !mm_is_monitor())
		फर्काऊ;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (अचर शून्य *)&null_conv);
	यदि (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	यदि (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = रिक्त;
	मुक्त(sshpam_initial_user);
	sshpam_initial_user = रिक्त;
}

स्थिर पूर्णाङ्क
sshpam_init(संरचना ssh *ssh, Authctxt *authctxt)
{
	अचर वर्ण *user = authctxt->user;
	पूर्णाङ्क r;

	यदि (options.pam_service_name == रिक्त)
		fatal_f("internal error: NULL PAM service name");
#यदि defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_SIZE)
	/* Protect buggy PAM implementations from excessively long usernames */
	यदि (म_माप(user) >= PAM_MAX_RESP_SIZE)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#endif
	यदि (sshpam_handle == रिक्त && ssh == रिक्त)
		fatal("%s: called initially with no packet context", __func__);
	यदि (sshpam_handle != रिक्त) {
		/* We already have a PAM context; check if the user matches */
		यदि ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		फर्काऊ 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	यदि (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = रिक्त;
		फर्काऊ (-1);
	}

	यदि (ssh != रिक्त && sshpam_rhost == रिक्त) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	यदि (sshpam_rhost != रिक्त && म_भेद(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		यदि (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = रिक्त;
			फर्काऊ (-1);
		}
	}
	यदि (ssh != रिक्त && sshpam_laddr != रिक्त) {
		वर्ण *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		यदि ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		मुक्त(conninfo);
	}

#ifdef PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	यदि (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = रिक्त;
		फर्काऊ (-1);
	}
#endif
	फर्काऊ (0);
}

स्थिर शून्य
expose_authinfo(अचर वर्ण *caller)
{
	वर्ण *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	यदि (sshpam_authctxt->session_info == रिक्त)
		auth_info = xstrdup("");
	अन्यथा यदि ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	मुक्त(auth_info);
}

स्थिर शून्य *
sshpam_init_ctx(Authctxt *authctxt)
{
	संरचना pam_ctxt *ctxt;
	पूर्णाङ्क result, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	यदि (!options.use_pam || sshpam_account_status == 0)
		फर्काऊ रिक्त;

	/* Initialize PAM */
	यदि (sshpam_init(रिक्त, authctxt) == -1) {
		error("PAM: initialization failed");
		फर्काऊ (रिक्त);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, परिमाण *ctxt);

	/* Start the authentication thread */
	यदि (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", म_त्रुटि(त्रुटि_सं));
		मुक्त(ctxt);
		फर्काऊ (रिक्त);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, रिक्त, sshpam_thread, ctxt);
	यदि (result != 0) {
		error("PAM: failed to start authentication thread: %s",
		    म_त्रुटि(result));
		बंद(socks[0]);
		बंद(socks[1]);
		मुक्त(ctxt);
		फर्काऊ (रिक्त);
	}
	cleanup_ctxt = ctxt;
	फर्काऊ (ctxt);
}

स्थिर पूर्णाङ्क
sshpam_query(शून्य *ctx, वर्ण **name, वर्ण **info,
    u_int *अङ्क, वर्ण ***prompts, u_int **echo_on)
{
	संरचना sshbuf *buffer;
	संरचना pam_ctxt *ctxt = ctx;
	u_char type;
	वर्ण *सन्देश;
	माप_प्रकार mlen, nmesg = 0;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि ((buffer = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = रिक्त;
	*अङ्क = 0;
	ctxt->pam_done = SshPamNone;

	जबसम्म (ssh_सन्देश_recv(ctxt->pam_psock, buffer) == 0) {
		यदि (++nmesg > PAM_MAX_अङ्क_सन्देश)
			fatal_f("too many query messages");
		यदि ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
		    (r = sshbuf_get_cstring(buffer, &सन्देश, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		विकल्प (type) {
		पक्ष PAM_PROMPT_ECHO_ON:
		पक्ष PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, परिमाण(वर्ण *));
			*echo_on = xcalloc(1, परिमाण(u_int));
			(*prompts)[0] = सन्देश;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*अङ्क = 1;
			sshbuf_free(buffer);
			फर्काऊ (0);
		पक्ष PAM_ERROR_सन्देश:
		पक्ष PAM_TEXT_INFO:
			मुक्त(*info);
			*info = सन्देश; /* transfer ownership */
			सन्देश = रिक्त;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(buffer);
			फर्काऊ (0);
		पक्ष PAM_ACCT_EXPIRED:
		पक्ष PAM_MAXTRIES:
			यदि (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			यदि (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		पक्ष PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		पक्ष PAM_SUCCESS:
			यदि (type == PAM_SUCCESS) {
				यदि (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_जरा_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(buffer);
				ctxt->pam_done = SshPamAuthenticated;
				मुक्त(सन्देश);
				sshbuf_free(buffer);
				फर्काऊ (0);
			}
			error("PAM: %s for %s%.100s from %.100s", सन्देश,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		स्वभाव:
			मुक्त(सन्देश);
			ctxt->pam_done = SshPamError;
			sshbuf_free(buffer);
			फर्काऊ (-1);
		}
	}
	sshbuf_free(buffer);
	फर्काऊ (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
स्थिर वर्ण *
fake_password(अचर वर्ण *wire_password)
{
	अचर वर्ण junk[] = "\b\n\r\177INCORRECT";
	वर्ण *ret = रिक्त;
	माप_प्रकार i, l = wire_password != रिक्त ? म_माप(wire_password) : 0;

	यदि (l >= पूर्णांक_उच्च)
		fatal_f("password length too long: %zu", l);

	ret = दो_स्मृति(l + 1);
	यदि (ret == रिक्त)
		फर्काऊ रिक्त;
	लागि (i = 0; i < l; i++)
		ret[i] = junk[i % (परिमाण(junk) - 1)];
	ret[i] = '\0';
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
sshpam_respond(शून्य *ctx, u_int अङ्क, वर्ण **resp)
{
	संरचना sshbuf *buffer;
	संरचना pam_ctxt *ctxt = ctx;
	वर्ण *fake;
	पूर्णाङ्क r;

	debug2_f("PAM: entering, %u responses", अङ्क);
	विकल्प (ctxt->pam_done) {
	पक्ष SshPamAuthenticated:
		sshpam_authenticated = 1;
		फर्काऊ (0);
	पक्ष SshPamNone:
		रोक;
	पक्ष SshPamAgain:
		फर्काऊ 1;	/* KbdintResultAgain */
	स्वभाव:
		फर्काऊ (-1);
	}
	यदि (अङ्क != 1) {
		error("PAM: expected one response, got %u", अङ्क);
		फर्काऊ (-1);
	}
	यदि ((buffer = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_जरा_login == PERMIT_YES)) {
		यदि ((r = sshbuf_put_cstring(buffer, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} अन्यथा {
		fake = fake_password(*resp);
		यदि ((r = sshbuf_put_cstring(buffer, fake)) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(fake);
	}
	यदि (ssh_सन्देश_send(ctxt->pam_psock, PAM_AUTHTOK, buffer) == -1) {
		sshbuf_free(buffer);
		फर्काऊ (-1);
	}
	sshbuf_free(buffer);
	फर्काऊ (1);
}

स्थिर शून्य
sshpam_free_ctx(शून्य *ctxtp)
{
	संरचना pam_ctxt *ctxt = ctxtp;

	debug3_f("entering");
	sshpam_thread_cleanup();
	मुक्त(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

पूर्णाङ्क
sshpam_priv_kbdint_authdone(शून्य *ctxtp)
{
	संरचना pam_ctxt *ctxt = ctxtp;

	फर्काऊ ctxt->pam_done == SshPamAuthenticated;
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
शून्य
start_pam(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	यदि (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	यदि (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

शून्य
finish_pam(शून्य)
{
	sshpam_cleanup();
}


u_int
do_pam_account(शून्य)
{
	debug_f("called");
	यदि (sshpam_account_status != -1)
		फर्काऊ (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	यदि (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		फर्काऊ (sshpam_account_status);
	}

	यदि (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	फर्काऊ (sshpam_account_status);
}

शून्य
do_pam_setcred(शून्य)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (अचर शून्य *)&store_conv);
	यदि (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	यदि (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		फर्काऊ;
	}
	यदि (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	अन्यथा
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

शून्य
do_pam_session(संरचना ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (अचर शून्य *)&store_conv);
	यदि (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	यदि (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	अन्यथा {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

पूर्णाङ्क
is_pam_session_open(शून्य)
{
	फर्काऊ sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
पूर्णाङ्क
do_pam_putenv(वर्ण *name, वर्ण *मान)
{
	पूर्णाङ्क ret = 1;
	वर्ण *compound;
	माप_प्रकार len;

	len = म_माप(name) + म_माप(मान) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, मान);
	ret = pam_putenv(sshpam_handle, compound);
	मुक्त(compound);

	फर्काऊ (ret);
}

वर्ण **
fetch_pam_child_environment(शून्य)
{
	फर्काऊ sshpam_env;
}

वर्ण **
fetch_pam_environment(शून्य)
{
	फर्काऊ (pam_getenvlist(sshpam_handle));
}

शून्य
free_pam_environment(वर्ण **env)
{
	वर्ण **envp;

	यदि (env == रिक्त)
		फर्काऊ;

	लागि (envp = env; *envp; envp++)
		मुक्त(*envp);
	मुक्त(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
स्थिर पूर्णाङ्क
sshpam_passwd_conv(पूर्णाङ्क n, sshpam_const संरचना pam_message **सन्देश,
    संरचना pam_response **resp, शून्य *data)
{
	संरचना pam_response *reply;
	पूर्णाङ्क r, i;
	माप_प्रकार len;

	debug3_f("PAM: called with %d messages", n);

	*resp = रिक्त;

	यदि (n <= 0 || n > PAM_MAX_अङ्क_सन्देश)
		फर्काऊ (PAM_CONV_ERR);

	यदि ((reply = सुस्मृति(n, परिमाण(*reply))) == रिक्त)
		फर्काऊ (PAM_CONV_ERR);

	लागि (i = 0; i < n; ++i) {
		विकल्प (PAM_सन्देश_MEMBER(सन्देश, i, सन्देश_style)) {
		पक्ष PAM_PROMPT_ECHO_OFF:
			यदि (sshpam_password == रिक्त)
				गच्छ fail;
			यदि ((reply[i].resp = strdup(sshpam_password)) == रिक्त)
				गच्छ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			रोक;
		पक्ष PAM_ERROR_सन्देश:
		पक्ष PAM_TEXT_INFO:
			len = म_माप(PAM_सन्देश_MEMBER(सन्देश, i, सन्देश));
			यदि (len > 0) {
				यदि ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_सन्देश_MEMBER(सन्देश, i, सन्देश))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			यदि ((reply[i].resp = strdup("")) == रिक्त)
				गच्छ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			रोक;
		स्वभाव:
			गच्छ fail;
		}
	}
	*resp = reply;
	फर्काऊ (PAM_SUCCESS);

 fail:
	लागि(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	फर्काऊ (PAM_CONV_ERR);
}

स्थिर संरचना pam_conv passwd_conv = { sshpam_passwd_conv, रिक्त };

/*
 * Attempt password authentication via PAM
 */
पूर्णाङ्क
sshpam_auth_passwd(Authctxt *authctxt, अचर वर्ण *password)
{
	पूर्णाङ्क flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	वर्ण *fake = रिक्त;

	यदि (!options.use_pam || sshpam_handle == रिक्त)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	यदि (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_जरा_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (अचर शून्य *)&passwd_conv);
	यदि (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = रिक्त;
	मुक्त(fake);
	यदि (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	यदि (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	यदि (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		फर्काऊ 1;
	} अन्यथा {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		फर्काऊ 0;
	}
}

पूर्णाङ्क
sshpam_get_maxtries_reached(शून्य)
{
	फर्काऊ sshpam_maxtries_reached;
}

शून्य
sshpam_set_maxtries_reached(पूर्णाङ्क reached)
{
	यदि (reached == 0 || sshpam_maxtries_reached)
		फर्काऊ;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#endif /* USE_PAM */
