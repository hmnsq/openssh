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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/wait.h>

#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित USE_PAM
#अगर defined(HAVE_SECURITY_PAM_APPL_H)
#समावेश <security/pam_appl.h>
#या_अगर defined (HAVE_PAM_PAM_APPL_H)
#समावेश <pam/pam_appl.h>
#पूर्ण_अगर

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#अगर_घोषित PAM_SUN_CODEBASE
# define sshpam_const		/* Solaris, HP-UX, SunOS */
#अन्यथा
# define sshpam_const	स्थिर	/* LinuxPAM, OpenPAM, AIX */
#पूर्ण_अगर

/* Ambiguity in spec: is it an array of pointers or a pointer to an array? */
#अगर_घोषित PAM_SUN_CODEBASE
# define PAM_संदेश_MEMBER(संदेश, n, member) ((*(संदेश))[(n)].member)
#अन्यथा
# define PAM_संदेश_MEMBER(संदेश, n, member) ((संदेश)[(n)]->member)
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-pam.h"
#समावेश "canohost.h"
#समावेश "log.h"
#समावेश "msg.h"
#समावेश "packet.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "ssh2.h"
#समावेश "auth-options.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "srclimit.h"

बाह्य ServerOptions options;
बाह्य काष्ठा sshbuf *loginmsg;
बाह्य u_int utmp_len;

/* so we don't silently change behaviour */
#अगर_घोषित USE_POSIX_THREADS
# error "USE_POSIX_THREADS replaced by UNSUPPORTED_POSIX_THREADS_HACK"
#पूर्ण_अगर

/*
 * Formerly known as USE_POSIX_THREADS, using this is completely unsupported
 * and generally a bad idea.  Use at own risk and do not expect support if
 * this breaks.
 */
#अगर_घोषित UNSUPPORTED_POSIX_THREADS_HACK
#समावेश <pthread.h>
/*
 * Avoid namespace clash when *not* using pthreads for systems *with*
 * pthreads, which unconditionally define pthread_t via sys/types.h
 * (e.g. Linux)
 */
प्रकार pthread_t sp_pthread_t;
#अन्यथा
प्रकार pid_t sp_pthread_t;
#घोषणा pthread_exit	fake_pthread_exit
#घोषणा pthread_create	fake_pthread_create
#घोषणा pthread_cancel	fake_pthread_cancel
#घोषणा pthread_join	fake_pthread_join
#पूर्ण_अगर

प्रकार पूर्णांक SshPamDone;
#घोषणा SshPamError -1
#घोषणा SshPamNone 0
#घोषणा SshPamAuthenticated 1
#घोषणा SshPamAgain 2

काष्ठा pam_ctxt {
	sp_pthread_t	 pam_thread;
	पूर्णांक		 pam_psock;
	पूर्णांक		 pam_csock;
	SshPamDone	 pam_done;
};

अटल व्योम sshpam_free_ctx(व्योम *);
अटल काष्ठा pam_ctxt *cleanup_ctxt;

#अगर_अघोषित UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

अटल पूर्णांक sshpam_thread_status = -1;
अटल sshsig_t sshpam_oldsig;

अटल व्योम
sshpam_sigchld_handler(पूर्णांक sig)
{
	ssh_signal(SIGCHLD, संक_पूर्व);
	अगर (cleanup_ctxt == शून्य)
		वापस;	/* handler called after PAM cleanup, shouldn't happen */
	अगर (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
	    <= 0) {
		/* PAM thread has not exited, privsep slave must have */
		समाप्त(cleanup_ctxt->pam_thread, संक_इति);
		जबतक (waitpid(cleanup_ctxt->pam_thread,
		    &sshpam_thread_status, 0) == -1) {
			अगर (त्रुटि_सं == EINTR)
				जारी;
			वापस;
		}
	}
	अगर (sshpam_thread_status == -1)
		वापस;
	अगर (WIFSIGNALED(sshpam_thread_status)) {
		अगर (signal_is_crash(WTERMSIG(sshpam_thread_status)))
			_निकास(EXIT_CHILD_CRASH);
	} अन्यथा अगर (!WIFEXITED(sshpam_thread_status))
		_निकास(EXIT_CHILD_CRASH);
}

/* ARGSUSED */
अटल व्योम
pthread_exit(व्योम *मूल्य)
{
	_निकास(0);
}

/* ARGSUSED */
अटल पूर्णांक
pthread_create(sp_pthread_t *thread, स्थिर व्योम *attr,
    व्योम *(*thread_start)(व्योम *), व्योम *arg)
{
	pid_t pid;
	काष्ठा pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	चयन ((pid = विभाजन())) {
	हाल -1:
		error("fork(): %s", म_त्रुटि(त्रुटि_सं));
		वापस त्रुटि_सं;
	हाल 0:
		बंद(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_निकास(1);
	शेष:
		*thread = pid;
		बंद(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = ssh_signal(SIGCHLD, sshpam_sigchld_handler);
		वापस (0);
	}
}

अटल पूर्णांक
pthread_cancel(sp_pthread_t thread)
{
	ssh_signal(SIGCHLD, sshpam_oldsig);
	वापस (समाप्त(thread, संक_इति));
}

/* ARGSUSED */
अटल पूर्णांक
pthread_join(sp_pthread_t thread, व्योम **मूल्य)
{
	पूर्णांक status;

	अगर (sshpam_thread_status != -1)
		वापस (sshpam_thread_status);
	ssh_signal(SIGCHLD, sshpam_oldsig);
	जबतक (waitpid(thread, &status, 0) == -1) {
		अगर (त्रुटि_सं == EINTR)
			जारी;
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	वापस (status);
}
#पूर्ण_अगर


अटल pam_handle_t *sshpam_handle = शून्य;
अटल अक्षर *sshpam_initial_user;
अटल पूर्णांक sshpam_err = 0;
अटल पूर्णांक sshpam_authenticated = 0;
अटल पूर्णांक sshpam_session_open = 0;
अटल पूर्णांक sshpam_cred_established = 0;
अटल पूर्णांक sshpam_account_status = -1;
अटल पूर्णांक sshpam_maxtries_reached = 0;
अटल अक्षर **sshpam_env = शून्य;
अटल Authctxt *sshpam_authctxt = शून्य;
अटल स्थिर अक्षर *sshpam_password = शून्य;
अटल अक्षर *sshpam_rhost = शून्य;
अटल अक्षर *sshpam_laddr = शून्य;

/* Some PAM implementations don't implement this */
#अगर_अघोषित HAVE_PAM_GETENVLIST
अटल अक्षर **
pam_getenvlist(pam_handle_t *pamh)
{
	/*
	 * XXX - If necessary, we can still support environment passing
	 * for platforms without pam_getenvlist by searching for known
	 * env vars (e.g. KRB5CCNAME) from the PAM environment.
	 */
	 वापस शून्य;
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_PAM_PUTENV
अटल पूर्णांक
pam_putenv(pam_handle_t *pamh, स्थिर अक्षर *name_मूल्य)
{
	वापस PAM_SUCCESS;
}
#पूर्ण_अगर /* HAVE_PAM_PUTENV */

अटल व्योम
sshpam_password_change_required(पूर्णांक reqd)
{
	बाह्य काष्ठा sshauthopt *auth_opts;
	अटल पूर्णांक saved_port, saved_agent, saved_x11;

	debug3_f("reqd=%d", reqd);
	अगर (sshpam_authctxt == शून्य)
		fatal_f("PAM authctxt not initialized");
	sshpam_authctxt->force_pwchange = reqd;
	अगर (reqd) {
		saved_port = auth_opts->permit_port_forwarding_flag;
		saved_agent = auth_opts->permit_agent_forwarding_flag;
		saved_x11 = auth_opts->permit_x11_forwarding_flag;
		auth_opts->permit_port_forwarding_flag = 0;
		auth_opts->permit_agent_forwarding_flag = 0;
		auth_opts->permit_x11_forwarding_flag = 0;
	} अन्यथा {
		अगर (saved_port)
			auth_opts->permit_port_forwarding_flag = saved_port;
		अगर (saved_agent)
			auth_opts->permit_agent_forwarding_flag = saved_agent;
		अगर (saved_x11)
			auth_opts->permit_x11_forwarding_flag = saved_x11;
	}
}

/* Import regular and PAM environment from subprocess */
अटल व्योम
import_environments(काष्ठा sshbuf *b)
{
	अक्षर *env;
	u_int n, i, अंक_env;
	पूर्णांक r;

	debug3_f("entering");

#अगर_अघोषित UNSUPPORTED_POSIX_THREADS_HACK
	/* Import variables set by do_pam_account */
	अगर ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	अगर (n > पूर्णांक_उच्च)
		fatal_f("invalid PAM account status %u", n);
	sshpam_account_status = (पूर्णांक)n;
	अगर ((r = sshbuf_get_u32(b, &n)) != 0)
		fatal_fr(r, "buffer error");
	sshpam_password_change_required(n != 0);

	/* Import environment from subprocess */
	अगर ((r = sshbuf_get_u32(b, &अंक_env)) != 0)
		fatal_fr(r, "buffer error");
	अगर (अंक_env > 1024) {
		fatal_f("received %u environment variables, expected <= 1024",
		    अंक_env);
	}
	sshpam_env = xcalloc(अंक_env + 1, माप(*sshpam_env));
	debug3("PAM: num env strings %u", अंक_env);
	क्रम(i = 0; i < अंक_env; i++) {
		अगर ((r = sshbuf_get_cstring(b, &(sshpam_env[i]), शून्य)) != 0)
			fatal_fr(r, "buffer error");
	}
	sshpam_env[अंक_env] = शून्य;

	/* Import PAM environment from subprocess */
	अगर ((r = sshbuf_get_u32(b, &अंक_env)) != 0)
		fatal_fr(r, "buffer error");
	अगर (अंक_env > 1024) {
		fatal_f("received %u PAM env variables, expected <= 1024",
		    अंक_env);
	}
	debug("PAM: num PAM env strings %u", अंक_env);
	क्रम (i = 0; i < अंक_env; i++) {
		अगर ((r = sshbuf_get_cstring(b, &env, शून्य)) != 0)
			fatal_fr(r, "buffer error");
		/* Errors are not fatal here */
		अगर ((r = pam_putenv(sshpam_handle, env)) != PAM_SUCCESS) {
			error("PAM: pam_putenv: %s",
			    pam_strerror(sshpam_handle, r));
		}
		/*
		 * XXX this possibly leaks env because it is not documented
		 * what pam_putenv() does with it. Does it copy it? Does it
		 * take ownership? We don't know, so it's safest just to leak.
		 */
	}
#पूर्ण_अगर
}

/*
 * Conversation function for authentication thread.
 */
अटल पूर्णांक
sshpam_thread_conv(पूर्णांक n, sshpam_const काष्ठा pam_message **संदेश,
    काष्ठा pam_response **resp, व्योम *तथ्य)
{
	काष्ठा sshbuf *बफर;
	काष्ठा pam_ctxt *ctxt;
	काष्ठा pam_response *reply;
	पूर्णांक r, i;
	u_char status;

	debug3_f("PAM: entering, %d messages", n);
	*resp = शून्य;

	अगर (तथ्य == शून्य) {
		error("PAM: conversation function passed a null context");
		वापस (PAM_CONV_ERR);
	}
	ctxt = तथ्य;
	अगर (n <= 0 || n > PAM_MAX_अंक_संदेश)
		वापस (PAM_CONV_ERR);

	अगर ((reply = सुस्मृति(n, माप(*reply))) == शून्य)
		वापस PAM_CONV_ERR;
	अगर ((बफर = sshbuf_new()) == शून्य) {
		मुक्त(reply);
		वापस PAM_CONV_ERR;
	}

	क्रम (i = 0; i < n; ++i) {
		चयन (PAM_संदेश_MEMBER(संदेश, i, संदेश_style)) {
		हाल PAM_PROMPT_ECHO_OFF:
		हाल PAM_PROMPT_ECHO_ON:
			अगर ((r = sshbuf_put_cstring(बफर,
			    PAM_संदेश_MEMBER(संदेश, i, संदेश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			अगर (ssh_संदेश_send(ctxt->pam_csock,
			    PAM_संदेश_MEMBER(संदेश, i, संदेश_style), बफर) == -1)
				जाओ fail;

			अगर (ssh_संदेश_recv(ctxt->pam_csock, बफर) == -1)
				जाओ fail;
			अगर ((r = sshbuf_get_u8(बफर, &status)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			अगर (status != PAM_AUTHTOK)
				जाओ fail;
			अगर ((r = sshbuf_get_cstring(बफर,
			    &reply[i].resp, शून्य)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			अवरोध;
		हाल PAM_ERROR_संदेश:
		हाल PAM_TEXT_INFO:
			debug3("PAM: Got message of type %d: %s",
			       PAM_संदेश_MEMBER(संदेश, i, संदेश_style),
			       PAM_संदेश_MEMBER(संदेश, i, संदेश));
			अगर ((r = sshbuf_put_cstring(बफर,
			    PAM_संदेश_MEMBER(संदेश, i, संदेश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			अगर (ssh_संदेश_send(ctxt->pam_csock,
			    PAM_संदेश_MEMBER(संदेश, i, संदेश_style), बफर) == -1)
				जाओ fail;
			अवरोध;
		शेष:
			जाओ fail;
		}
		sshbuf_reset(बफर);
	}
	sshbuf_free(बफर);
	*resp = reply;
	वापस (PAM_SUCCESS);

 fail:
	क्रम(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	sshbuf_free(बफर);
	वापस (PAM_CONV_ERR);
}

अटल पूर्णांक
check_pam_user(Authctxt *authctxt)
{
	स्थिर अक्षर *pam_user;

	अगर (authctxt == शून्य || authctxt->pw == शून्य ||
	    authctxt->pw->pw_name == शून्य)
		fatal_f("PAM authctxt user not initialized");

	अगर ((sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const व्योम **) &pam_user)) != PAM_SUCCESS)
		वापस sshpam_err;

	अगर (pam_user == शून्य) {
		debug("PAM error: PAM_USER is NULL");
		वापस PAM_USER_UNKNOWN;
	}

	अगर (sshpam_initial_user == शून्य)
		fatal_f("internal error: sshpam_initial_user NULL");
	अगर (म_भेद(sshpam_initial_user, pam_user) != 0) {
		error_f("PAM user \"%s\" does not match previous \"%s\"",
		      pam_user, sshpam_initial_user);
		वापस PAM_USER_UNKNOWN;
	}
	वापस PAM_SUCCESS;
}

/*
 * Authentication thread.
 */
अटल व्योम *
sshpam_thread(व्योम *ctxtp)
{
	काष्ठा pam_ctxt *ctxt = ctxtp;
	काष्ठा sshbuf *बफर = शून्य;
	काष्ठा pam_conv sshpam_conv;
	पूर्णांक r, flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
#अगर_अघोषित UNSUPPORTED_POSIX_THREADS_HACK
	बाह्य अक्षर **environ;
	अक्षर **env_from_pam;
	u_int i;
	स्थिर अक्षर *pam_user;
	स्थिर अक्षर **ptr_pam_user = &pam_user;
	अक्षर *tz = दो_पर्या("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
	    (sshpam_const व्योम **)ptr_pam_user);
	अगर (sshpam_err != PAM_SUCCESS)
		जाओ auth_fail;

	environ[0] = शून्य;
	अगर (tz != शून्य)
		अगर (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
			    म_त्रुटि(त्रुटि_सं));

	अगर (sshpam_authctxt != शून्य) {
		setproctitle("%s [pam]",
		    sshpam_authctxt->valid ? pam_user : "unknown");
	}
#पूर्ण_अगर

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	अगर (sshpam_authctxt == शून्य)
		fatal_f("PAM authctxt not initialized");

	अगर ((बफर = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (स्थिर व्योम *)&sshpam_conv);
	अगर (sshpam_err != PAM_SUCCESS)
		जाओ auth_fail;
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	अगर (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	अगर (sshpam_err != PAM_SUCCESS)
		जाओ auth_fail;
	अगर ((sshpam_err = check_pam_user(sshpam_authctxt)) != PAM_SUCCESS)
		जाओ auth_fail;

	अगर (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		जाओ auth_fail;
	}
	अगर (sshpam_authctxt->force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
		    PAM_CHANGE_EXPIRED_AUTHTOK);
		अगर (sshpam_err != PAM_SUCCESS)
			जाओ auth_fail;
		sshpam_password_change_required(0);
	}

	अगर ((r = sshbuf_put_cstring(बफर, "OK")) != 0)
		fatal_fr(r, "buffer error");

#अगर_अघोषित UNSUPPORTED_POSIX_THREADS_HACK
	/* Export variables set by do_pam_account */
	अगर ((r = sshbuf_put_u32(बफर, sshpam_account_status)) != 0 ||
	    (r = sshbuf_put_u32(बफर, sshpam_authctxt->force_pwchange)) != 0)
		fatal_fr(r, "buffer error");

	/* Export any environment strings set in child */
	क्रम (i = 0; environ[i] != शून्य; i++) {
		/*गिनती*/
		अगर (i > पूर्णांक_उच्च)
			fatal_f("too many environment strings");
	}
	अगर ((r = sshbuf_put_u32(बफर, i)) != 0)
		fatal_fr(r, "buffer error");
	क्रम (i = 0; environ[i] != शून्य; i++) {
		अगर ((r = sshbuf_put_cstring(बफर, environ[i])) != 0)
			fatal_fr(r, "buffer error");
	}
	/* Export any environment strings set by PAM in child */
	env_from_pam = pam_getenvlist(sshpam_handle);
	क्रम (i = 0; env_from_pam != शून्य && env_from_pam[i] != शून्य; i++) {
		/*गिनती*/
		अगर (i > पूर्णांक_उच्च)
			fatal_f("too many PAM environment strings");
	}
	अगर ((r = sshbuf_put_u32(बफर, i)) != 0)
		fatal_fr(r, "buffer error");
	क्रम (i = 0; env_from_pam != शून्य && env_from_pam[i] != शून्य; i++) {
		अगर ((r = sshbuf_put_cstring(बफर, env_from_pam[i])) != 0)
			fatal_fr(r, "buffer error");
	}
#पूर्ण_अगर /* UNSUPPORTED_POSIX_THREADS_HACK */

	/* XXX - can't do much about an error here */
	ssh_संदेश_send(ctxt->pam_csock, sshpam_err, बफर);
	sshbuf_free(बफर);
	pthread_exit(शून्य);

 auth_fail:
	अगर ((r = sshbuf_put_cstring(बफर,
	    pam_strerror(sshpam_handle, sshpam_err))) != 0)
		fatal_fr(r, "buffer error");
	/* XXX - can't do much about an error here */
	अगर (sshpam_err == PAM_ACCT_EXPIRED)
		ssh_संदेश_send(ctxt->pam_csock, PAM_ACCT_EXPIRED, बफर);
	अन्यथा अगर (sshpam_maxtries_reached)
		ssh_संदेश_send(ctxt->pam_csock, PAM_MAXTRIES, बफर);
	अन्यथा
		ssh_संदेश_send(ctxt->pam_csock, PAM_AUTH_ERR, बफर);
	sshbuf_free(बफर);
	pthread_exit(शून्य);

	वापस (शून्य); /* Avoid warning for non-pthread case */
}

व्योम
sshpam_thread_cleanup(व्योम)
{
	काष्ठा pam_ctxt *ctxt = cleanup_ctxt;

	debug3_f("entering");
	अगर (ctxt != शून्य && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, शून्य);
		बंद(ctxt->pam_psock);
		बंद(ctxt->pam_csock);
		स_रखो(ctxt, 0, माप(*ctxt));
		cleanup_ctxt = शून्य;
	}
}

अटल पूर्णांक
sshpam_null_conv(पूर्णांक n, sshpam_const काष्ठा pam_message **संदेश,
    काष्ठा pam_response **resp, व्योम *तथ्य)
{
	debug3_f("PAM: entering, %d messages", n);
	वापस (PAM_CONV_ERR);
}

अटल काष्ठा pam_conv null_conv = { sshpam_null_conv, शून्य };

अटल पूर्णांक
sshpam_store_conv(पूर्णांक n, sshpam_const काष्ठा pam_message **संदेश,
    काष्ठा pam_response **resp, व्योम *तथ्य)
{
	काष्ठा pam_response *reply;
	पूर्णांक r, i;

	debug3_f("PAM: called with %d messages", n);
	*resp = शून्य;

	अगर (n <= 0 || n > PAM_MAX_अंक_संदेश)
		वापस (PAM_CONV_ERR);

	अगर ((reply = सुस्मृति(n, माप(*reply))) == शून्य)
		वापस (PAM_CONV_ERR);

	क्रम (i = 0; i < n; ++i) {
		चयन (PAM_संदेश_MEMBER(संदेश, i, संदेश_style)) {
		हाल PAM_ERROR_संदेश:
		हाल PAM_TEXT_INFO:
			अगर ((r = sshbuf_putf(loginmsg, "%s\n",
			    PAM_संदेश_MEMBER(संदेश, i, संदेश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			reply[i].resp_retcode = PAM_SUCCESS;
			अवरोध;
		शेष:
			जाओ fail;
		}
	}
	*resp = reply;
	वापस (PAM_SUCCESS);

 fail:
	क्रम(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	वापस (PAM_CONV_ERR);
}

अटल काष्ठा pam_conv store_conv = { sshpam_store_conv, शून्य };

व्योम
sshpam_cleanup(व्योम)
{
	अगर (sshpam_handle == शून्य || !mm_is_monitor())
		वापस;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (स्थिर व्योम *)&null_conv);
	अगर (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	अगर (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = शून्य;
	मुक्त(sshpam_initial_user);
	sshpam_initial_user = शून्य;
}

अटल पूर्णांक
sshpam_init(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	स्थिर अक्षर *user = authctxt->user;
	पूर्णांक r;

	अगर (options.pam_service_name == शून्य)
		fatal_f("internal error: NULL PAM service name");
#अगर defined(PAM_SUN_CODEBASE) && defined(PAM_MAX_RESP_आकार)
	/* Protect buggy PAM implementations from excessively long usernames */
	अगर (म_माप(user) >= PAM_MAX_RESP_आकार)
		fatal("Username too long from %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#पूर्ण_अगर
	अगर (sshpam_handle == शून्य && ssh == शून्य)
		fatal("%s: called initially with no packet context", __func__);
	अगर (sshpam_handle != शून्य) {
		/* We already have a PAM context; check if the user matches */
		अगर ((sshpam_err = check_pam_user(authctxt)) != PAM_SUCCESS)
			fatal("PAM user mismatch");
		वापस 0;
	}
	debug("PAM: initializing for \"%s\" with service \"%s\"", user,
	    options.pam_service_name);
	sshpam_err = pam_start(options.pam_service_name, user,
	    &store_conv, &sshpam_handle);
	sshpam_initial_user = xstrdup(user);
	sshpam_authctxt = authctxt;

	अगर (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = शून्य;
		वापस (-1);
	}

	अगर (ssh != शून्य && sshpam_rhost == शून्य) {
		/*
		 * We need to cache these as we don't have packet context
		 * during the kbdint flow.
		 */
		sshpam_rhost = xstrdup(auth_get_canonical_hostname(ssh,
		    options.use_dns));
		sshpam_laddr = get_local_ipaddr(
		    ssh_packet_get_connection_in(ssh));
	}
	अगर (sshpam_rhost != शून्य && म_भेद(sshpam_rhost, "UNKNOWN") != 0) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
		    sshpam_rhost);
		अगर (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = शून्य;
			वापस (-1);
		}
	}
	अगर (ssh != शून्य && sshpam_laddr != शून्य) {
		अक्षर *conninfo;

		/* Put SSH_CONNECTION in the PAM environment too */
		xasprintf(&conninfo, "SSH_CONNECTION=%.50s %d %.50s %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    sshpam_laddr, ssh_local_port(ssh));
		अगर ((r = pam_putenv(sshpam_handle, conninfo)) != PAM_SUCCESS)
			logit("pam_putenv: %s", pam_strerror(sshpam_handle, r));
		मुक्त(conninfo);
	}

#अगर_घोषित PAM_TTY_KLUDGE
	/*
	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
	 * sshd doesn't set the tty until too late in the auth process and
	 * may not even set one (for tty-less connections)
	 */
	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	अगर (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = शून्य;
		वापस (-1);
	}
#पूर्ण_अगर
	वापस (0);
}

अटल व्योम
expose_authinfo(स्थिर अक्षर *caller)
{
	अक्षर *auth_info;

	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */
	अगर (sshpam_authctxt->session_info == शून्य)
		auth_info = xstrdup("");
	अन्यथा अगर ((auth_info = sshbuf_dup_string(
	    sshpam_authctxt->session_info)) == शून्य)
		fatal_f("sshbuf_dup_string failed");

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", auth_info);
	मुक्त(auth_info);
}

अटल व्योम *
sshpam_init_ctx(Authctxt *authctxt)
{
	काष्ठा pam_ctxt *ctxt;
	पूर्णांक परिणाम, socks[2];

	debug3_f("entering");
	/*
	 * Refuse to start if we don't have PAM enabled or do_pam_account
	 * has previously failed.
	 */
	अगर (!options.use_pam || sshpam_account_status == 0)
		वापस शून्य;

	/* Initialize PAM */
	अगर (sshpam_init(शून्य, authctxt) == -1) {
		error("PAM: initialization failed");
		वापस (शून्य);
	}

	expose_authinfo(__func__);
	ctxt = xcalloc(1, माप *ctxt);

	/* Start the authentication thread */
	अगर (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", म_त्रुटि(त्रुटि_सं));
		मुक्त(ctxt);
		वापस (शून्य);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	परिणाम = pthread_create(&ctxt->pam_thread, शून्य, sshpam_thread, ctxt);
	अगर (परिणाम != 0) {
		error("PAM: failed to start authentication thread: %s",
		    म_त्रुटि(परिणाम));
		बंद(socks[0]);
		बंद(socks[1]);
		मुक्त(ctxt);
		वापस (शून्य);
	}
	cleanup_ctxt = ctxt;
	वापस (ctxt);
}

अटल पूर्णांक
sshpam_query(व्योम *ctx, अक्षर **name, अक्षर **info,
    u_int *अंक, अक्षर ***prompts, u_int **echo_on)
{
	काष्ठा sshbuf *बफर;
	काष्ठा pam_ctxt *ctxt = ctx;
	u_char type;
	अक्षर *संदेश;
	माप_प्रकार mlen, nmesg = 0;
	पूर्णांक r;

	debug3_f("entering");
	अगर ((बफर = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	*name = xstrdup("");
	*info = xstrdup("");
	*prompts = शून्य;
	*अंक = 0;
	ctxt->pam_done = SshPamNone;

	जबतक (ssh_संदेश_recv(ctxt->pam_psock, बफर) == 0) {
		अगर (++nmesg > PAM_MAX_अंक_संदेश)
			fatal_f("too many query messages");
		अगर ((r = sshbuf_get_u8(बफर, &type)) != 0 ||
		    (r = sshbuf_get_cstring(बफर, &संदेश, &mlen)) != 0)
			fatal_fr(r, "buffer error");
		चयन (type) {
		हाल PAM_PROMPT_ECHO_ON:
		हाल PAM_PROMPT_ECHO_OFF:
			*prompts = xcalloc(1, माप(अक्षर *));
			*echo_on = xcalloc(1, माप(u_int));
			(*prompts)[0] = संदेश;	/* transfer ownership */
			(*echo_on)[0] = (type == PAM_PROMPT_ECHO_ON);
			*अंक = 1;
			sshbuf_free(बफर);
			वापस (0);
		हाल PAM_ERROR_संदेश:
		हाल PAM_TEXT_INFO:
			मुक्त(*info);
			*info = संदेश; /* transfer ownership */
			संदेश = शून्य;
			ctxt->pam_done = SshPamAgain;
			sshbuf_free(बफर);
			वापस (0);
		हाल PAM_ACCT_EXPIRED:
		हाल PAM_MAXTRIES:
			अगर (type == PAM_ACCT_EXPIRED)
				sshpam_account_status = 0;
			अगर (type == PAM_MAXTRIES)
				sshpam_set_maxtries_reached(1);
			/* FALLTHROUGH */
		हाल PAM_AUTH_ERR:
			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
			/* FALLTHROUGH */
		हाल PAM_SUCCESS:
			अगर (type == PAM_SUCCESS) {
				अगर (!sshpam_authctxt->valid ||
				    (sshpam_authctxt->pw->pw_uid == 0 &&
				    options.permit_मूल_login != PERMIT_YES))
					fatal("Internal error: PAM auth "
					    "succeeded when it should have "
					    "failed");
				import_environments(बफर);
				ctxt->pam_done = SshPamAuthenticated;
				मुक्त(संदेश);
				sshbuf_free(बफर);
				वापस (0);
			}
			error("PAM: %s for %s%.100s from %.100s", संदेश,
			    sshpam_authctxt->valid ? "" : "illegal user ",
			    sshpam_authctxt->user, sshpam_rhost);
			/* FALLTHROUGH */
		शेष:
			मुक्त(संदेश);
			ctxt->pam_done = SshPamError;
			sshbuf_free(बफर);
			वापस (-1);
		}
	}
	sshbuf_free(बफर);
	वापस (-1);
}

/*
 * Returns a junk password of identical length to that the user supplied.
 * Used to mitigate timing attacks against crypt(3)/PAM stacks that
 * vary processing time in proportion to password length.
 */
अटल अक्षर *
fake_password(स्थिर अक्षर *wire_password)
{
	स्थिर अक्षर junk[] = "\b\n\r\177INCORRECT";
	अक्षर *ret = शून्य;
	माप_प्रकार i, l = wire_password != शून्य ? म_माप(wire_password) : 0;

	अगर (l >= पूर्णांक_उच्च)
		fatal_f("password length too long: %zu", l);

	ret = दो_स्मृति(l + 1);
	अगर (ret == शून्य)
		वापस शून्य;
	क्रम (i = 0; i < l; i++)
		ret[i] = junk[i % (माप(junk) - 1)];
	ret[i] = '\0';
	वापस ret;
}

अटल पूर्णांक
sshpam_respond(व्योम *ctx, u_int अंक, अक्षर **resp)
{
	काष्ठा sshbuf *बफर;
	काष्ठा pam_ctxt *ctxt = ctx;
	अक्षर *fake;
	पूर्णांक r;

	debug2_f("PAM: entering, %u responses", अंक);
	चयन (ctxt->pam_done) {
	हाल SshPamAuthenticated:
		sshpam_authenticated = 1;
		वापस (0);
	हाल SshPamNone:
		अवरोध;
	हाल SshPamAgain:
		वापस 1;	/* KbdintResultAgain */
	शेष:
		वापस (-1);
	}
	अगर (अंक != 1) {
		error("PAM: expected one response, got %u", अंक);
		वापस (-1);
	}
	अगर ((बफर = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर (sshpam_authctxt->valid &&
	    (sshpam_authctxt->pw->pw_uid != 0 ||
	    options.permit_मूल_login == PERMIT_YES)) {
		अगर ((r = sshbuf_put_cstring(बफर, *resp)) != 0)
			fatal_fr(r, "buffer error");
	} अन्यथा {
		fake = fake_password(*resp);
		अगर ((r = sshbuf_put_cstring(बफर, fake)) != 0)
			fatal_fr(r, "buffer error");
		मुक्त(fake);
	}
	अगर (ssh_संदेश_send(ctxt->pam_psock, PAM_AUTHTOK, बफर) == -1) {
		sshbuf_free(बफर);
		वापस (-1);
	}
	sshbuf_free(बफर);
	वापस (1);
}

अटल व्योम
sshpam_free_ctx(व्योम *ctxtp)
{
	काष्ठा pam_ctxt *ctxt = ctxtp;

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

पूर्णांक
sshpam_priv_kbdint_authdone(व्योम *ctxtp)
{
	काष्ठा pam_ctxt *ctxt = ctxtp;

	वापस ctxt->pam_done == SshPamAuthenticated;
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
व्योम
start_pam(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	अगर (!options.use_pam)
		fatal("PAM: initialisation requested when UsePAM=no");

	अगर (sshpam_init(ssh, authctxt) == -1)
		fatal("PAM: initialisation failed");
}

व्योम
finish_pam(व्योम)
{
	sshpam_cleanup();
}


u_int
do_pam_account(व्योम)
{
	debug_f("called");
	अगर (sshpam_account_status != -1)
		वापस (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
	    pam_strerror(sshpam_handle, sshpam_err));

	अगर (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		वापस (sshpam_account_status);
	}

	अगर (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		sshpam_password_change_required(1);

	sshpam_account_status = 1;
	वापस (sshpam_account_status);
}

व्योम
do_pam_setcred(व्योम)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (स्थिर व्योम *)&store_conv);
	अगर (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: establishing credentials");
	sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	अगर (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		वापस;
	}
	अगर (sshpam_authenticated)
		fatal("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	अन्यथा
		debug("PAM: pam_setcred(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
}

व्योम
do_pam_session(काष्ठा ssh *ssh)
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (स्थिर व्योम *)&store_conv);
	अगर (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	अगर (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	अन्यथा {
		sshpam_session_open = 0;
		auth_restrict_session(ssh);
		error("PAM: pam_open_session(): %s",
		    pam_strerror(sshpam_handle, sshpam_err));
	}

}

पूर्णांक
is_pam_session_open(व्योम)
{
	वापस sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
पूर्णांक
do_pam_putenv(अक्षर *name, अक्षर *मूल्य)
{
	पूर्णांक ret = 1;
	अक्षर *compound;
	माप_प्रकार len;

	len = म_माप(name) + म_माप(मूल्य) + 2;
	compound = xmalloc(len);

	snprintf(compound, len, "%s=%s", name, मूल्य);
	ret = pam_putenv(sshpam_handle, compound);
	मुक्त(compound);

	वापस (ret);
}

अक्षर **
fetch_pam_child_environment(व्योम)
{
	वापस sshpam_env;
}

अक्षर **
fetch_pam_environment(व्योम)
{
	वापस (pam_getenvlist(sshpam_handle));
}

व्योम
free_pam_environment(अक्षर **env)
{
	अक्षर **envp;

	अगर (env == शून्य)
		वापस;

	क्रम (envp = env; *envp; envp++)
		मुक्त(*envp);
	मुक्त(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
अटल पूर्णांक
sshpam_passwd_conv(पूर्णांक n, sshpam_const काष्ठा pam_message **संदेश,
    काष्ठा pam_response **resp, व्योम *तथ्य)
{
	काष्ठा pam_response *reply;
	पूर्णांक r, i;
	माप_प्रकार len;

	debug3_f("PAM: called with %d messages", n);

	*resp = शून्य;

	अगर (n <= 0 || n > PAM_MAX_अंक_संदेश)
		वापस (PAM_CONV_ERR);

	अगर ((reply = सुस्मृति(n, माप(*reply))) == शून्य)
		वापस (PAM_CONV_ERR);

	क्रम (i = 0; i < n; ++i) {
		चयन (PAM_संदेश_MEMBER(संदेश, i, संदेश_style)) {
		हाल PAM_PROMPT_ECHO_OFF:
			अगर (sshpam_password == शून्य)
				जाओ fail;
			अगर ((reply[i].resp = strdup(sshpam_password)) == शून्य)
				जाओ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			अवरोध;
		हाल PAM_ERROR_संदेश:
		हाल PAM_TEXT_INFO:
			len = म_माप(PAM_संदेश_MEMBER(संदेश, i, संदेश));
			अगर (len > 0) {
				अगर ((r = sshbuf_putf(loginmsg, "%s\n",
				    PAM_संदेश_MEMBER(संदेश, i, संदेश))) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}
			अगर ((reply[i].resp = strdup("")) == शून्य)
				जाओ fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			अवरोध;
		शेष:
			जाओ fail;
		}
	}
	*resp = reply;
	वापस (PAM_SUCCESS);

 fail:
	क्रम(i = 0; i < n; i++) {
		मुक्त(reply[i].resp);
	}
	मुक्त(reply);
	वापस (PAM_CONV_ERR);
}

अटल काष्ठा pam_conv passwd_conv = { sshpam_passwd_conv, शून्य };

/*
 * Attempt password authentication via PAM
 */
पूर्णांक
sshpam_auth_passwd(Authctxt *authctxt, स्थिर अक्षर *password)
{
	पूर्णांक flags = (options.permit_empty_passwd == 0 ?
	    PAM_DISALLOW_NULL_AUTHTOK : 0);
	अक्षर *fake = शून्य;

	अगर (!options.use_pam || sshpam_handle == शून्य)
		fatal("PAM: %s called when PAM disabled or failed to "
		    "initialise.", __func__);

	sshpam_password = password;
	sshpam_authctxt = authctxt;

	/*
	 * If the user logging in is invalid, or is root but is not permitted
	 * by PermitRootLogin, use an invalid password to prevent leaking
	 * information via timing (eg if the PAM config has a delay on fail).
	 */
	अगर (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
	    options.permit_मूल_login != PERMIT_YES))
		sshpam_password = fake = fake_password(password);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
	    (स्थिर व्योम *)&passwd_conv);
	अगर (sshpam_err != PAM_SUCCESS)
		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
		    pam_strerror(sshpam_handle, sshpam_err));

	expose_authinfo(__func__);

	sshpam_err = pam_authenticate(sshpam_handle, flags);
	sshpam_password = शून्य;
	मुक्त(fake);
	अगर (sshpam_err == PAM_SUCCESS)
		sshpam_err = check_pam_user(authctxt);
	अगर (sshpam_err == PAM_MAXTRIES)
		sshpam_set_maxtries_reached(1);
	अगर (sshpam_err == PAM_SUCCESS && authctxt->valid) {
		debug("PAM: password authentication accepted for %.100s",
		    authctxt->user);
		वापस 1;
	} अन्यथा {
		debug("PAM: password authentication failed for %.100s: %s",
		    authctxt->valid ? authctxt->user : "an illegal user",
		    pam_strerror(sshpam_handle, sshpam_err));
		वापस 0;
	}
}

पूर्णांक
sshpam_get_maxtries_reached(व्योम)
{
	वापस sshpam_maxtries_reached;
}

व्योम
sshpam_set_maxtries_reached(पूर्णांक reached)
{
	अगर (reached == 0 || sshpam_maxtries_reached)
		वापस;
	sshpam_maxtries_reached = 1;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
}
#पूर्ण_अगर /* USE_PAM */
