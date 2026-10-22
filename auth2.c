/* $OpenBSD: auth2.c,v 1.176 2026/09/16 00:37:07 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/uio.h>

#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <time.h>

#समावेश "stdlib.h"
#समावेश "atomicio.h"
#समावेश "xmalloc.h"
#समावेश "ssh2.h"
#समावेश "packet.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "dispatch.h"
#समावेश "pathnames.h"
#समावेश "ssherr.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "digest.h"
#समावेश "kex.h"

/* import */
बाह्य ServerOptions options;
बाह्य काष्ठा sshbuf *loginmsg;

/* methods */

बाह्य Authmethod method_none;
बाह्य Authmethod method_pubkey;
बाह्य Authmethod method_passwd;
बाह्य Authmethod method_kbdint;
बाह्य Authmethod method_hostbased;
#अगर_घोषित GSSAPI
बाह्य Authmethod method_gssapi;
#पूर्ण_अगर

Authmethod *authmethods[] = {
	&method_none,
	&method_pubkey,
#अगर_घोषित GSSAPI
	&method_gssapi,
#पूर्ण_अगर
	&method_passwd,
	&method_kbdint,
	&method_hostbased,
	शून्य
};

/* protocol */

अटल पूर्णांक निवेश_service_request(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_request(पूर्णांक, uint32_t, काष्ठा ssh *);

/* helper */
अटल Authmethod *authmethod_byname(स्थिर अक्षर *);
अटल Authmethod *authmethod_lookup(Authctxt *, स्थिर अक्षर *);
अटल अक्षर *authmethods_get(Authctxt *authctxt);

#घोषणा MATCH_NONE	0	/* method or submethod mismatch */
#घोषणा MATCH_METHOD	1	/* method matches (no submethod specified) */
#घोषणा MATCH_BOTH	2	/* method and submethod match */
#घोषणा MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
अटल पूर्णांक list_starts_with(स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);

अक्षर *
auth2_read_banner(व्योम)
{
	काष्ठा stat st;
	अक्षर *banner = शून्य;
	माप_प्रकार len, n;
	पूर्णांक fd;

	अगर ((fd = खोलो(options.banner, O_RDONLY)) == -1)
		वापस (शून्य);
	अगर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		वापस (शून्य);
	}
	अगर (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		बंद(fd);
		वापस (शून्य);
	}

	len = (माप_प्रकार)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(पढ़ो, fd, banner, len);
	बंद(fd);

	अगर (n != len) {
		मुक्त(banner);
		वापस (शून्य);
	}
	banner[n] = '\0';

	वापस (banner);
}

अटल व्योम
userauth_send_banner(काष्ठा ssh *ssh, स्थिर अक्षर *संदेश)
{
	पूर्णांक r;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, संदेश)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

अटल व्योम
userauth_banner(काष्ठा ssh *ssh)
{
	अक्षर *banner = शून्य;

	अगर (options.banner == शून्य)
		वापस;

	अगर ((banner = mm_auth2_read_banner()) == शून्य)
		जाओ done;
	userauth_send_banner(ssh, banner);

done:
	मुक्त(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
व्योम
do_authentication2(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	अगर (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_निवेश_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_REQUEST, &निवेश_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = शून्य;
}

अटल पूर्णांक
निवेश_service_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *service = शून्य;
	पूर्णांक r, acceptit = 0;

	अगर ((r = sshpkt_get_cstring(ssh, &service, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;

	अगर (authctxt == शून्य)
		fatal("input_service_request: no authctxt");

	अगर (म_भेद(service, "ssh-userauth") == 0) {
		अगर (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_REQUEST,
			    &निवेश_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	अगर (acceptit) {
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			जाओ out;
	} अन्यथा {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	मुक्त(service);
	वापस r;
}

#घोषणा MIN_FAIL_DELAY_SECONDS 0.005
#घोषणा MAX_FAIL_DELAY_SECONDS 5.0
अटल द्विगुन
user_specific_delay(स्थिर अक्षर *user)
{
	अक्षर b[512];
	माप_प्रकार len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	द्विगुन delay;

	(व्योम)snprintf(b, माप b, "%llu%s",
	    (अचिन्हित दीर्घ दीर्घ)options.timing_secret, user);
	अगर (ssh_digest_memory(SSH_DIGEST_SHA512, b, म_माप(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (द्विगुन)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	वापस MIN_FAIL_DELAY_SECONDS + delay;
}

अटल व्योम
ensure_minimum_time_since(द्विगुन start, द्विगुन seconds)
{
	काष्ठा timespec ts;
	द्विगुन elapsed = monotime_double() - start, req = seconds, remain;

	अगर (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		वापस;
	}

	/* if we've already passed the requested time, scale up */
	जबतक ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, शून्य);
}

व्योम
auth_failure_delay(Authctxt *authctxt, द्विगुन tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

अटल पूर्णांक
निवेश_userauth_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = शून्य;
	अक्षर *user = शून्य, *service = शून्य, *method = शून्य, *style = शून्य;
	पूर्णांक r, authenticated = 0;
	द्विगुन tstart = monotime_double();

	अगर (authctxt == शून्य)
		fatal("input_userauth_request: no authctxt");

	अगर ((r = sshpkt_get_cstring(ssh, &user, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, शून्य)) != 0)
		जाओ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	अगर ((style = म_अक्षर(user, ':')) != शून्य)
		*style++ = 0;

	अगर (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	अगर (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : शून्य;
		अगर (authctxt->pw && म_भेद(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} अन्यथा {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#अगर_घोषित SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#पूर्ण_अगर
		}
#अगर_घोषित USE_PAM
		अगर (options.use_pam)
			mm_start_pam(ssh);
#पूर्ण_अगर
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		अगर ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		अगर (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} अन्यथा अगर (म_भेद(user, authctxt->user) != 0 ||
	    म_भेद(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#अगर_घोषित GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, शून्य);
#पूर्ण_अगर

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	अगर (m != शून्य && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	अगर (!authctxt->authenticated && म_भेद(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, शून्य);
	r = 0;
 out:
	मुक्त(service);
	मुक्त(user);
	मुक्त(method);
	वापस r;
}

व्योम
userauth_finish(काष्ठा ssh *ssh, पूर्णांक authenticated, स्थिर अक्षर *packet_method,
    स्थिर अक्षर *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = शून्य;
	स्थिर अक्षर *method = packet_method;
	अक्षर *methods;
	पूर्णांक r, partial = 0;

	अगर (authenticated) {
		अगर (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		अगर (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		अगर ((m = authmethod_byname(method)) == शून्य)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	अगर (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_मूल_allowed(ssh, method)) {
		authenticated = 0;
#अगर_घोषित SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_मूल_DENIED);
#पूर्ण_अगर
	}

	अगर (authenticated && options.अंक_auth_methods != 0) {
		अगर (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	अगर (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	अगर (authctxt->postponed)
		वापस;

#अगर_घोषित USE_PAM
	अगर (options.use_pam && authenticated) {
		पूर्णांक r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		अगर (sshbuf_len(loginmsg) > 0) {
			अगर ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			अगर ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		अगर (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#पूर्ण_अगर

	अगर (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} अन्यथा {
		/* Allow initial try of "none" auth without failure penalty */
		अगर (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || म_भेद(method, "none") != 0))
			authctxt->failures++;
		अगर (authctxt->failures >= options.max_authtries) {
#अगर_घोषित SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#पूर्ण_अगर
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		मुक्त(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
पूर्णांक
auth2_method_allowed(Authctxt *authctxt, स्थिर अक्षर *method,
    स्थिर अक्षर *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	अगर (options.अंक_auth_methods == 0)
		वापस 1;
	क्रम (i = 0; i < authctxt->अंक_auth_methods; i++) {
		अगर (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			वापस 1;
	}
	वापस 0;
}

अटल अक्षर *
authmethods_get(Authctxt *authctxt)
{
	काष्ठा sshbuf *b;
	अक्षर *list;
	पूर्णांक i, r;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	क्रम (i = 0; authmethods[i] != शून्य; i++) {
		अगर (म_भेद(authmethods[i]->cfg->name, "none") == 0)
			जारी;
		अगर (authmethods[i]->cfg->enabled == शून्य ||
		    *(authmethods[i]->cfg->enabled) == 0)
			जारी;
		अगर (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    शून्य))
			जारी;
		अगर ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	अगर ((list = sshbuf_dup_string(b)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	वापस list;
}

अटल Authmethod *
authmethod_byname(स्थिर अक्षर *name)
{
	पूर्णांक i;

	अगर (name == शून्य)
		fatal_f("NULL authentication method name");
	क्रम (i = 0; authmethods[i] != शून्य; i++) {
		अगर (म_भेद(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != शून्य &&
		    म_भेद(name, authmethods[i]->cfg->synonym) == 0))
			वापस authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	वापस शून्य;
}

अटल Authmethod *
authmethod_lookup(Authctxt *authctxt, स्थिर अक्षर *name)
{
	Authmethod *method;

	अगर ((method = authmethod_byname(name)) == शून्य)
		वापस शून्य;

	अगर (method->cfg->enabled == शून्य || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		वापस शून्य;
	}
	अगर (!auth2_method_allowed(authctxt, method->cfg->name, शून्य)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		वापस शून्य;
	}
	वापस method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
पूर्णांक
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	अगर (options.अंक_auth_methods == 1 &&
	    म_भेद(options.auth_methods[0], "any") == 0) {
		मुक्त(options.auth_methods[0]);
		options.auth_methods[0] = शून्य;
		options.अंक_auth_methods = 0;
	}

	अगर (options.अंक_auth_methods == 0)
		वापस 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.अंक_auth_methods,
	    माप(*authctxt->auth_methods));
	authctxt->अंक_auth_methods = 0;
	क्रम (i = 0; i < options.अंक_auth_methods; i++) {
		अगर (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			जारी;
		}
		debug("authentication methods list %d: %s",
		    authctxt->अंक_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->अंक_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	अगर (authctxt->अंक_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		वापस -1;
	}
	वापस 0;
}

अटल पूर्णांक
list_starts_with(स्थिर अक्षर *methods, स्थिर अक्षर *method,
    स्थिर अक्षर *submethod)
{
	माप_प्रकार l = म_माप(method);
	पूर्णांक match;
	स्थिर अक्षर *p;

	अगर (म_भेदन(methods, method, l) != 0)
		वापस MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	अगर (*p == ':') {
		अगर (!submethod)
			वापस MATCH_PARTIAL;
		l = म_माप(submethod);
		p += 1;
		अगर (म_भेदन(submethod, p, l))
			वापस MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	अगर (*p != ',' && *p != '\0')
		वापस MATCH_NONE;
	वापस match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
अटल पूर्णांक
remove_method(अक्षर **methods, स्थिर अक्षर *method, स्थिर अक्षर *submethod)
{
	अक्षर *omethods = *methods, *p;
	माप_प्रकार l = म_माप(method);
	पूर्णांक match;

	match = list_starts_with(omethods, method, submethod);
	अगर (match != MATCH_METHOD && match != MATCH_BOTH)
		वापस 0;
	p = omethods + l;
	अगर (submethod && match == MATCH_BOTH)
		p += 1 + म_माप(submethod); /* include colon */
	अगर (*p == ',')
		p++;
	*methods = xstrdup(p);
	मुक्त(omethods);
	वापस 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
पूर्णांक
auth2_update_methods_lists(Authctxt *authctxt, स्थिर अक्षर *method,
    स्थिर अक्षर *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	क्रम (i = 0; i < authctxt->अंक_auth_methods; i++) {
		अगर (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			जारी;
		found = 1;
		अगर (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			वापस 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	अगर (!found)
		fatal_f("method not in AuthenticationMethods");
	वापस 0;
}

/* Reset method-specific information */
व्योम auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_कुंजी);
	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_कुंजी = शून्य;
	authctxt->auth_method_info = शून्य;
}

/* Record auth method-specific information for logs */
व्योम
auth2_record_info(Authctxt *authctxt, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक i;

	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_info = शून्य;

	बहु_शुरू(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	बहु_पूर्ण(ap);

	अगर (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
व्योम
auth2_record_कुंजी(Authctxt *authctxt, पूर्णांक authenticated,
    स्थिर काष्ठा sshkey *कुंजी)
{
	काष्ठा sshkey **tmp, *dup;
	पूर्णांक r;

	अगर ((r = sshkey_from_private(कुंजी, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_कुंजी);
	authctxt->auth_method_कुंजी = dup;

	अगर (!authenticated)
		वापस;

	/* If authenticated, make sure we don't accept this key again */
	अगर ((r = sshkey_from_private(कुंजी, &dup)) != 0)
		fatal_fr(r, "copy key");
	अगर (authctxt->nprev_कुंजियाँ >= पूर्णांक_उच्च ||
	    (tmp = recallocarray(authctxt->पूर्व_कुंजियाँ, authctxt->nprev_कुंजियाँ,
	    authctxt->nprev_कुंजियाँ + 1, माप(*authctxt->पूर्व_कुंजियाँ))) == शून्य)
		fatal_f("reallocarray failed");
	authctxt->पूर्व_कुंजियाँ = tmp;
	authctxt->पूर्व_कुंजियाँ[authctxt->nprev_कुंजियाँ] = dup;
	authctxt->nprev_कुंजियाँ++;

}

/* Checks whether a key has already been previously used for authentication */
पूर्णांक
auth2_कुंजी_already_used(Authctxt *authctxt, स्थिर काष्ठा sshkey *कुंजी)
{
	u_int i;
	अक्षर *fp;

	क्रम (i = 0; i < authctxt->nprev_कुंजियाँ; i++) {
		अगर (sshkey_equal_public(कुंजी, authctxt->पूर्व_कुंजियाँ[i])) {
			fp = sshkey_fingerprint(authctxt->पूर्व_कुंजियाँ[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->पूर्व_कुंजियाँ[i]),
			    fp == शून्य ? "UNKNOWN" : fp);
			मुक्त(fp);
			वापस 1;
		}
	}
	वापस 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
व्योम
auth2_update_session_info(Authctxt *authctxt, स्थिर अक्षर *method,
    स्थिर अक्षर *submethod)
{
	पूर्णांक r;

	अगर (authctxt->session_info == शून्य) {
		अगर ((authctxt->session_info = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	अगर ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == शून्य ? "" : "/",
	    submethod == शून्य ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	अगर (authctxt->auth_method_कुंजी != शून्य) {
		अगर ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_कुंजी,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	अगर (authctxt->auth_method_info != शून्य) {
		/* Ensure no ambiguity here */
		अगर (म_अक्षर(authctxt->auth_method_info, '\n') != शून्य)
			fatal_f("auth_method_info contains \\n");
		अगर ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	अगर ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

