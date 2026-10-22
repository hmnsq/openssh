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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "stdlib.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssherr.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"

/* import */
बाह्य ServerOptions options;
बाह्य संरचना sshbuf *loginmsg;

/* methods */

बाह्य Authmethod method_none;
बाह्य Authmethod method_pubkey;
बाह्य Authmethod method_passwd;
बाह्य Authmethod method_kbdint;
बाह्य Authmethod method_hostbased;
#ifdef GSSAPI
बाह्य Authmethod method_gssapi;
#endif

Authmethod *authmethods[] = {
	&method_none,
	&method_pubkey,
#ifdef GSSAPI
	&method_gssapi,
#endif
	&method_passwd,
	&method_kbdint,
	&method_hostbased,
	रिक्त
};

/* protocol */

स्थिर पूर्णांक आदान_service_request(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_request(पूर्णांक, uint32_t, संरचना ssh *);

/* helper */
स्थिर Authmethod *authmethod_byname(स्थिरांक अक्षर *);
स्थिर Authmethod *authmethod_lookup(Authctxt *, स्थिरांक अक्षर *);
स्थिर अक्षर *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
स्थिर पूर्णांक list_starts_with(स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);

अक्षर *
auth2_read_banner(शून्य)
{
	संरचना stat st;
	अक्षर *banner = रिक्त;
	माप_प्रकार len, n;
	पूर्णांक fd;

	जर ((fd = खोलो(options.banner, O_RDONLY)) == -1)
		परत (रिक्त);
	जर (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		परत (रिक्त);
	}
	जर (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		बंद(fd);
		परत (रिक्त);
	}

	len = (माप_प्रकार)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(पठ, fd, banner, len);
	बंद(fd);

	जर (n != len) {
		मुक्त(banner);
		परत (रिक्त);
	}
	banner[n] = '\0';

	परत (banner);
}

स्थिर शून्य
userauth_send_banner(संरचना ssh *ssh, स्थिरांक अक्षर *संदेश)
{
	पूर्णांक r;

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, संदेश)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

स्थिर शून्य
userauth_banner(संरचना ssh *ssh)
{
	अक्षर *banner = रिक्त;

	जर (options.banner == रिक्त)
		परत;

	जर ((banner = mm_auth2_read_banner()) == रिक्त)
		जा done;
	userauth_send_banner(ssh, banner);

done:
	मुक्त(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
शून्य
do_authentication2(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	जर (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_आदान_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_REQUEST, &आदान_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = रिक्त;
}

स्थिर पूर्णांक
आदान_service_request(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *service = रिक्त;
	पूर्णांक r, acceptit = 0;

	जर ((r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जा out;

	जर (authctxt == रिक्त)
		fatal("input_service_request: no authctxt");

	जर (म_भेद(service, "ssh-userauth") == 0) {
		जर (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_REQUEST,
			    &आदान_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	जर (acceptit) {
		जर ((r = sshpkt_start(ssh, SSH2_संदेश_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			जा out;
	} अन्यथा {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	मुक्त(service);
	परत r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
स्थिर द्विगुण
user_specific_delay(स्थिरांक अक्षर *user)
{
	अक्षर b[512];
	माप_प्रकार len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	द्विगुण delay;

	(शून्य)snprintf(b, आकार b, "%llu%s",
	    (अचिन्हित दीर्घ दीर्घ)options.timing_secret, user);
	जर (ssh_digest_memory(SSH_DIGEST_SHA512, b, म_माप(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (द्विगुण)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	परत MIN_FAIL_DELAY_SECONDS + delay;
}

स्थिर शून्य
ensure_minimum_time_since(द्विगुण start, द्विगुण seconds)
{
	संरचना timespec ts;
	द्विगुण elapsed = monotime_double() - start, req = seconds, remain;

	जर (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		परत;
	}

	/* if we've already passed the requested time, scale up */
	पर्यंत ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, रिक्त);
}

शून्य
auth_failure_delay(Authctxt *authctxt, द्विगुण tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

स्थिर पूर्णांक
आदान_userauth_request(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	अक्षर *user = रिक्त, *service = रिक्त, *method = रिक्त, *style = रिक्त;
	पूर्णांक r, authenticated = 0;
	द्विगुण tstart = monotime_double();

	जर (authctxt == रिक्त)
		fatal("input_userauth_request: no authctxt");

	जर ((r = sshpkt_get_cstring(ssh, &user, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, रिक्त)) != 0)
		जा out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	जर ((style = म_अक्षर(user, ':')) != रिक्त)
		*style++ = 0;

	जर (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	जर (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : रिक्त;
		जर (authctxt->pw && म_भेद(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} अन्यथा {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		जर (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		जर ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		जर (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} अन्यथा जर (म_भेद(user, authctxt->user) != 0 ||
	    म_भेद(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#ifdef GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	जर (m != रिक्त && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	जर (!authctxt->authenticated && म_भेद(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, रिक्त);
	r = 0;
 out:
	मुक्त(service);
	मुक्त(user);
	मुक्त(method);
	परत r;
}

शून्य
userauth_finish(संरचना ssh *ssh, पूर्णांक authenticated, स्थिरांक अक्षर *packet_method,
    स्थिरांक अक्षर *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	स्थिरांक अक्षर *method = packet_method;
	अक्षर *methods;
	पूर्णांक r, partial = 0;

	जर (authenticated) {
		जर (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		जर (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		जर ((m = authmethod_byname(method)) == रिक्त)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	जर (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_मूळ_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_मूळ_DENIED);
#endif
	}

	जर (authenticated && options.अंक_auth_methods != 0) {
		जर (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	जर (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	जर (authctxt->postponed)
		परत;

#ifdef USE_PAM
	जर (options.use_pam && authenticated) {
		पूर्णांक r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		जर (sshbuf_len(loginmsg) > 0) {
			जर ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			जर ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		जर (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	जर (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} अन्यथा {
		/* Allow initial try of "none" auth without failure penalty */
		जर (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || म_भेद(method, "none") != 0))
			authctxt->failures++;
		जर (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_FAILURE)) != 0 ||
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
auth2_method_allowed(Authctxt *authctxt, स्थिरांक अक्षर *method,
    स्थिरांक अक्षर *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	जर (options.अंक_auth_methods == 0)
		परत 1;
	साठी (i = 0; i < authctxt->अंक_auth_methods; i++) {
		जर (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			परत 1;
	}
	परत 0;
}

स्थिर अक्षर *
authmethods_get(Authctxt *authctxt)
{
	संरचना sshbuf *b;
	अक्षर *list;
	पूर्णांक i, r;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	साठी (i = 0; authmethods[i] != रिक्त; i++) {
		जर (म_भेद(authmethods[i]->cfg->name, "none") == 0)
			सुरूठेवा;
		जर (authmethods[i]->cfg->enabled == रिक्त ||
		    *(authmethods[i]->cfg->enabled) == 0)
			सुरूठेवा;
		जर (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    रिक्त))
			सुरूठेवा;
		जर ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	जर ((list = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	परत list;
}

स्थिर Authmethod *
authmethod_byname(स्थिरांक अक्षर *name)
{
	पूर्णांक i;

	जर (name == रिक्त)
		fatal_f("NULL authentication method name");
	साठी (i = 0; authmethods[i] != रिक्त; i++) {
		जर (म_भेद(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != रिक्त &&
		    म_भेद(name, authmethods[i]->cfg->synonym) == 0))
			परत authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	परत रिक्त;
}

स्थिर Authmethod *
authmethod_lookup(Authctxt *authctxt, स्थिरांक अक्षर *name)
{
	Authmethod *method;

	जर ((method = authmethod_byname(name)) == रिक्त)
		परत रिक्त;

	जर (method->cfg->enabled == रिक्त || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		परत रिक्त;
	}
	जर (!auth2_method_allowed(authctxt, method->cfg->name, रिक्त)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		परत रिक्त;
	}
	परत method;
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
	जर (options.अंक_auth_methods == 1 &&
	    म_भेद(options.auth_methods[0], "any") == 0) {
		मुक्त(options.auth_methods[0]);
		options.auth_methods[0] = रिक्त;
		options.अंक_auth_methods = 0;
	}

	जर (options.अंक_auth_methods == 0)
		परत 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.अंक_auth_methods,
	    आकार(*authctxt->auth_methods));
	authctxt->अंक_auth_methods = 0;
	साठी (i = 0; i < options.अंक_auth_methods; i++) {
		जर (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			सुरूठेवा;
		}
		debug("authentication methods list %d: %s",
		    authctxt->अंक_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->अंक_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	जर (authctxt->अंक_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		परत -1;
	}
	परत 0;
}

स्थिर पूर्णांक
list_starts_with(स्थिरांक अक्षर *methods, स्थिरांक अक्षर *method,
    स्थिरांक अक्षर *submethod)
{
	माप_प्रकार l = म_माप(method);
	पूर्णांक match;
	स्थिरांक अक्षर *p;

	जर (म_भेदन(methods, method, l) != 0)
		परत MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	जर (*p == ':') {
		जर (!submethod)
			परत MATCH_PARTIAL;
		l = म_माप(submethod);
		p += 1;
		जर (म_भेदन(submethod, p, l))
			परत MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	जर (*p != ',' && *p != '\0')
		परत MATCH_NONE;
	परत match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
स्थिर पूर्णांक
remove_method(अक्षर **methods, स्थिरांक अक्षर *method, स्थिरांक अक्षर *submethod)
{
	अक्षर *omethods = *methods, *p;
	माप_प्रकार l = म_माप(method);
	पूर्णांक match;

	match = list_starts_with(omethods, method, submethod);
	जर (match != MATCH_METHOD && match != MATCH_BOTH)
		परत 0;
	p = omethods + l;
	जर (submethod && match == MATCH_BOTH)
		p += 1 + म_माप(submethod); /* include colon */
	जर (*p == ',')
		p++;
	*methods = xstrdup(p);
	मुक्त(omethods);
	परत 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
पूर्णांक
auth2_update_methods_lists(Authctxt *authctxt, स्थिरांक अक्षर *method,
    स्थिरांक अक्षर *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	साठी (i = 0; i < authctxt->अंक_auth_methods; i++) {
		जर (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			सुरूठेवा;
		found = 1;
		जर (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			परत 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	जर (!found)
		fatal_f("method not in AuthenticationMethods");
	परत 0;
}

/* Reset method-specific information */
शून्य auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_किल्ली);
	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_किल्ली = रिक्त;
	authctxt->auth_method_info = रिक्त;
}

/* Record auth method-specific information for logs */
शून्य
auth2_record_info(Authctxt *authctxt, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक i;

	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_info = रिक्त;

	बहु_शुरू(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	बहु_पूर्ण(ap);

	जर (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
शून्य
auth2_record_किल्ली(Authctxt *authctxt, पूर्णांक authenticated,
    स्थिरांक संरचना sshkey *किल्ली)
{
	संरचना sshkey **tmp, *dup;
	पूर्णांक r;

	जर ((r = sshkey_from_private(किल्ली, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_किल्ली);
	authctxt->auth_method_किल्ली = dup;

	जर (!authenticated)
		परत;

	/* If authenticated, make sure we don't accept this key again */
	जर ((r = sshkey_from_private(किल्ली, &dup)) != 0)
		fatal_fr(r, "copy key");
	जर (authctxt->nprev_किल्ल्या >= पूर्णांक_उच्च ||
	    (tmp = recallocarray(authctxt->prev_किल्ल्या, authctxt->nprev_किल्ल्या,
	    authctxt->nprev_किल्ल्या + 1, आकार(*authctxt->prev_किल्ल्या))) == रिक्त)
		fatal_f("reallocarray failed");
	authctxt->prev_किल्ल्या = tmp;
	authctxt->prev_किल्ल्या[authctxt->nprev_किल्ल्या] = dup;
	authctxt->nprev_किल्ल्या++;

}

/* Checks whether a key has already been previously used for authentication */
पूर्णांक
auth2_किल्ली_already_used(Authctxt *authctxt, स्थिरांक संरचना sshkey *किल्ली)
{
	u_int i;
	अक्षर *fp;

	साठी (i = 0; i < authctxt->nprev_किल्ल्या; i++) {
		जर (sshkey_equal_public(किल्ली, authctxt->prev_किल्ल्या[i])) {
			fp = sshkey_fingerprint(authctxt->prev_किल्ल्या[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_किल्ल्या[i]),
			    fp == रिक्त ? "UNKNOWN" : fp);
			मुक्त(fp);
			परत 1;
		}
	}
	परत 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
शून्य
auth2_update_session_info(Authctxt *authctxt, स्थिरांक अक्षर *method,
    स्थिरांक अक्षर *submethod)
{
	पूर्णांक r;

	जर (authctxt->session_info == रिक्त) {
		जर ((authctxt->session_info = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	जर ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == रिक्त ? "" : "/",
	    submethod == रिक्त ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	जर (authctxt->auth_method_किल्ली != रिक्त) {
		जर ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_किल्ली,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	जर (authctxt->auth_method_info != रिक्त) {
		/* Ensure no ambiguity here */
		जर (म_अक्षर(authctxt->auth_method_info, '\n') != रिक्त)
			fatal_f("auth_method_info contains \\n");
		जर ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	जर ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

