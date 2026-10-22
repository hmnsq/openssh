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

स्थिर पूर्णाङ्क आगत_service_request(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क आगत_userauth_request(पूर्णाङ्क, uint32_t, संरचना ssh *);

/* helper */
स्थिर Authmethod *authmethod_byname(अचर वर्ण *);
स्थिर Authmethod *authmethod_lookup(Authctxt *, अचर वर्ण *);
स्थिर वर्ण *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
स्थिर पूर्णाङ्क list_starts_with(अचर वर्ण *, अचर वर्ण *, अचर वर्ण *);

वर्ण *
auth2_read_banner(शून्य)
{
	संरचना stat st;
	वर्ण *banner = रिक्त;
	माप_प्रकार len, n;
	पूर्णाङ्क fd;

	यदि ((fd = खोलो(options.banner, O_RDONLY)) == -1)
		फर्काऊ (रिक्त);
	यदि (ख_स्थिति(fd, &st) == -1) {
		बंद(fd);
		फर्काऊ (रिक्त);
	}
	यदि (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		बंद(fd);
		फर्काऊ (रिक्त);
	}

	len = (माप_प्रकार)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(पठ, fd, banner, len);
	बंद(fd);

	यदि (n != len) {
		मुक्त(banner);
		फर्काऊ (रिक्त);
	}
	banner[n] = '\0';

	फर्काऊ (banner);
}

स्थिर शून्य
userauth_send_banner(संरचना ssh *ssh, अचर वर्ण *सन्देश)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, सन्देश)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

स्थिर शून्य
userauth_banner(संरचना ssh *ssh)
{
	वर्ण *banner = रिक्त;

	यदि (options.banner == रिक्त)
		फर्काऊ;

	यदि ((banner = mm_auth2_read_banner()) == रिक्त)
		गच्छ done;
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
	यदि (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_सन्देश_EXT_INFO, &kex_आगत_ext_info);
	ssh_dispatch_set(ssh, SSH2_सन्देश_SERVICE_REQUEST, &आगत_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = रिक्त;
}

स्थिर पूर्णाङ्क
आगत_service_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	वर्ण *service = रिक्त;
	पूर्णाङ्क r, acceptit = 0;

	यदि ((r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;

	यदि (authctxt == रिक्त)
		fatal("input_service_request: no authctxt");

	यदि (म_भेद(service, "ssh-userauth") == 0) {
		यदि (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_सन्देश_USERAUTH_REQUEST,
			    &आगत_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	यदि (acceptit) {
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			गच्छ out;
	} अन्यथा {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_सन्देश_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	मुक्त(service);
	फर्काऊ r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
स्थिर द्विगुण
user_specific_delay(अचर वर्ण *user)
{
	वर्ण b[512];
	माप_प्रकार len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	द्विगुण delay;

	(शून्य)snprintf(b, परिमाण b, "%llu%s",
	    (अचिन्हित दीर्घ दीर्घ)options.timing_secret, user);
	यदि (ssh_digest_memory(SSH_DIGEST_SHA512, b, म_माप(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (द्विगुण)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	फर्काऊ MIN_FAIL_DELAY_SECONDS + delay;
}

स्थिर शून्य
ensure_minimum_time_since(द्विगुण start, द्विगुण seconds)
{
	संरचना timespec ts;
	द्विगुण elapsed = monotime_double() - start, req = seconds, remain;

	यदि (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		फर्काऊ;
	}

	/* if we've already passed the requested time, scale up */
	जबसम्म ((remain = seconds - elapsed) < 0.0)
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

स्थिर पूर्णाङ्क
आगत_userauth_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	वर्ण *user = रिक्त, *service = रिक्त, *method = रिक्त, *style = रिक्त;
	पूर्णाङ्क r, authenticated = 0;
	द्विगुण tstart = monotime_double();

	यदि (authctxt == रिक्त)
		fatal("input_userauth_request: no authctxt");

	यदि ((r = sshpkt_get_cstring(ssh, &user, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, रिक्त)) != 0)
		गच्छ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	यदि ((style = म_अक्षर(user, ':')) != रिक्त)
		*style++ = 0;

	यदि (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	यदि (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : रिक्त;
		यदि (authctxt->pw && म_भेद(service, "ssh-connection")==0) {
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
		यदि (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		यदि ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		यदि (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} अन्यथा यदि (म_भेद(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_सन्देश_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_set(ssh, SSH2_सन्देश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	यदि (m != रिक्त && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	यदि (!authctxt->authenticated && म_भेद(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, रिक्त);
	r = 0;
 out:
	मुक्त(service);
	मुक्त(user);
	मुक्त(method);
	फर्काऊ r;
}

शून्य
userauth_finish(संरचना ssh *ssh, पूर्णाङ्क authenticated, अचर वर्ण *packet_method,
    अचर वर्ण *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	अचर वर्ण *method = packet_method;
	वर्ण *methods;
	पूर्णाङ्क r, partial = 0;

	यदि (authenticated) {
		यदि (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		यदि (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		यदि ((m = authmethod_byname(method)) == रिक्त)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	यदि (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_जरा_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_जरा_DENIED);
#endif
	}

	यदि (authenticated && options.अङ्क_auth_methods != 0) {
		यदि (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	यदि (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	यदि (authctxt->postponed)
		फर्काऊ;

#ifdef USE_PAM
	यदि (options.use_pam && authenticated) {
		पूर्णाङ्क r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		यदि (sshbuf_len(loginmsg) > 0) {
			यदि ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			यदि ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		यदि (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	यदि (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_सन्देश_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} अन्यथा {
		/* Allow initial try of "none" auth without failure penalty */
		यदि (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || म_भेद(method, "none") != 0))
			authctxt->failures++;
		यदि (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देश_USERAUTH_FAILURE)) != 0 ||
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
पूर्णाङ्क
auth2_method_allowed(Authctxt *authctxt, अचर वर्ण *method,
    अचर वर्ण *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	यदि (options.अङ्क_auth_methods == 0)
		फर्काऊ 1;
	लागि (i = 0; i < authctxt->अङ्क_auth_methods; i++) {
		यदि (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			फर्काऊ 1;
	}
	फर्काऊ 0;
}

स्थिर वर्ण *
authmethods_get(Authctxt *authctxt)
{
	संरचना sshbuf *b;
	वर्ण *list;
	पूर्णाङ्क i, r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	लागि (i = 0; authmethods[i] != रिक्त; i++) {
		यदि (म_भेद(authmethods[i]->cfg->name, "none") == 0)
			जारी;
		यदि (authmethods[i]->cfg->enabled == रिक्त ||
		    *(authmethods[i]->cfg->enabled) == 0)
			जारी;
		यदि (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    रिक्त))
			जारी;
		यदि ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	यदि ((list = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	फर्काऊ list;
}

स्थिर Authmethod *
authmethod_byname(अचर वर्ण *name)
{
	पूर्णाङ्क i;

	यदि (name == रिक्त)
		fatal_f("NULL authentication method name");
	लागि (i = 0; authmethods[i] != रिक्त; i++) {
		यदि (म_भेद(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != रिक्त &&
		    म_भेद(name, authmethods[i]->cfg->synonym) == 0))
			फर्काऊ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	फर्काऊ रिक्त;
}

स्थिर Authmethod *
authmethod_lookup(Authctxt *authctxt, अचर वर्ण *name)
{
	Authmethod *method;

	यदि ((method = authmethod_byname(name)) == रिक्त)
		फर्काऊ रिक्त;

	यदि (method->cfg->enabled == रिक्त || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		फर्काऊ रिक्त;
	}
	यदि (!auth2_method_allowed(authctxt, method->cfg->name, रिक्त)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		फर्काऊ रिक्त;
	}
	फर्काऊ method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
पूर्णाङ्क
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	यदि (options.अङ्क_auth_methods == 1 &&
	    म_भेद(options.auth_methods[0], "any") == 0) {
		मुक्त(options.auth_methods[0]);
		options.auth_methods[0] = रिक्त;
		options.अङ्क_auth_methods = 0;
	}

	यदि (options.अङ्क_auth_methods == 0)
		फर्काऊ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.अङ्क_auth_methods,
	    परिमाण(*authctxt->auth_methods));
	authctxt->अङ्क_auth_methods = 0;
	लागि (i = 0; i < options.अङ्क_auth_methods; i++) {
		यदि (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			जारी;
		}
		debug("authentication methods list %d: %s",
		    authctxt->अङ्क_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->अङ्क_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	यदि (authctxt->अङ्क_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		फर्काऊ -1;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
list_starts_with(अचर वर्ण *methods, अचर वर्ण *method,
    अचर वर्ण *submethod)
{
	माप_प्रकार l = म_माप(method);
	पूर्णाङ्क match;
	अचर वर्ण *p;

	यदि (म_भेदन(methods, method, l) != 0)
		फर्काऊ MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	यदि (*p == ':') {
		यदि (!submethod)
			फर्काऊ MATCH_PARTIAL;
		l = म_माप(submethod);
		p += 1;
		यदि (म_भेदन(submethod, p, l))
			फर्काऊ MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	यदि (*p != ',' && *p != '\0')
		फर्काऊ MATCH_NONE;
	फर्काऊ match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
स्थिर पूर्णाङ्क
remove_method(वर्ण **methods, अचर वर्ण *method, अचर वर्ण *submethod)
{
	वर्ण *omethods = *methods, *p;
	माप_प्रकार l = म_माप(method);
	पूर्णाङ्क match;

	match = list_starts_with(omethods, method, submethod);
	यदि (match != MATCH_METHOD && match != MATCH_BOTH)
		फर्काऊ 0;
	p = omethods + l;
	यदि (submethod && match == MATCH_BOTH)
		p += 1 + म_माप(submethod); /* include colon */
	यदि (*p == ',')
		p++;
	*methods = xstrdup(p);
	मुक्त(omethods);
	फर्काऊ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
पूर्णाङ्क
auth2_update_methods_lists(Authctxt *authctxt, अचर वर्ण *method,
    अचर वर्ण *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	लागि (i = 0; i < authctxt->अङ्क_auth_methods; i++) {
		यदि (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			जारी;
		found = 1;
		यदि (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			फर्काऊ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	यदि (!found)
		fatal_f("method not in AuthenticationMethods");
	फर्काऊ 0;
}

/* Reset method-specific information */
शून्य auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_साँचो);
	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_साँचो = रिक्त;
	authctxt->auth_method_info = रिक्त;
}

/* Record auth method-specific information for logs */
शून्य
auth2_record_info(Authctxt *authctxt, अचर वर्ण *fmt, ...)
{
	बहु_सूची ap;
	पूर्णाङ्क i;

	मुक्त(authctxt->auth_method_info);
	authctxt->auth_method_info = रिक्त;

	बहु_शुरू(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	बहु_पूर्ण(ap);

	यदि (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
शून्य
auth2_record_साँचो(Authctxt *authctxt, पूर्णाङ्क authenticated,
    अचर संरचना sshkey *साँचो)
{
	संरचना sshkey **tmp, *dup;
	पूर्णाङ्क r;

	यदि ((r = sshkey_from_private(साँचो, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_साँचो);
	authctxt->auth_method_साँचो = dup;

	यदि (!authenticated)
		फर्काऊ;

	/* If authenticated, make sure we don't accept this key again */
	यदि ((r = sshkey_from_private(साँचो, &dup)) != 0)
		fatal_fr(r, "copy key");
	यदि (authctxt->nprev_साँचोहरू >= पूर्णांक_उच्च ||
	    (tmp = recallocarray(authctxt->prev_साँचोहरू, authctxt->nprev_साँचोहरू,
	    authctxt->nprev_साँचोहरू + 1, परिमाण(*authctxt->prev_साँचोहरू))) == रिक्त)
		fatal_f("reallocarray failed");
	authctxt->prev_साँचोहरू = tmp;
	authctxt->prev_साँचोहरू[authctxt->nprev_साँचोहरू] = dup;
	authctxt->nprev_साँचोहरू++;

}

/* Checks whether a key has already been previously used for authentication */
पूर्णाङ्क
auth2_साँचो_already_used(Authctxt *authctxt, अचर संरचना sshkey *साँचो)
{
	u_int i;
	वर्ण *fp;

	लागि (i = 0; i < authctxt->nprev_साँचोहरू; i++) {
		यदि (sshkey_equal_public(साँचो, authctxt->prev_साँचोहरू[i])) {
			fp = sshkey_fingerprint(authctxt->prev_साँचोहरू[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_साँचोहरू[i]),
			    fp == रिक्त ? "UNKNOWN" : fp);
			मुक्त(fp);
			फर्काऊ 1;
		}
	}
	फर्काऊ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
शून्य
auth2_update_session_info(Authctxt *authctxt, अचर वर्ण *method,
    अचर वर्ण *submethod)
{
	पूर्णाङ्क r;

	यदि (authctxt->session_info == रिक्त) {
		यदि ((authctxt->session_info = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	यदि ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == रिक्त ? "" : "/",
	    submethod == रिक्त ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	यदि (authctxt->auth_method_साँचो != रिक्त) {
		यदि ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_साँचो,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	यदि (authctxt->auth_method_info != रिक्त) {
		/* Ensure no ambiguity here */
		यदि (म_अक्षर(authctxt->auth_method_info, '\n') != रिक्त)
			fatal_f("auth_method_info contains \\n");
		यदि ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	यदि ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

