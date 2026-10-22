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
#यदि_परिभाषितम् GSSAPI
#अन्तर्भाव "ssh-gss.h"
#यदि_अन्तः
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"

/* import */
बाह्य ServerOptions options;
बाह्य संरचना sshbuf *loginmsg;

/* methods */

बाह्य Authmethod विधानम्_none;
बाह्य Authmethod विधानम्_pubkey;
बाह्य Authmethod विधानम्_passwd;
बाह्य Authmethod विधानम्_kbdint;
बाह्य Authmethod विधानम्_hostbased;
#यदि_परिभाषितम् GSSAPI
बाह्य Authmethod विधानम्_gssapi;
#यदि_अन्तः

Authmethod *authmethods[] = {
	&विधानम्_none,
	&विधानम्_pubkey,
#यदि_परिभाषितम् GSSAPI
	&विधानम्_gssapi,
#यदि_अन्तः
	&विधानम्_passwd,
	&विधानम्_kbdint,
	&विधानम्_hostbased,
	रिक्त
};

/* protocol */

स्थिर पूर्णाङ्क निवेशः_service_request(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_request(पूर्णाङ्क, uint32_t, संरचना ssh *);

/* helper */
स्थिर Authmethod *authmethod_byname(ध्रुव वर्ण *);
स्थिर Authmethod *authmethod_lookup(Authctxt *, ध्रुव वर्ण *);
स्थिर वर्ण *authmethods_get(Authctxt *authctxt);

#परिभाषय मेलनम्_NONE	0	/* method or submethod mismatch */
#परिभाषय मेलनम्_विधानम्	1	/* method matches (no submethod specified) */
#परिभाषय मेलनम्_BOTH	2	/* method and submethod match */
#परिभाषय मेलनम्_PARTIAL	3	/* method matches, submethod can't be checked */
स्थिर पूर्णाङ्क list_starts_with(ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);

वर्ण *
auth2_read_banner(शून्य)
{
	संरचना stat st;
	वर्ण *banner = रिक्त;
	आकार_t len, n;
	पूर्णाङ्क fd;

	यदि ((fd = उद्घाटय(options.banner, O_RDONLY)) == -1)
		प्रत्यागम (रिक्त);
	यदि (fstat(fd, &st) == -1) {
		close(fd);
		प्रत्यागम (रिक्त);
	}
	यदि (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		प्रत्यागम (रिक्त);
	}

	len = (आकार_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(पठ, fd, banner, len);
	close(fd);

	यदि (n != len) {
		मुक्त(banner);
		प्रत्यागम (रिक्त);
	}
	banner[n] = '\0';

	प्रत्यागम (banner);
}

स्थिर शून्य
userauth_send_banner(संरचना ssh *ssh, ध्रुव वर्ण *सन्देशः)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, सन्देशः)) != 0 ||
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
		प्रत्यागम;

	यदि ((banner = mm_auth2_read_banner()) == रिक्त)
		गच्छ समाप्तम्;
	userauth_send_banner(ssh, banner);

समाप्तम्:
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
		ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, &kex_निवेशः_ext_info);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_SERVICE_REQUEST, &निवेशः_service_request);
	ssh_dispatch_सततम्_fatal(ssh, DISPATCH_खण्डम्, &authctxt->success);
	ssh->authctxt = रिक्त;
}

स्थिर पूर्णाङ्क
निवेशः_service_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	वर्ण *service = रिक्त;
	पूर्णाङ्क r, acceptit = 0;

	यदि ((r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	यदि (authctxt == रिक्त)
		fatal("input_service_request: no authctxt");

	यदि (वाक्यं_तुलय(service, "ssh-userauth") == 0) {
		यदि (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_REQUEST,
			    &निवेशः_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	यदि (acceptit) {
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			गच्छ बहिर्गमनम्;
	} अन्यथा {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 बहिर्गमनम्:
	मुक्त(service);
	प्रत्यागम r;
}

#परिभाषय MIN_FAIL_DELAY_SECONDS 0.005
#परिभाषय MAX_FAIL_DELAY_SECONDS 5.0
स्थिर द्विगुण
user_specific_delay(ध्रुव वर्ण *user)
{
	वर्ण b[512];
	आकार_t len = ssh_digest_अष्टकानि(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	द्विगुण delay;

	(शून्य)snprintf(b, परिमाण b, "%llu%s",
	    (अचिह्नित दीर्घ दीर्घ)options.timing_secret, user);
	यदि (ssh_digest_स्मृतिः(SSH_DIGEST_SHA512, b, वाक्यदैर्घ्यम्(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (द्विगुण)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	प्रत्यागम MIN_FAIL_DELAY_SECONDS + delay;
}

स्थिर शून्य
ensure_minimum_time_since(द्विगुण start, द्विगुण seconds)
{
	संरचना timespec ts;
	द्विगुण elapsed = monotime_double() - start, req = seconds, remain;

	यदि (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		प्रत्यागम;
	}

	/* if we've already passed the requested time, scale up */
	यावत् ((remain = seconds - elapsed) < 0.0)
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
निवेशः_userauth_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	वर्ण *user = रिक्त, *service = रिक्त, *विधानम् = रिक्त, *style = रिक्त;
	पूर्णाङ्क r, authenticated = 0;
	द्विगुण tstart = monotime_double();

	यदि (authctxt == रिक्त)
		fatal("input_userauth_request: no authctxt");

	यदि ((r = sshpkt_get_cstring(ssh, &user, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &विधानम्, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	debug("userauth-request for user %s service %s method %s", user, service, विधानम्);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	यदि ((style = strchr(user, ':')) != रिक्त)
		*style++ = 0;

	यदि (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	यदि (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : रिक्त;
		यदि (authctxt->pw && वाक्यं_तुलय(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} अन्यथा {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#यदि_अन्तः
		}
#यदि_परिभाषितम् USE_PAM
		यदि (options.use_pam)
			mm_start_pam(ssh);
#यदि_अन्तः
		ssh_packet_समुच्चयः_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		यदि ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		यदि (auth2_सज्जता_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} अन्यथा यदि (वाक्यं_तुलय(user, authctxt->user) != 0 ||
	    वाक्यं_तुलय(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#यदि_परिभाषितम् GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
#यदि_अन्तः

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, विधानम्);
	यदि (m != रिक्त && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", विधानम्);
		authenticated =	m->userauth(ssh, विधानम्);
	}
	यदि (!authctxt->authenticated && वाक्यं_तुलय(विधानम्, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, विधानम्, रिक्त);
	r = 0;
 बहिर्गमनम्:
	मुक्त(service);
	मुक्त(user);
	मुक्त(विधानम्);
	प्रत्यागम r;
}

शून्य
userauth_finish(संरचना ssh *ssh, पूर्णाङ्क authenticated, ध्रुव वर्ण *packet_विधानम्,
    ध्रुव वर्ण *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = रिक्त;
	ध्रुव वर्ण *विधानम् = packet_विधानम्;
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
		यदि ((m = authmethod_byname(विधानम्)) == रिक्त)
			fatal("INTERNAL ERROR: bad method %s", विधानम्);
		विधानम् = m->cfg->name;
	}

	/* Special handling for root */
	यदि (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_मूलम्_allowed(ssh, विधानम्)) {
		authenticated = 0;
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_मूलम्_DENIED);
#यदि_अन्तः
	}

	यदि (authenticated && options.अङ्कः_auth_methods != 0) {
		यदि (!auth2_update_methods_lists(authctxt, विधानम्, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, विधानम्, submethod);

	/* Update information exposed to session */
	यदि (authenticated || partial)
		auth2_update_session_info(authctxt, विधानम्, submethod);

	यदि (authctxt->postponed)
		प्रत्यागम;

#यदि_परिभाषितम् USE_PAM
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
#यदि_अन्तः

	यदि (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_समुच्चयः_log_preamble(ssh, "user %s", authctxt->user);
	} अन्यथा {
		/* Allow initial try of "none" auth without failure penalty */
		यदि (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || वाक्यं_तुलय(विधानम्, "none") != 0))
			authctxt->failures++;
		यदि (authctxt->failures >= options.max_authtries) {
#यदि_परिभाषितम् SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#यदि_अन्तः
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_FAILURE)) != 0 ||
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
auth2_विधानम्_allowed(Authctxt *authctxt, ध्रुव वर्ण *विधानम्,
    ध्रुव वर्ण *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	यदि (options.अङ्कः_auth_methods == 0)
		प्रत्यागम 1;
	प्रति (i = 0; i < authctxt->अङ्कः_auth_methods; i++) {
		यदि (list_starts_with(authctxt->auth_methods[i], विधानम्,
		    submethod) != मेलनम्_NONE)
			प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

स्थिर वर्ण *
authmethods_get(Authctxt *authctxt)
{
	संरचना sshbuf *b;
	वर्ण *list;
	पूर्णाङ्क i, r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	प्रति (i = 0; authmethods[i] != रिक्त; i++) {
		यदि (वाक्यं_तुलय(authmethods[i]->cfg->name, "none") == 0)
			अनुवर्त;
		यदि (authmethods[i]->cfg->enabled == रिक्त ||
		    *(authmethods[i]->cfg->enabled) == 0)
			अनुवर्त;
		यदि (!auth2_विधानम्_allowed(authctxt, authmethods[i]->cfg->name,
		    रिक्त))
			अनुवर्त;
		यदि ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	यदि ((list = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	प्रत्यागम list;
}

स्थिर Authmethod *
authmethod_byname(ध्रुव वर्ण *name)
{
	पूर्णाङ्क i;

	यदि (name == रिक्त)
		fatal_f("NULL authentication method name");
	प्रति (i = 0; authmethods[i] != रिक्त; i++) {
		यदि (वाक्यं_तुलय(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != रिक्त &&
		    वाक्यं_तुलय(name, authmethods[i]->cfg->synonym) == 0))
			प्रत्यागम authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	प्रत्यागम रिक्त;
}

स्थिर Authmethod *
authmethod_lookup(Authctxt *authctxt, ध्रुव वर्ण *name)
{
	Authmethod *विधानम्;

	यदि ((विधानम् = authmethod_byname(name)) == रिक्त)
		प्रत्यागम रिक्त;

	यदि (विधानम्->cfg->enabled == रिक्त || *(विधानम्->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		प्रत्यागम रिक्त;
	}
	यदि (!auth2_विधानम्_allowed(authctxt, विधानम्->cfg->name, रिक्त)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम विधानम्;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
पूर्णाङ्क
auth2_सज्जता_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	यदि (options.अङ्कः_auth_methods == 1 &&
	    वाक्यं_तुलय(options.auth_methods[0], "any") == 0) {
		मुक्त(options.auth_methods[0]);
		options.auth_methods[0] = रिक्त;
		options.अङ्कः_auth_methods = 0;
	}

	यदि (options.अङ्कः_auth_methods == 0)
		प्रत्यागम 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.अङ्कः_auth_methods,
	    परिमाण(*authctxt->auth_methods));
	authctxt->अङ्कः_auth_methods = 0;
	प्रति (i = 0; i < options.अङ्कः_auth_methods; i++) {
		यदि (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			अनुवर्त;
		}
		debug("authentication methods list %d: %s",
		    authctxt->अङ्कः_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->अङ्कः_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	यदि (authctxt->अङ्कः_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		प्रत्यागम -1;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
list_starts_with(ध्रुव वर्ण *methods, ध्रुव वर्ण *विधानम्,
    ध्रुव वर्ण *submethod)
{
	आकार_t l = वाक्यदैर्घ्यम्(विधानम्);
	पूर्णाङ्क मेलनम्;
	ध्रुव वर्ण *p;

	यदि (वाक्ये_तुलय(methods, विधानम्, l) != 0)
		प्रत्यागम मेलनम्_NONE;
	p = methods + l;
	मेलनम् = मेलनम्_विधानम्;
	यदि (*p == ':') {
		यदि (!submethod)
			प्रत्यागम मेलनम्_PARTIAL;
		l = वाक्यदैर्घ्यम्(submethod);
		p += 1;
		यदि (वाक्ये_तुलय(submethod, p, l))
			प्रत्यागम मेलनम्_NONE;
		p += l;
		मेलनम् = मेलनम्_BOTH;
	}
	यदि (*p != ',' && *p != '\0')
		प्रत्यागम मेलनम्_NONE;
	प्रत्यागम मेलनम्;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
स्थिर पूर्णाङ्क
remove_विधानम्(वर्ण **methods, ध्रुव वर्ण *विधानम्, ध्रुव वर्ण *submethod)
{
	वर्ण *omethods = *methods, *p;
	आकार_t l = वाक्यदैर्घ्यम्(विधानम्);
	पूर्णाङ्क मेलनम्;

	मेलनम् = list_starts_with(omethods, विधानम्, submethod);
	यदि (मेलनम् != मेलनम्_विधानम् && मेलनम् != मेलनम्_BOTH)
		प्रत्यागम 0;
	p = omethods + l;
	यदि (submethod && मेलनम् == मेलनम्_BOTH)
		p += 1 + वाक्यदैर्घ्यम्(submethod); /* include colon */
	यदि (*p == ',')
		p++;
	*methods = xstrdup(p);
	मुक्त(omethods);
	प्रत्यागम 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
पूर्णाङ्क
auth2_update_methods_lists(Authctxt *authctxt, ध्रुव वर्ण *विधानम्,
    ध्रुव वर्ण *submethod)
{
	u_int i, प्राप्तम् = 0;

	debug3_f("updating methods list after \"%s\"", विधानम्);
	प्रति (i = 0; i < authctxt->अङ्कः_auth_methods; i++) {
		यदि (!remove_विधानम्(&(authctxt->auth_methods[i]), विधानम्,
		    submethod))
			अनुवर्त;
		प्राप्तम् = 1;
		यदि (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			प्रत्यागम 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	यदि (!प्राप्तम्)
		fatal_f("method not in AuthenticationMethods");
	प्रत्यागम 0;
}

/* Reset method-specific information */
शून्य auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_विधानम्_कुञ्चिका);
	मुक्त(authctxt->auth_विधानम्_info);
	authctxt->auth_विधानम्_कुञ्चिका = रिक्त;
	authctxt->auth_विधानम्_info = रिक्त;
}

/* Record auth method-specific information for logs */
शून्य
auth2_लेखः_info(Authctxt *authctxt, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	पूर्णाङ्क i;

	मुक्त(authctxt->auth_विधानम्_info);
	authctxt->auth_विधानम्_info = रिक्त;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_विधानम्_info, fmt, ap);
	va_end(ap);

	यदि (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
शून्य
auth2_लेखः_कुञ्चिका(Authctxt *authctxt, पूर्णाङ्क authenticated,
    ध्रुव संरचना sshkey *कुञ्चिका)
{
	संरचना sshkey **tmp, *dup;
	पूर्णाङ्क r;

	यदि ((r = sshkey_from_वैयक्तिकम्(कुञ्चिका, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_विधानम्_कुञ्चिका);
	authctxt->auth_विधानम्_कुञ्चिका = dup;

	यदि (!authenticated)
		प्रत्यागम;

	/* If authenticated, make sure we don't accept this key again */
	यदि ((r = sshkey_from_वैयक्तिकम्(कुञ्चिका, &dup)) != 0)
		fatal_fr(r, "copy key");
	यदि (authctxt->nprev_कुञ्चिकाः >= अधिकतम_पूर्णाङ्कः ||
	    (tmp = recallocarray(authctxt->पूर्व_कुञ्चिकाः, authctxt->nprev_कुञ्चिकाः,
	    authctxt->nprev_कुञ्चिकाः + 1, परिमाण(*authctxt->पूर्व_कुञ्चिकाः))) == रिक्त)
		fatal_f("reallocarray failed");
	authctxt->पूर्व_कुञ्चिकाः = tmp;
	authctxt->पूर्व_कुञ्चिकाः[authctxt->nprev_कुञ्चिकाः] = dup;
	authctxt->nprev_कुञ्चिकाः++;

}

/* Checks whether a key has already been previously used for authentication */
पूर्णाङ्क
auth2_कुञ्चिका_already_प्रयुक्तम्(Authctxt *authctxt, ध्रुव संरचना sshkey *कुञ्चिका)
{
	u_int i;
	वर्ण *fp;

	प्रति (i = 0; i < authctxt->nprev_कुञ्चिकाः; i++) {
		यदि (sshkey_equal_लौकिकम्(कुञ्चिका, authctxt->पूर्व_कुञ्चिकाः[i])) {
			fp = sshkey_fingerprint(authctxt->पूर्व_कुञ्चिकाः[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->पूर्व_कुञ्चिकाः[i]),
			    fp == रिक्त ? "UNKNOWN" : fp);
			मुक्त(fp);
			प्रत्यागम 1;
		}
	}
	प्रत्यागम 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
शून्य
auth2_update_session_info(Authctxt *authctxt, ध्रुव वर्ण *विधानम्,
    ध्रुव वर्ण *submethod)
{
	पूर्णाङ्क r;

	यदि (authctxt->session_info == रिक्त) {
		यदि ((authctxt->session_info = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	यदि ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    विधानम्, submethod == रिक्त ? "" : "/",
	    submethod == रिक्त ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	यदि (authctxt->auth_विधानम्_कुञ्चिका != रिक्त) {
		यदि ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_विधानम्_कुञ्चिका,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	यदि (authctxt->auth_विधानम्_info != रिक्त) {
		/* Ensure no ambiguity here */
		यदि (strchr(authctxt->auth_विधानम्_info, '\n') != रिक्त)
			fatal_f("auth_method_info contains \\n");
		यदि ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_विधानम्_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	यदि ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

