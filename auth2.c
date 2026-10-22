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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "stdlib.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssherr.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "kex.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం sshbuf *loginmsg;

/* methods */

బాహ్య Authmethod పద్ధతి_none;
బాహ్య Authmethod పద్ధతి_pubkey;
బాహ్య Authmethod పద్ధతి_passwd;
బాహ్య Authmethod పద్ధతి_kbdint;
బాహ్య Authmethod పద్ధతి_hostbased;
#నిర్వచితమైతే GSSAPI
బాహ్య Authmethod పద్ధతి_gssapi;
#అయితే_ముగింపు

Authmethod *authmethods[] = {
	&పద్ధతి_none,
	&పద్ధతి_pubkey,
#నిర్వచితమైతే GSSAPI
	&పద్ధతి_gssapi,
#అయితే_ముగింపు
	&పద్ధతి_passwd,
	&పద్ధతి_kbdint,
	&పద్ధతి_hostbased,
	ఖాళీ
};

/* protocol */

స్థిర పూర్ణాంకం ఆదానం_service_request(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_request(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

/* helper */
స్థిర Authmethod *authmethod_byname(స్థిరరాశి అక్షరం *);
స్థిర Authmethod *authmethod_lookup(Authctxt *, స్థిరరాశి అక్షరం *);
స్థిర అక్షరం *authmethods_get(Authctxt *authctxt);

#నిర్వచించు సరిపోలిక_NONE	0	/* method or submethod mismatch */
#నిర్వచించు సరిపోలిక_పద్ధతి	1	/* method matches (no submethod specified) */
#నిర్వచించు సరిపోలిక_BOTH	2	/* method and submethod match */
#నిర్వచించు సరిపోలిక_PARTIAL	3	/* method matches, submethod can't be checked */
స్థిర పూర్ణాంకం list_starts_with(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

అక్షరం *
auth2_read_banner(శూన్య)
{
	నిర్మాణం stat st;
	అక్షరం *banner = ఖాళీ;
	కొలత_t len, n;
	పూర్ణాంకం fd;

	ఒకవేళ ((fd = open(options.banner, O_RDONLY)) == -1)
		తిరిగి (ఖాళీ);
	ఒకవేళ (fstat(fd, &st) == -1) {
		close(fd);
		తిరిగి (ఖాళీ);
	}
	ఒకవేళ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		తిరిగి (ఖాళీ);
	}

	len = (కొలత_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(పఠ, fd, banner, len);
	close(fd);

	ఒకవేళ (n != len) {
		విడుదల(banner);
		తిరిగి (ఖాళీ);
	}
	banner[n] = '\0';

	తిరిగి (banner);
}

స్థిర శూన్య
userauth_send_banner(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *సందేశం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, సందేశం)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

స్థిర శూన్య
userauth_banner(నిర్మాణం ssh *ssh)
{
	అక్షరం *banner = ఖాళీ;

	ఒకవేళ (options.banner == ఖాళీ)
		తిరిగి;

	ఒకవేళ ((banner = mm_auth2_read_banner()) == ఖాళీ)
		వెళ్ళు పూర్తి;
	userauth_send_banner(ssh, banner);

పూర్తి:
	విడుదల(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
శూన్య
do_authentication2(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ఒకవేళ (ssh->kex->ext_info_c)
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, &kex_ఆదానం_ext_info);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_SERVICE_REQUEST, &ఆదానం_service_request);
	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_ఖండం, &authctxt->success);
	ssh->authctxt = ఖాళీ;
}

స్థిర పూర్ణాంకం
ఆదానం_service_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	అక్షరం *service = ఖాళీ;
	పూర్ణాంకం r, acceptit = 0;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &service, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_service_request: no authctxt");

	ఒకవేళ (strcmp(service, "ssh-userauth") == 0) {
		ఒకవేళ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_REQUEST,
			    &ఆదానం_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	ఒకవేళ (acceptit) {
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 బహిర్గతం:
	విడుదల(service);
	తిరిగి r;
}

#నిర్వచించు MIN_FAIL_DELAY_SECONDS 0.005
#నిర్వచించు MAX_FAIL_DELAY_SECONDS 5.0
స్థిర ద్విగుణ
user_specific_delay(స్థిరరాశి అక్షరం *user)
{
	అక్షరం b[512];
	కొలత_t len = ssh_digest_బైట్లు(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ద్విగుణ delay;

	(శూన్య)snprintf(b, పరిమాణం b, "%llu%s",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)options.timing_secret, user);
	ఒకవేళ (ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA512, b, అక్షరశ్రేణి_పొడవు(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ద్విగుణ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	తిరిగి MIN_FAIL_DELAY_SECONDS + delay;
}

స్థిర శూన్య
ensure_minimum_సమయం_since(ద్విగుణ ప్రారంభం, ద్విగుణ seconds)
{
	నిర్మాణం timespec ts;
	ద్విగుణ elapsed = monotime_double() - ప్రారంభం, req = seconds, remain;

	ఒకవేళ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		తిరిగి;
	}

	/* if we've already passed the requested time, scale up */
	అయితే ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ఖాళీ);
}

శూన్య
auth_failure_delay(Authctxt *authctxt, ద్విగుణ tstart)
{
	ensure_minimum_సమయం_since(tstart, user_specific_delay(authctxt->user));
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ఖాళీ;
	అక్షరం *user = ఖాళీ, *service = ఖాళీ, *పద్ధతి = ఖాళీ, *style = ఖాళీ;
	పూర్ణాంకం r, authenticated = 0;
	ద్విగుణ tstart = monotime_double();

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_userauth_request: no authctxt");

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &user, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &పద్ధతి, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	debug("userauth-request for user %s service %s method %s", user, service, పద్ధతి);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	ఒకవేళ ((style = strchr(user, ':')) != ఖాళీ)
		*style++ = 0;

	ఒకవేళ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	ఒకవేళ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ఖాళీ;
		ఒకవేళ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} లేకపోతే {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#నిర్వచితమైతే SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#అయితే_ముగింపు
		}
#నిర్వచితమైతే USE_PAM
		ఒకవేళ (options.use_pam)
			mm_ప్రారంభం_pam(ssh);
#అయితే_ముగింపు
		ssh_packet_సమితి_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		ఒకవేళ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		ఒకవేళ (auth2_అమరిక_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} లేకపోతే ఒకవేళ (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#నిర్వచితమైతే GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ఖాళీ);
#అయితే_ముగింపు

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, పద్ధతి);
	ఒకవేళ (m != ఖాళీ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", పద్ధతి);
		authenticated =	m->userauth(ssh, పద్ధతి);
	}
	ఒకవేళ (!authctxt->authenticated && strcmp(పద్ధతి, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_ముగింపు(ssh, authenticated, పద్ధతి, ఖాళీ);
	r = 0;
 బహిర్గతం:
	విడుదల(service);
	విడుదల(user);
	విడుదల(పద్ధతి);
	తిరిగి r;
}

శూన్య
userauth_ముగింపు(నిర్మాణం ssh *ssh, పూర్ణాంకం authenticated, స్థిరరాశి అక్షరం *packet_పద్ధతి,
    స్థిరరాశి అక్షరం *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ఖాళీ;
	స్థిరరాశి అక్షరం *పద్ధతి = packet_పద్ధతి;
	అక్షరం *methods;
	పూర్ణాంకం r, partial = 0;

	ఒకవేళ (authenticated) {
		ఒకవేళ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		ఒకవేళ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		ఒకవేళ ((m = authmethod_byname(పద్ధతి)) == ఖాళీ)
			fatal("INTERNAL ERROR: bad method %s", పద్ధతి);
		పద్ధతి = m->cfg->name;
	}

	/* Special handling for root */
	ఒకవేళ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_మూలం_allowed(ssh, పద్ధతి)) {
		authenticated = 0;
#నిర్వచితమైతే SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_మూలం_DENIED);
#అయితే_ముగింపు
	}

	ఒకవేళ (authenticated && options.అంకె_auth_methods != 0) {
		ఒకవేళ (!auth2_update_methods_lists(authctxt, పద్ధతి, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, పద్ధతి, submethod);

	/* Update information exposed to session */
	ఒకవేళ (authenticated || partial)
		auth2_update_session_info(authctxt, పద్ధతి, submethod);

	ఒకవేళ (authctxt->postponed)
		తిరిగి;

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam && authenticated) {
		పూర్ణాంకం r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		ఒకవేళ (sshbuf_len(loginmsg) > 0) {
			ఒకవేళ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			ఒకవేళ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		ఒకవేళ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#అయితే_ముగింపు

	ఒకవేళ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_సమితి_log_preamble(ssh, "user %s", authctxt->user);
	} లేకపోతే {
		/* Allow initial try of "none" auth without failure penalty */
		ఒకవేళ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(పద్ధతి, "none") != 0))
			authctxt->failures++;
		ఒకవేళ (authctxt->failures >= options.max_authtries) {
#నిర్వచితమైతే SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#అయితే_ముగింపు
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		విడుదల(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
పూర్ణాంకం
auth2_పద్ధతి_allowed(Authctxt *authctxt, స్థిరరాశి అక్షరం *పద్ధతి,
    స్థిరరాశి అక్షరం *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	ఒకవేళ (options.అంకె_auth_methods == 0)
		తిరిగి 1;
	కొరకు (i = 0; i < authctxt->అంకె_auth_methods; i++) {
		ఒకవేళ (list_starts_with(authctxt->auth_methods[i], పద్ధతి,
		    submethod) != సరిపోలిక_NONE)
			తిరిగి 1;
	}
	తిరిగి 0;
}

స్థిర అక్షరం *
authmethods_get(Authctxt *authctxt)
{
	నిర్మాణం sshbuf *b;
	అక్షరం *list;
	పూర్ణాంకం i, r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	కొరకు (i = 0; authmethods[i] != ఖాళీ; i++) {
		ఒకవేళ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			కొనసాగు;
		ఒకవేళ (authmethods[i]->cfg->enabled == ఖాళీ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			కొనసాగు;
		ఒకవేళ (!auth2_పద్ధతి_allowed(authctxt, authmethods[i]->cfg->name,
		    ఖాళీ))
			కొనసాగు;
		ఒకవేళ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	ఒకవేళ ((list = sshbuf_dup_string(b)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	తిరిగి list;
}

స్థిర Authmethod *
authmethod_byname(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం i;

	ఒకవేళ (name == ఖాళీ)
		fatal_f("NULL authentication method name");
	కొరకు (i = 0; authmethods[i] != ఖాళీ; i++) {
		ఒకవేళ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ఖాళీ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			తిరిగి authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	తిరిగి ఖాళీ;
}

స్థిర Authmethod *
authmethod_lookup(Authctxt *authctxt, స్థిరరాశి అక్షరం *name)
{
	Authmethod *పద్ధతి;

	ఒకవేళ ((పద్ధతి = authmethod_byname(name)) == ఖాళీ)
		తిరిగి ఖాళీ;

	ఒకవేళ (పద్ధతి->cfg->enabled == ఖాళీ || *(పద్ధతి->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (!auth2_పద్ధతి_allowed(authctxt, పద్ధతి->cfg->name, ఖాళీ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		తిరిగి ఖాళీ;
	}
	తిరిగి పద్ధతి;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
పూర్ణాంకం
auth2_అమరిక_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	ఒకవేళ (options.అంకె_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		విడుదల(options.auth_methods[0]);
		options.auth_methods[0] = ఖాళీ;
		options.అంకె_auth_methods = 0;
	}

	ఒకవేళ (options.అంకె_auth_methods == 0)
		తిరిగి 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.అంకె_auth_methods,
	    పరిమాణం(*authctxt->auth_methods));
	authctxt->అంకె_auth_methods = 0;
	కొరకు (i = 0; i < options.అంకె_auth_methods; i++) {
		ఒకవేళ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			కొనసాగు;
		}
		debug("authentication methods list %d: %s",
		    authctxt->అంకె_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->అంకె_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	ఒకవేళ (authctxt->అంకె_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		తిరిగి -1;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
list_starts_with(స్థిరరాశి అక్షరం *methods, స్థిరరాశి అక్షరం *పద్ధతి,
    స్థిరరాశి అక్షరం *submethod)
{
	కొలత_t l = అక్షరశ్రేణి_పొడవు(పద్ధతి);
	పూర్ణాంకం సరిపోలిక;
	స్థిరరాశి అక్షరం *p;

	ఒకవేళ (అక్షరశ్రేణి_పోలిక(methods, పద్ధతి, l) != 0)
		తిరిగి సరిపోలిక_NONE;
	p = methods + l;
	సరిపోలిక = సరిపోలిక_పద్ధతి;
	ఒకవేళ (*p == ':') {
		ఒకవేళ (!submethod)
			తిరిగి సరిపోలిక_PARTIAL;
		l = అక్షరశ్రేణి_పొడవు(submethod);
		p += 1;
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(submethod, p, l))
			తిరిగి సరిపోలిక_NONE;
		p += l;
		సరిపోలిక = సరిపోలిక_BOTH;
	}
	ఒకవేళ (*p != ',' && *p != '\0')
		తిరిగి సరిపోలిక_NONE;
	తిరిగి సరిపోలిక;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
స్థిర పూర్ణాంకం
remove_పద్ధతి(అక్షరం **methods, స్థిరరాశి అక్షరం *పద్ధతి, స్థిరరాశి అక్షరం *submethod)
{
	అక్షరం *omethods = *methods, *p;
	కొలత_t l = అక్షరశ్రేణి_పొడవు(పద్ధతి);
	పూర్ణాంకం సరిపోలిక;

	సరిపోలిక = list_starts_with(omethods, పద్ధతి, submethod);
	ఒకవేళ (సరిపోలిక != సరిపోలిక_పద్ధతి && సరిపోలిక != సరిపోలిక_BOTH)
		తిరిగి 0;
	p = omethods + l;
	ఒకవేళ (submethod && సరిపోలిక == సరిపోలిక_BOTH)
		p += 1 + అక్షరశ్రేణి_పొడవు(submethod); /* include colon */
	ఒకవేళ (*p == ',')
		p++;
	*methods = xstrdup(p);
	విడుదల(omethods);
	తిరిగి 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
పూర్ణాంకం
auth2_update_methods_lists(Authctxt *authctxt, స్థిరరాశి అక్షరం *పద్ధతి,
    స్థిరరాశి అక్షరం *submethod)
{
	u_int i, దొరికింది = 0;

	debug3_f("updating methods list after \"%s\"", పద్ధతి);
	కొరకు (i = 0; i < authctxt->అంకె_auth_methods; i++) {
		ఒకవేళ (!remove_పద్ధతి(&(authctxt->auth_methods[i]), పద్ధతి,
		    submethod))
			కొనసాగు;
		దొరికింది = 1;
		ఒకవేళ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			తిరిగి 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	ఒకవేళ (!దొరికింది)
		fatal_f("method not in AuthenticationMethods");
	తిరిగి 0;
}

/* Reset method-specific information */
శూన్య auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_పద్ధతి_కీలకం);
	విడుదల(authctxt->auth_పద్ధతి_info);
	authctxt->auth_పద్ధతి_కీలకం = ఖాళీ;
	authctxt->auth_పద్ధతి_info = ఖాళీ;
}

/* Record auth method-specific information for logs */
శూన్య
auth2_రికార్డు_info(Authctxt *authctxt, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;
	పూర్ణాంకం i;

	విడుదల(authctxt->auth_పద్ధతి_info);
	authctxt->auth_పద్ధతి_info = ఖాళీ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_పద్ధతి_info, fmt, ap);
	va_end(ap);

	ఒకవేళ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
శూన్య
auth2_రికార్డు_కీలకం(Authctxt *authctxt, పూర్ణాంకం authenticated,
    స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం sshkey **tmp, *dup;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(కీలకం, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_పద్ధతి_కీలకం);
	authctxt->auth_పద్ధతి_కీలకం = dup;

	ఒకవేళ (!authenticated)
		తిరిగి;

	/* If authenticated, make sure we don't accept this key again */
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(కీలకం, &dup)) != 0)
		fatal_fr(r, "copy key");
	ఒకవేళ (authctxt->nprev_కీలకాలు >= గరిష్ఠ_పూర్ణాంకం ||
	    (tmp = recallocarray(authctxt->prev_కీలకాలు, authctxt->nprev_కీలకాలు,
	    authctxt->nprev_కీలకాలు + 1, పరిమాణం(*authctxt->prev_కీలకాలు))) == ఖాళీ)
		fatal_f("reallocarray failed");
	authctxt->prev_కీలకాలు = tmp;
	authctxt->prev_కీలకాలు[authctxt->nprev_కీలకాలు] = dup;
	authctxt->nprev_కీలకాలు++;

}

/* Checks whether a key has already been previously used for authentication */
పూర్ణాంకం
auth2_కీలకం_already_వాడిన(Authctxt *authctxt, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	u_int i;
	అక్షరం *fp;

	కొరకు (i = 0; i < authctxt->nprev_కీలకాలు; i++) {
		ఒకవేళ (sshkey_equal_ప్రజా(కీలకం, authctxt->prev_కీలకాలు[i])) {
			fp = sshkey_fingerprint(authctxt->prev_కీలకాలు[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_కీలకాలు[i]),
			    fp == ఖాళీ ? "UNKNOWN" : fp);
			విడుదల(fp);
			తిరిగి 1;
		}
	}
	తిరిగి 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
శూన్య
auth2_update_session_info(Authctxt *authctxt, స్థిరరాశి అక్షరం *పద్ధతి,
    స్థిరరాశి అక్షరం *submethod)
{
	పూర్ణాంకం r;

	ఒకవేళ (authctxt->session_info == ఖాళీ) {
		ఒకవేళ ((authctxt->session_info = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	ఒకవేళ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    పద్ధతి, submethod == ఖాళీ ? "" : "/",
	    submethod == ఖాళీ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	ఒకవేళ (authctxt->auth_పద్ధతి_కీలకం != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_పాఠ్యం(authctxt->auth_పద్ధతి_కీలకం,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	ఒకవేళ (authctxt->auth_పద్ధతి_info != ఖాళీ) {
		/* Ensure no ambiguity here */
		ఒకవేళ (strchr(authctxt->auth_పద్ధతి_info, '\n') != ఖాళీ)
			fatal_f("auth_method_info contains \\n");
		ఒకవేళ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_పద్ధతి_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	ఒకవేళ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

