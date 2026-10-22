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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "stdlib.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"

/* import */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;

/* methods */

ବାହ୍ୟ Authmethod method_none;
ବାହ୍ୟ Authmethod method_pubkey;
ବାହ୍ୟ Authmethod method_passwd;
ବାହ୍ୟ Authmethod method_kbdint;
ବାହ୍ୟ Authmethod method_hostbased;
#ifdef GSSAPI
ବାହ୍ୟ Authmethod method_gssapi;
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
	ଖାଲି
};

/* protocol */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_service_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

/* helper */
ସ୍ଥିର Authmethod *authmethod_byname(ଅଚଳ ଅକ୍ଷର *);
ସ୍ଥିର Authmethod *authmethod_lookup(Authctxt *, ଅଚଳ ଅକ୍ଷର *);
ସ୍ଥିର ଅକ୍ଷର *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା list_starts_with(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

ଅକ୍ଷର *
auth2_read_banner(ଶୂନ୍ୟ)
{
	ସଂରଚନା stat st;
	ଅକ୍ଷର *banner = ଖାଲି;
	size_t len, n;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	ଯଦି ((fd = open(options.banner, O_RDONLY)) == -1)
		ଫେରନ୍ତୁ (ଖାଲି);
	ଯଦି (fstat(fd, &st) == -1) {
		close(fd);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	ଯଦି (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(ପଠ, fd, banner, len);
	close(fd);

	ଯଦି (n != len) {
		ମୁକ୍ତ(banner);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	banner[n] = '\0';

	ଫେରନ୍ତୁ (banner);
}

ସ୍ଥିର ଶୂନ୍ୟ
userauth_send_banner(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ସନ୍ଦେଶ)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ସ୍ଥିର ଶୂନ୍ୟ
userauth_banner(ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର *banner = ଖାଲି;

	ଯଦି (options.banner == ଖାଲି)
		ଫେରନ୍ତୁ;

	ଯଦି ((banner = mm_auth2_read_banner()) == ଖାଲି)
		ଯାଅ done;
	userauth_send_banner(ssh, banner);

done:
	ମୁକ୍ତ(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
ଶୂନ୍ୟ
do_authentication2(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ଯଦି (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, &kex_ନିବେଶ_ext_info);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_SERVICE_REQUEST, &ନିବେଶ_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_service_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ଅକ୍ଷର *service = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, acceptit = 0;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &service, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_service_request: no authctxt");

	ଯଦି (strcmp(service, "ssh-userauth") == 0) {
		ଯଦି (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST,
			    &ନିବେଶ_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	ଯଦି (acceptit) {
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	ମୁକ୍ତ(service);
	ଫେରନ୍ତୁ r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
ସ୍ଥିର ଦ୍ୱିଗୁଣ
user_specific_delay(ଅଚଳ ଅକ୍ଷର *user)
{
	ଅକ୍ଷର b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ଦ୍ୱିଗୁଣ delay;

	(ଶୂନ୍ୟ)snprintf(b, ଆକାର b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	ଯଦି (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ଦ୍ୱିଗୁଣ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ଫେରନ୍ତୁ MIN_FAIL_DELAY_SECONDS + delay;
}

ସ୍ଥିର ଶୂନ୍ୟ
ensure_minimum_time_since(ଦ୍ୱିଗୁଣ start, ଦ୍ୱିଗୁଣ seconds)
{
	ସଂରଚନା timespec ts;
	ଦ୍ୱିଗୁଣ elapsed = monotime_double() - start, req = seconds, remain;

	ଯଦି (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ଫେରନ୍ତୁ;
	}

	/* if we've already passed the requested time, scale up */
	ଯେତେବେଳେ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ଖାଲି);
}

ଶୂନ୍ୟ
auth_failure_delay(Authctxt *authctxt, ଦ୍ୱିଗୁଣ tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ଖାଲି;
	ଅକ୍ଷର *user = ଖାଲି, *service = ଖାଲି, *method = ଖାଲି, *style = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated = 0;
	ଦ୍ୱିଗୁଣ tstart = monotime_double();

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_userauth_request: no authctxt");

	ଯଦି ((r = sshpkt_get_cstring(ssh, &user, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, ଖାଲି)) != 0)
		ଯାଅ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	ଯଦି ((style = strchr(user, ':')) != ଖାଲି)
		*style++ = 0;

	ଯଦି (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	ଯଦି (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ଖାଲି;
		ଯଦି (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} ଅନ୍ୟଥା {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		ଯଦି (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		ଯଦି ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		ଯଦି (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} ଅନ୍ୟଥା ଯଦି (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#ifdef GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ଖାଲି);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	ଯଦି (m != ଖାଲି && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	ଯଦି (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, ଖାଲି);
	r = 0;
 out:
	ମୁକ୍ତ(service);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(method);
	ଫେରନ୍ତୁ r;
}

ଶୂନ୍ୟ
userauth_finish(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା authenticated, ଅଚଳ ଅକ୍ଷର *packet_method,
    ଅଚଳ ଅକ୍ଷର *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *method = packet_method;
	ଅକ୍ଷର *methods;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, partial = 0;

	ଯଦି (authenticated) {
		ଯଦି (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		ଯଦି (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		ଯଦି ((m = authmethod_byname(method)) == ଖାଲି)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	ଯଦି (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_ମୂଳ_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ମୂଳ_DENIED);
#endif
	}

	ଯଦି (authenticated && options.ଅଙ୍କ_auth_methods != 0) {
		ଯଦି (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	ଯଦି (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	ଯଦି (authctxt->postponed)
		ଫେରନ୍ତୁ;

#ifdef USE_PAM
	ଯଦି (options.use_pam && authenticated) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		ଯଦି (sshbuf_len(loginmsg) > 0) {
			ଯଦି ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			ଯଦି ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		ଯଦି (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	ଯଦି (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} ଅନ୍ୟଥା {
		/* Allow initial try of "none" auth without failure penalty */
		ଯଦି (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		ଯଦି (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		ମୁକ୍ତ(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_method_allowed(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *method,
    ଅଚଳ ଅକ୍ଷର *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	ଯଦି (options.ଅଙ୍କ_auth_methods == 0)
		ଫେରନ୍ତୁ 1;
	ପାଇଁ (i = 0; i < authctxt->ଅଙ୍କ_auth_methods; i++) {
		ଯଦି (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅକ୍ଷର *
authmethods_get(Authctxt *authctxt)
{
	ସଂରଚନା sshbuf *b;
	ଅକ୍ଷର *list;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ପାଇଁ (i = 0; authmethods[i] != ଖାଲି; i++) {
		ଯଦି (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ଜାରି;
		ଯଦି (authmethods[i]->cfg->enabled == ଖାଲି ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ଜାରି;
		ଯଦି (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    ଖାଲି))
			ଜାରି;
		ଯଦି ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	ଯଦି ((list = sshbuf_dup_string(b)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ଫେରନ୍ତୁ list;
}

ସ୍ଥିର Authmethod *
authmethod_byname(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (name == ଖାଲି)
		fatal_f("NULL authentication method name");
	ପାଇଁ (i = 0; authmethods[i] != ଖାଲି; i++) {
		ଯଦି (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ଖାଲି &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ଫେରନ୍ତୁ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର Authmethod *
authmethod_lookup(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *name)
{
	Authmethod *method;

	ଯଦି ((method = authmethod_byname(name)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	ଯଦି (method->cfg->enabled == ଖାଲି || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (!auth2_method_allowed(authctxt, method->cfg->name, ଖାଲି)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	ଯଦି (options.ଅଙ୍କ_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		ମୁକ୍ତ(options.auth_methods[0]);
		options.auth_methods[0] = ଖାଲି;
		options.ଅଙ୍କ_auth_methods = 0;
	}

	ଯଦି (options.ଅଙ୍କ_auth_methods == 0)
		ଫେରନ୍ତୁ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.ଅଙ୍କ_auth_methods,
	    ଆକାର(*authctxt->auth_methods));
	authctxt->ଅଙ୍କ_auth_methods = 0;
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_auth_methods; i++) {
		ଯଦି (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ଜାରି;
		}
		debug("authentication methods list %d: %s",
		    authctxt->ଅଙ୍କ_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->ଅଙ୍କ_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	ଯଦି (authctxt->ଅଙ୍କ_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
list_starts_with(ଅଚଳ ଅକ୍ଷର *methods, ଅଚଳ ଅକ୍ଷର *method,
    ଅଚଳ ଅକ୍ଷର *submethod)
{
	size_t l = strlen(method);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match;
	ଅଚଳ ଅକ୍ଷର *p;

	ଯଦି (strncmp(methods, method, l) != 0)
		ଫେରନ୍ତୁ MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	ଯଦି (*p == ':') {
		ଯଦି (!submethod)
			ଫେରନ୍ତୁ MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		ଯଦି (strncmp(submethod, p, l))
			ଫେରନ୍ତୁ MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	ଯଦି (*p != ',' && *p != '\0')
		ଫେରନ୍ତୁ MATCH_NONE;
	ଫେରନ୍ତୁ match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
remove_method(ଅକ୍ଷର **methods, ଅଚଳ ଅକ୍ଷର *method, ଅଚଳ ଅକ୍ଷର *submethod)
{
	ଅକ୍ଷର *omethods = *methods, *p;
	size_t l = strlen(method);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match;

	match = list_starts_with(omethods, method, submethod);
	ଯଦି (match != MATCH_METHOD && match != MATCH_BOTH)
		ଫେରନ୍ତୁ 0;
	p = omethods + l;
	ଯଦି (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	ଯଦି (*p == ',')
		p++;
	*methods = xstrdup(p);
	ମୁକ୍ତ(omethods);
	ଫେରନ୍ତୁ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_update_methods_lists(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *method,
    ଅଚଳ ଅକ୍ଷର *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	ପାଇଁ (i = 0; i < authctxt->ଅଙ୍କ_auth_methods; i++) {
		ଯଦି (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			ଜାରି;
		found = 1;
		ଯଦି (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ଫେରନ୍ତୁ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	ଯଦି (!found)
		fatal_f("method not in AuthenticationMethods");
	ଫେରନ୍ତୁ 0;
}

/* Reset method-specific information */
ଶୂନ୍ୟ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_ଚାବି);
	ମୁକ୍ତ(authctxt->auth_method_info);
	authctxt->auth_method_ଚାବି = ଖାଲି;
	authctxt->auth_method_info = ଖାଲି;
}

/* Record auth method-specific information for logs */
ଶୂନ୍ୟ
auth2_record_info(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ମୁକ୍ତ(authctxt->auth_method_info);
	authctxt->auth_method_info = ଖାଲି;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	ଯଦି (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
ଶୂନ୍ୟ
auth2_record_ଚାବି(Authctxt *authctxt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା authenticated,
    ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା sshkey **tmp, *dup;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_from_private(ଚାବି, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_ଚାବି);
	authctxt->auth_method_ଚାବି = dup;

	ଯଦି (!authenticated)
		ଫେରନ୍ତୁ;

	/* If authenticated, make sure we don't accept this key again */
	ଯଦି ((r = sshkey_from_private(ଚାବି, &dup)) != 0)
		fatal_fr(r, "copy key");
	ଯଦି (authctxt->nprev_ଚାବିଗୁଡ଼ିକ >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_ଚାବିଗୁଡ଼ିକ, authctxt->nprev_ଚାବିଗୁଡ଼ିକ,
	    authctxt->nprev_ଚାବିଗୁଡ଼ିକ + 1, ଆକାର(*authctxt->prev_ଚାବିଗୁଡ଼ିକ))) == ଖାଲି)
		fatal_f("reallocarray failed");
	authctxt->prev_ଚାବିଗୁଡ଼ିକ = tmp;
	authctxt->prev_ଚାବିଗୁଡ଼ିକ[authctxt->nprev_ଚାବିଗୁଡ଼ିକ] = dup;
	authctxt->nprev_ଚାବିଗୁଡ଼ିକ++;

}

/* Checks whether a key has already been previously used for authentication */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_ଚାବି_already_used(Authctxt *authctxt, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	u_int i;
	ଅକ୍ଷର *fp;

	ପାଇଁ (i = 0; i < authctxt->nprev_ଚାବିଗୁଡ଼ିକ; i++) {
		ଯଦି (sshkey_equal_public(ଚାବି, authctxt->prev_ଚାବିଗୁଡ଼ିକ[i])) {
			fp = sshkey_fingerprint(authctxt->prev_ଚାବିଗୁଡ଼ିକ[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_ଚାବିଗୁଡ଼ିକ[i]),
			    fp == ଖାଲି ? "UNKNOWN" : fp);
			ମୁକ୍ତ(fp);
			ଫେରନ୍ତୁ 1;
		}
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
ଶୂନ୍ୟ
auth2_update_session_info(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *method,
    ଅଚଳ ଅକ୍ଷର *submethod)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt->session_info == ଖାଲି) {
		ଯଦି ((authctxt->session_info = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	ଯଦି ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == ଖାଲି ? "" : "/",
	    submethod == ଖାଲି ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	ଯଦି (authctxt->auth_method_ଚାବି != ଖାଲି) {
		ଯଦି ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_ଚାବି,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	ଯଦି (authctxt->auth_method_info != ଖାଲି) {
		/* Ensure no ambiguity here */
		ଯଦି (strchr(authctxt->auth_method_info, '\n') != ଖାଲି)
			fatal_f("auth_method_info contains \\n");
		ଯଦି ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	ଯଦି ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

