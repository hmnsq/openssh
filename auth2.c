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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <time.h>

#அந்தர்பாவ "stdlib.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "ssherr.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "kex.h"

/* import */
வெளி ServerOptions options;
வெளி கட்டமைப்பு sshbuf *loginmsg;

/* methods */

வெளி Authmethod method_none;
வெளி Authmethod method_pubkey;
வெளி Authmethod method_passwd;
வெளி Authmethod method_kbdint;
வெளி Authmethod method_hostbased;
#ifdef GSSAPI
வெளி Authmethod method_gssapi;
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
	வெற்று
};

/* protocol */

நிலையான முழு உள்ளீடு_service_request(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_request(முழு, uint32_t, கட்டமைப்பு ssh *);

/* helper */
நிலையான Authmethod *authmethod_byname(மாறிலி எழுத்து *);
நிலையான Authmethod *authmethod_lookup(Authctxt *, மாறிலி எழுத்து *);
நிலையான எழுத்து *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
நிலையான முழு list_starts_with(மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

எழுத்து *
auth2_read_banner(வெறுமை)
{
	கட்டமைப்பு stat st;
	எழுத்து *banner = வெற்று;
	size_t len, n;
	முழு fd;

	எனில் ((fd = open(options.banner, O_RDONLY)) == -1)
		திரும்பு (வெற்று);
	எனில் (fstat(fd, &st) == -1) {
		close(fd);
		திரும்பு (வெற்று);
	}
	எனில் (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		திரும்பு (வெற்று);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(பட, fd, banner, len);
	close(fd);

	எனில் (n != len) {
		விடுவி(banner);
		திரும்பு (வெற்று);
	}
	banner[n] = '\0';

	திரும்பு (banner);
}

நிலையான வெறுமை
userauth_send_banner(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *செய்தி)
{
	முழு r;

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, செய்தி)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

நிலையான வெறுமை
userauth_banner(கட்டமைப்பு ssh *ssh)
{
	எழுத்து *banner = வெற்று;

	எனில் (options.banner == வெற்று)
		திரும்பு;

	எனில் ((banner = mm_auth2_read_banner()) == வெற்று)
		செல் done;
	userauth_send_banner(ssh, banner);

done:
	விடுவி(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
வெறுமை
do_authentication2(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	எனில் (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, &kex_உள்ளீடு_ext_info);
	ssh_dispatch_set(ssh, SSH2_செய்தி_SERVICE_REQUEST, &உள்ளீடு_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = வெற்று;
}

நிலையான முழு
உள்ளீடு_service_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	எழுத்து *service = வெற்று;
	முழு r, acceptit = 0;

	எனில் ((r = sshpkt_get_cstring(ssh, &service, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;

	எனில் (authctxt == வெற்று)
		fatal("input_service_request: no authctxt");

	எனில் (strcmp(service, "ssh-userauth") == 0) {
		எனில் (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_REQUEST,
			    &உள்ளீடு_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	எனில் (acceptit) {
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			செல் out;
	} இல்லையெனில் {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	விடுவி(service);
	திரும்பு r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
நிலையான இரட்டை
user_specific_delay(மாறிலி எழுத்து *user)
{
	எழுத்து b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	இரட்டை delay;

	(வெறுமை)snprintf(b, அளவு b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	எனில் (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (இரட்டை)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	திரும்பு MIN_FAIL_DELAY_SECONDS + delay;
}

நிலையான வெறுமை
ensure_minimum_time_since(இரட்டை start, இரட்டை seconds)
{
	கட்டமைப்பு timespec ts;
	இரட்டை elapsed = monotime_double() - start, req = seconds, remain;

	எனில் (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		திரும்பு;
	}

	/* if we've already passed the requested time, scale up */
	போது ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, வெற்று);
}

வெறுமை
auth_failure_delay(Authctxt *authctxt, இரட்டை tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

நிலையான முழு
உள்ளீடு_userauth_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = வெற்று;
	எழுத்து *user = வெற்று, *service = வெற்று, *method = வெற்று, *style = வெற்று;
	முழு r, authenticated = 0;
	இரட்டை tstart = monotime_double();

	எனில் (authctxt == வெற்று)
		fatal("input_userauth_request: no authctxt");

	எனில் ((r = sshpkt_get_cstring(ssh, &user, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, வெற்று)) != 0)
		செல் out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	எனில் ((style = strchr(user, ':')) != வெற்று)
		*style++ = 0;

	எனில் (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	எனில் (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : வெற்று;
		எனில் (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} இல்லையெனில் {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		எனில் (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		எனில் ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		எனில் (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} இல்லையெனில் எனில் (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, வெற்று);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	எனில் (m != வெற்று && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	எனில் (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, வெற்று);
	r = 0;
 out:
	விடுவி(service);
	விடுவி(user);
	விடுவி(method);
	திரும்பு r;
}

வெறுமை
userauth_finish(கட்டமைப்பு ssh *ssh, முழு authenticated, மாறிலி எழுத்து *packet_method,
    மாறிலி எழுத்து *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = வெற்று;
	மாறிலி எழுத்து *method = packet_method;
	எழுத்து *methods;
	முழு r, partial = 0;

	எனில் (authenticated) {
		எனில் (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		எனில் (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		எனில் ((m = authmethod_byname(method)) == வெற்று)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	எனில் (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_வேர்_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_வேர்_DENIED);
#endif
	}

	எனில் (authenticated && options.இலக்கம்_auth_methods != 0) {
		எனில் (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	எனில் (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	எனில் (authctxt->postponed)
		திரும்பு;

#ifdef USE_PAM
	எனில் (options.use_pam && authenticated) {
		முழு r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		எனில் (sshbuf_len(loginmsg) > 0) {
			எனில் ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			எனில் ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		எனில் (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	எனில் (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} இல்லையெனில் {
		/* Allow initial try of "none" auth without failure penalty */
		எனில் (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		எனில் (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		விடுவி(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
முழு
auth2_method_allowed(Authctxt *authctxt, மாறிலி எழுத்து *method,
    மாறிலி எழுத்து *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	எனில் (options.இலக்கம்_auth_methods == 0)
		திரும்பு 1;
	க்கு (i = 0; i < authctxt->இலக்கம்_auth_methods; i++) {
		எனில் (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			திரும்பு 1;
	}
	திரும்பு 0;
}

நிலையான எழுத்து *
authmethods_get(Authctxt *authctxt)
{
	கட்டமைப்பு sshbuf *b;
	எழுத்து *list;
	முழு i, r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	க்கு (i = 0; authmethods[i] != வெற்று; i++) {
		எனில் (strcmp(authmethods[i]->cfg->name, "none") == 0)
			தொடர்;
		எனில் (authmethods[i]->cfg->enabled == வெற்று ||
		    *(authmethods[i]->cfg->enabled) == 0)
			தொடர்;
		எனில் (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    வெற்று))
			தொடர்;
		எனில் ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	எனில் ((list = sshbuf_dup_string(b)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	திரும்பு list;
}

நிலையான Authmethod *
authmethod_byname(மாறிலி எழுத்து *name)
{
	முழு i;

	எனில் (name == வெற்று)
		fatal_f("NULL authentication method name");
	க்கு (i = 0; authmethods[i] != வெற்று; i++) {
		எனில் (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != வெற்று &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			திரும்பு authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	திரும்பு வெற்று;
}

நிலையான Authmethod *
authmethod_lookup(Authctxt *authctxt, மாறிலி எழுத்து *name)
{
	Authmethod *method;

	எனில் ((method = authmethod_byname(name)) == வெற்று)
		திரும்பு வெற்று;

	எனில் (method->cfg->enabled == வெற்று || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		திரும்பு வெற்று;
	}
	எனில் (!auth2_method_allowed(authctxt, method->cfg->name, வெற்று)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		திரும்பு வெற்று;
	}
	திரும்பு method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
முழு
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	எனில் (options.இலக்கம்_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		விடுவி(options.auth_methods[0]);
		options.auth_methods[0] = வெற்று;
		options.இலக்கம்_auth_methods = 0;
	}

	எனில் (options.இலக்கம்_auth_methods == 0)
		திரும்பு 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.இலக்கம்_auth_methods,
	    அளவு(*authctxt->auth_methods));
	authctxt->இலக்கம்_auth_methods = 0;
	க்கு (i = 0; i < options.இலக்கம்_auth_methods; i++) {
		எனில் (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			தொடர்;
		}
		debug("authentication methods list %d: %s",
		    authctxt->இலக்கம்_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->இலக்கம்_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	எனில் (authctxt->இலக்கம்_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		திரும்பு -1;
	}
	திரும்பு 0;
}

நிலையான முழு
list_starts_with(மாறிலி எழுத்து *methods, மாறிலி எழுத்து *method,
    மாறிலி எழுத்து *submethod)
{
	size_t l = strlen(method);
	முழு match;
	மாறிலி எழுத்து *p;

	எனில் (strncmp(methods, method, l) != 0)
		திரும்பு MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	எனில் (*p == ':') {
		எனில் (!submethod)
			திரும்பு MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		எனில் (strncmp(submethod, p, l))
			திரும்பு MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	எனில் (*p != ',' && *p != '\0')
		திரும்பு MATCH_NONE;
	திரும்பு match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
நிலையான முழு
remove_method(எழுத்து **methods, மாறிலி எழுத்து *method, மாறிலி எழுத்து *submethod)
{
	எழுத்து *omethods = *methods, *p;
	size_t l = strlen(method);
	முழு match;

	match = list_starts_with(omethods, method, submethod);
	எனில் (match != MATCH_METHOD && match != MATCH_BOTH)
		திரும்பு 0;
	p = omethods + l;
	எனில் (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	எனில் (*p == ',')
		p++;
	*methods = xstrdup(p);
	விடுவி(omethods);
	திரும்பு 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
முழு
auth2_update_methods_lists(Authctxt *authctxt, மாறிலி எழுத்து *method,
    மாறிலி எழுத்து *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	க்கு (i = 0; i < authctxt->இலக்கம்_auth_methods; i++) {
		எனில் (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			தொடர்;
		found = 1;
		எனில் (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			திரும்பு 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	எனில் (!found)
		fatal_f("method not in AuthenticationMethods");
	திரும்பு 0;
}

/* Reset method-specific information */
வெறுமை auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_சாவி);
	விடுவி(authctxt->auth_method_info);
	authctxt->auth_method_சாவி = வெற்று;
	authctxt->auth_method_info = வெற்று;
}

/* Record auth method-specific information for logs */
வெறுமை
auth2_record_info(Authctxt *authctxt, மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;
	முழு i;

	விடுவி(authctxt->auth_method_info);
	authctxt->auth_method_info = வெற்று;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	எனில் (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
வெறுமை
auth2_record_சாவி(Authctxt *authctxt, முழு authenticated,
    மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு sshkey **tmp, *dup;
	முழு r;

	எனில் ((r = sshkey_from_private(சாவி, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_சாவி);
	authctxt->auth_method_சாவி = dup;

	எனில் (!authenticated)
		திரும்பு;

	/* If authenticated, make sure we don't accept this key again */
	எனில் ((r = sshkey_from_private(சாவி, &dup)) != 0)
		fatal_fr(r, "copy key");
	எனில் (authctxt->nprev_சாவிகள் >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_சாவிகள், authctxt->nprev_சாவிகள்,
	    authctxt->nprev_சாவிகள் + 1, அளவு(*authctxt->prev_சாவிகள்))) == வெற்று)
		fatal_f("reallocarray failed");
	authctxt->prev_சாவிகள் = tmp;
	authctxt->prev_சாவிகள்[authctxt->nprev_சாவிகள்] = dup;
	authctxt->nprev_சாவிகள்++;

}

/* Checks whether a key has already been previously used for authentication */
முழு
auth2_சாவி_already_used(Authctxt *authctxt, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	u_int i;
	எழுத்து *fp;

	க்கு (i = 0; i < authctxt->nprev_சாவிகள்; i++) {
		எனில் (sshkey_equal_public(சாவி, authctxt->prev_சாவிகள்[i])) {
			fp = sshkey_fingerprint(authctxt->prev_சாவிகள்[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_சாவிகள்[i]),
			    fp == வெற்று ? "UNKNOWN" : fp);
			விடுவி(fp);
			திரும்பு 1;
		}
	}
	திரும்பு 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
வெறுமை
auth2_update_session_info(Authctxt *authctxt, மாறிலி எழுத்து *method,
    மாறிலி எழுத்து *submethod)
{
	முழு r;

	எனில் (authctxt->session_info == வெற்று) {
		எனில் ((authctxt->session_info = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	எனில் ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == வெற்று ? "" : "/",
	    submethod == வெற்று ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	எனில் (authctxt->auth_method_சாவி != வெற்று) {
		எனில் ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_சாவி,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	எனில் (authctxt->auth_method_info != வெற்று) {
		/* Ensure no ambiguity here */
		எனில் (strchr(authctxt->auth_method_info, '\n') != வெற்று)
			fatal_f("auth_method_info contains \\n");
		எனில் ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	எனில் ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

