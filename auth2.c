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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/uio.h>

#شامل <fcntl.h>
#شامل <limits.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <time.h>

#شامل "stdlib.h"
#شامل "atomicio.h"
#شامل "xmalloc.h"
#شامل "ssh2.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "dispatch.h"
#شامل "pathnames.h"
#شامل "ssherr.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "digest.h"
#شامل "kex.h"

/* import */
بیرونی ServerOptions options;
بیرونی ساختار sshbuf *loginmsg;

/* methods */

بیرونی Authmethod method_none;
بیرونی Authmethod method_pubkey;
بیرونی Authmethod method_passwd;
بیرونی Authmethod method_kbdint;
بیرونی Authmethod method_hostbased;
#ifdef GSSAPI
بیرونی Authmethod method_gssapi;
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
	پوچ
};

/* protocol */

ایستا صحیح درون_داد_service_request(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_request(صحیح, uint32_t, ساختار ssh *);

/* helper */
ایستا Authmethod *authmethod_byname(ثابت نویسه *);
ایستا Authmethod *authmethod_lookup(Authctxt *, ثابت نویسه *);
ایستا نویسه *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
ایستا صحیح list_starts_with(ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);

نویسه *
auth2_read_banner(تهی)
{
	ساختار stat st;
	نویسه *banner = پوچ;
	size_t len, n;
	صحیح fd;

	اگر ((fd = open(options.banner, O_RDONLY)) == -1)
		بازگشت (پوچ);
	اگر (fstat(fd, &st) == -1) {
		close(fd);
		بازگشت (پوچ);
	}
	اگر (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		بازگشت (پوچ);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(اقرأ, fd, banner, len);
	close(fd);

	اگر (n != len) {
		آزاد(banner);
		بازگشت (پوچ);
	}
	banner[n] = '\0';

	بازگشت (banner);
}

ایستا تهی
userauth_send_banner(ساختار ssh *ssh, ثابت نویسه *پیام)
{
	صحیح r;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, پیام)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ایستا تهی
userauth_banner(ساختار ssh *ssh)
{
	نویسه *banner = پوچ;

	اگر (options.banner == پوچ)
		بازگشت;

	اگر ((banner = mm_auth2_read_banner()) == پوچ)
		برو done;
	userauth_send_banner(ssh, banner);

done:
	آزاد(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
تهی
do_authentication2(ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	اگر (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, &kex_درون_داد_ext_info);
	ssh_dispatch_set(ssh, SSH2_پیام_SERVICE_REQUEST, &درون_داد_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = پوچ;
}

ایستا صحیح
درون_داد_service_request(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	نویسه *service = پوچ;
	صحیح r, acceptit = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &service, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;

	اگر (authctxt == پوچ)
		fatal("input_service_request: no authctxt");

	اگر (strcmp(service, "ssh-userauth") == 0) {
		اگر (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_REQUEST,
			    &درون_داد_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	اگر (acceptit) {
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			برو out;
	} وگرنه {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	آزاد(service);
	بازگشت r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
ایستا دوگانه
user_specific_delay(ثابت نویسه *user)
{
	نویسه b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	دوگانه delay;

	(تهی)snprintf(b, اندازه b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	اگر (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (دوگانه)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	بازگشت MIN_FAIL_DELAY_SECONDS + delay;
}

ایستا تهی
ensure_minimum_time_since(دوگانه start, دوگانه seconds)
{
	ساختار timespec ts;
	دوگانه elapsed = monotime_double() - start, req = seconds, remain;

	اگر (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		بازگشت;
	}

	/* if we've already passed the requested time, scale up */
	وقتی ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, پوچ);
}

تهی
auth_failure_delay(Authctxt *authctxt, دوگانه tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

ایستا صحیح
درون_داد_userauth_request(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = پوچ;
	نویسه *user = پوچ, *service = پوچ, *method = پوچ, *style = پوچ;
	صحیح r, authenticated = 0;
	دوگانه tstart = monotime_double();

	اگر (authctxt == پوچ)
		fatal("input_userauth_request: no authctxt");

	اگر ((r = sshpkt_get_cstring(ssh, &user, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, پوچ)) != 0)
		برو out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	اگر ((style = strchr(user, ':')) != پوچ)
		*style++ = 0;

	اگر (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	اگر (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : پوچ;
		اگر (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} وگرنه {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		اگر (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		اگر ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		اگر (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} وگرنه اگر (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, پوچ);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, پوچ);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	اگر (m != پوچ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	اگر (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, پوچ);
	r = 0;
 out:
	آزاد(service);
	آزاد(user);
	آزاد(method);
	بازگشت r;
}

تهی
userauth_finish(ساختار ssh *ssh, صحیح authenticated, ثابت نویسه *packet_method,
    ثابت نویسه *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = پوچ;
	ثابت نویسه *method = packet_method;
	نویسه *methods;
	صحیح r, partial = 0;

	اگر (authenticated) {
		اگر (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		اگر (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		اگر ((m = authmethod_byname(method)) == پوچ)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	اگر (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_ریشه_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ریشه_DENIED);
#endif
	}

	اگر (authenticated && options.رقم_auth_methods != 0) {
		اگر (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	اگر (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	اگر (authctxt->postponed)
		بازگشت;

#ifdef USE_PAM
	اگر (options.use_pam && authenticated) {
		صحیح r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		اگر (sshbuf_len(loginmsg) > 0) {
			اگر ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			اگر ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		اگر (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	اگر (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} وگرنه {
		/* Allow initial try of "none" auth without failure penalty */
		اگر (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		اگر (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		آزاد(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
صحیح
auth2_method_allowed(Authctxt *authctxt, ثابت نویسه *method,
    ثابت نویسه *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	اگر (options.رقم_auth_methods == 0)
		بازگشت 1;
	برای (i = 0; i < authctxt->رقم_auth_methods; i++) {
		اگر (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			بازگشت 1;
	}
	بازگشت 0;
}

ایستا نویسه *
authmethods_get(Authctxt *authctxt)
{
	ساختار sshbuf *b;
	نویسه *list;
	صحیح i, r;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	برای (i = 0; authmethods[i] != پوچ; i++) {
		اگر (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ادامه;
		اگر (authmethods[i]->cfg->enabled == پوچ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ادامه;
		اگر (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    پوچ))
			ادامه;
		اگر ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	اگر ((list = sshbuf_dup_string(b)) == پوچ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	بازگشت list;
}

ایستا Authmethod *
authmethod_byname(ثابت نویسه *name)
{
	صحیح i;

	اگر (name == پوچ)
		fatal_f("NULL authentication method name");
	برای (i = 0; authmethods[i] != پوچ; i++) {
		اگر (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != پوچ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			بازگشت authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	بازگشت پوچ;
}

ایستا Authmethod *
authmethod_lookup(Authctxt *authctxt, ثابت نویسه *name)
{
	Authmethod *method;

	اگر ((method = authmethod_byname(name)) == پوچ)
		بازگشت پوچ;

	اگر (method->cfg->enabled == پوچ || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		بازگشت پوچ;
	}
	اگر (!auth2_method_allowed(authctxt, method->cfg->name, پوچ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		بازگشت پوچ;
	}
	بازگشت method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
صحیح
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	اگر (options.رقم_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		آزاد(options.auth_methods[0]);
		options.auth_methods[0] = پوچ;
		options.رقم_auth_methods = 0;
	}

	اگر (options.رقم_auth_methods == 0)
		بازگشت 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.رقم_auth_methods,
	    اندازه(*authctxt->auth_methods));
	authctxt->رقم_auth_methods = 0;
	برای (i = 0; i < options.رقم_auth_methods; i++) {
		اگر (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ادامه;
		}
		debug("authentication methods list %d: %s",
		    authctxt->رقم_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->رقم_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	اگر (authctxt->رقم_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		بازگشت -1;
	}
	بازگشت 0;
}

ایستا صحیح
list_starts_with(ثابت نویسه *methods, ثابت نویسه *method,
    ثابت نویسه *submethod)
{
	size_t l = strlen(method);
	صحیح match;
	ثابت نویسه *p;

	اگر (strncmp(methods, method, l) != 0)
		بازگشت MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	اگر (*p == ':') {
		اگر (!submethod)
			بازگشت MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		اگر (strncmp(submethod, p, l))
			بازگشت MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	اگر (*p != ',' && *p != '\0')
		بازگشت MATCH_NONE;
	بازگشت match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ایستا صحیح
remove_method(نویسه **methods, ثابت نویسه *method, ثابت نویسه *submethod)
{
	نویسه *omethods = *methods, *p;
	size_t l = strlen(method);
	صحیح match;

	match = list_starts_with(omethods, method, submethod);
	اگر (match != MATCH_METHOD && match != MATCH_BOTH)
		بازگشت 0;
	p = omethods + l;
	اگر (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	اگر (*p == ',')
		p++;
	*methods = xstrdup(p);
	آزاد(omethods);
	بازگشت 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
صحیح
auth2_update_methods_lists(Authctxt *authctxt, ثابت نویسه *method,
    ثابت نویسه *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	برای (i = 0; i < authctxt->رقم_auth_methods; i++) {
		اگر (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			ادامه;
		found = 1;
		اگر (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			بازگشت 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	اگر (!found)
		fatal_f("method not in AuthenticationMethods");
	بازگشت 0;
}

/* Reset method-specific information */
تهی auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_کلید);
	آزاد(authctxt->auth_method_info);
	authctxt->auth_method_کلید = پوچ;
	authctxt->auth_method_info = پوچ;
}

/* Record auth method-specific information for logs */
تهی
auth2_record_info(Authctxt *authctxt, ثابت نویسه *fmt, ...)
{
	va_list ap;
	صحیح i;

	آزاد(authctxt->auth_method_info);
	authctxt->auth_method_info = پوچ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	اگر (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
تهی
auth2_record_کلید(Authctxt *authctxt, صحیح authenticated,
    ثابت ساختار sshkey *کلید)
{
	ساختار sshkey **tmp, *dup;
	صحیح r;

	اگر ((r = sshkey_from_private(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_کلید);
	authctxt->auth_method_کلید = dup;

	اگر (!authenticated)
		بازگشت;

	/* If authenticated, make sure we don't accept this key again */
	اگر ((r = sshkey_from_private(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	اگر (authctxt->nprev_کلیدها >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_کلیدها, authctxt->nprev_کلیدها,
	    authctxt->nprev_کلیدها + 1, اندازه(*authctxt->prev_کلیدها))) == پوچ)
		fatal_f("reallocarray failed");
	authctxt->prev_کلیدها = tmp;
	authctxt->prev_کلیدها[authctxt->nprev_کلیدها] = dup;
	authctxt->nprev_کلیدها++;

}

/* Checks whether a key has already been previously used for authentication */
صحیح
auth2_کلید_already_used(Authctxt *authctxt, ثابت ساختار sshkey *کلید)
{
	u_int i;
	نویسه *fp;

	برای (i = 0; i < authctxt->nprev_کلیدها; i++) {
		اگر (sshkey_equal_public(کلید, authctxt->prev_کلیدها[i])) {
			fp = sshkey_fingerprint(authctxt->prev_کلیدها[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_کلیدها[i]),
			    fp == پوچ ? "UNKNOWN" : fp);
			آزاد(fp);
			بازگشت 1;
		}
	}
	بازگشت 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
تهی
auth2_update_session_info(Authctxt *authctxt, ثابت نویسه *method,
    ثابت نویسه *submethod)
{
	صحیح r;

	اگر (authctxt->session_info == پوچ) {
		اگر ((authctxt->session_info = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	اگر ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == پوچ ? "" : "/",
	    submethod == پوچ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	اگر (authctxt->auth_method_کلید != پوچ) {
		اگر ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_کلید,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	اگر (authctxt->auth_method_info != پوچ) {
		/* Ensure no ambiguity here */
		اگر (strchr(authctxt->auth_method_info, '\n') != پوچ)
			fatal_f("auth_method_info contains \\n");
		اگر ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	اگر ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

