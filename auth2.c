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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/uio.h>

#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <time.h>

#ضمن "stdlib.h"
#ضمن "atomicio.h"
#ضمن "xmalloc.h"
#ضمن "ssh2.h"
#ضمن "packet.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "dispatch.h"
#ضمن "pathnames.h"
#ضمن "ssherr.h"
#ifdef GSSAPI
#ضمن "ssh-gss.h"
#endif
#ضمن "monitor_wrap.h"
#ضمن "digest.h"
#ضمن "kex.h"

/* import */
خارجي ServerOptions options;
خارجي بنية sshbuf *loginmsg;

/* methods */

خارجي Authmethod method_none;
خارجي Authmethod method_pubkey;
خارجي Authmethod method_passwd;
خارجي Authmethod method_kbdint;
خارجي Authmethod method_hostbased;
#ifdef GSSAPI
خارجي Authmethod method_gssapi;
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
	عدم
};

/* protocol */

ساكن صحيح input_service_request(صحيح, uint32_t, بنية ssh *);
ساكن صحيح input_userauth_request(صحيح, uint32_t, بنية ssh *);

/* helper */
ساكن Authmethod *authmethod_byname(ثابت حرف *);
ساكن Authmethod *authmethod_lookup(Authctxt *, ثابت حرف *);
ساكن حرف *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
ساكن صحيح list_starts_with(ثابت حرف *, ثابت حرف *, ثابت حرف *);

حرف *
auth2_read_banner(فراغ)
{
	بنية stat st;
	حرف *banner = عدم;
	size_t len, n;
	صحيح fd;

	אם ((fd = open(options.banner, O_RDONLY)) == -1)
		החזר (عدم);
	אם (fstat(fd, &st) == -1) {
		close(fd);
		החזר (عدم);
	}
	אם (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		החזר (عدم);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(اقرأ, fd, banner, len);
	close(fd);

	אם (n != len) {
		حرر(banner);
		החזר (عدم);
	}
	banner[n] = '\0';

	החזר (banner);
}

ساكن فراغ
userauth_send_banner(بنية ssh *ssh, ثابت حرف *msg)
{
	صحيح r;

	אם ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, msg)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ساكن فراغ
userauth_banner(بنية ssh *ssh)
{
	حرف *banner = عدم;

	אם (options.banner == عدم)
		החזר;

	אם ((banner = mm_auth2_read_banner()) == عدم)
		اذهب done;
	userauth_send_banner(ssh, banner);

done:
	حرر(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
فراغ
do_authentication2(بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	אם (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = عدم;
}

ساكن صحيح
input_service_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *service = عدم;
	صحيح r, acceptit = 0;

	אם ((r = sshpkt_get_cstring(ssh, &service, عدم)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		اذهب out;

	אם (authctxt == عدم)
		fatal("input_service_request: no authctxt");

	אם (strcmp(service, "ssh-userauth") == 0) {
		אם (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
			    &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	אם (acceptit) {
		אם ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			اذهب out;
	} אחרת {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	حرر(service);
	החזר r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
ساكن مزدوج
user_specific_delay(ثابت حرف *user)
{
	حرف b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	مزدوج delay;

	(فراغ)snprintf(b, حجم b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	אם (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (مزدوج)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	החזר MIN_FAIL_DELAY_SECONDS + delay;
}

ساكن فراغ
ensure_minimum_time_since(مزدوج start, مزدوج seconds)
{
	بنية timespec ts;
	مزدوج elapsed = monotime_double() - start, req = seconds, remain;

	אם (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		החזר;
	}

	/* if we've already passed the requested time, scale up */
	כלעוד ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, عدم);
}

فراغ
auth_failure_delay(Authctxt *authctxt, مزدوج tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

ساكن صحيح
input_userauth_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = عدم;
	حرف *user = عدم, *service = عدم, *method = عدم, *style = عدم;
	صحيح r, authenticated = 0;
	مزدوج tstart = monotime_double();

	אם (authctxt == عدم)
		fatal("input_userauth_request: no authctxt");

	אם ((r = sshpkt_get_cstring(ssh, &user, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, عدم)) != 0)
		اذهب out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	אם ((style = strchr(user, ':')) != عدم)
		*style++ = 0;

	אם (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	אם (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : عدم;
		אם (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} אחרת {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		אם (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		אם ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		אם (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} אחרת אם (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, عدم);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, عدم);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	אם (m != عدم && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	אם (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, عدم);
	r = 0;
 out:
	حرر(service);
	حرر(user);
	حرر(method);
	החזר r;
}

فراغ
userauth_finish(بنية ssh *ssh, صحيح authenticated, ثابت حرف *packet_method,
    ثابت حرف *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = عدم;
	ثابت حرف *method = packet_method;
	حرف *methods;
	صحيح r, partial = 0;

	אם (authenticated) {
		אם (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		אם (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		אם ((m = authmethod_byname(method)) == عدم)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	אם (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ROOT_DENIED);
#endif
	}

	אם (authenticated && options.num_auth_methods != 0) {
		אם (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	אם (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	אם (authctxt->postponed)
		החזר;

#ifdef USE_PAM
	אם (options.use_pam && authenticated) {
		صحيح r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		אם (sshbuf_len(loginmsg) > 0) {
			אם ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			אם ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		אם (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	אם (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		אם ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} אחרת {
		/* Allow initial try of "none" auth without failure penalty */
		אם (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		אם (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		אם ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		حرر(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
صحيح
auth2_method_allowed(Authctxt *authctxt, ثابت حرف *method,
    ثابت حرف *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	אם (options.num_auth_methods == 0)
		החזר 1;
	עבור (i = 0; i < authctxt->num_auth_methods; i++) {
		אם (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			החזר 1;
	}
	החזר 0;
}

ساكن حرف *
authmethods_get(Authctxt *authctxt)
{
	بنية sshbuf *b;
	حرف *list;
	صحيح i, r;

	אם ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	עבור (i = 0; authmethods[i] != عدم; i++) {
		אם (strcmp(authmethods[i]->cfg->name, "none") == 0)
			استمر;
		אם (authmethods[i]->cfg->enabled == عدم ||
		    *(authmethods[i]->cfg->enabled) == 0)
			استمر;
		אם (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    عدم))
			استمر;
		אם ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	אם ((list = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	החזר list;
}

ساكن Authmethod *
authmethod_byname(ثابت حرف *name)
{
	صحيح i;

	אם (name == عدم)
		fatal_f("NULL authentication method name");
	עבור (i = 0; authmethods[i] != عدم; i++) {
		אם (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != عدم &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			החזר authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	החזר عدم;
}

ساكن Authmethod *
authmethod_lookup(Authctxt *authctxt, ثابت حرف *name)
{
	Authmethod *method;

	אם ((method = authmethod_byname(name)) == عدم)
		החזר عدم;

	אם (method->cfg->enabled == عدم || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		החזר عدم;
	}
	אם (!auth2_method_allowed(authctxt, method->cfg->name, عدم)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		החזר عدم;
	}
	החזר method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
صحيح
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	אם (options.num_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		حرر(options.auth_methods[0]);
		options.auth_methods[0] = عدم;
		options.num_auth_methods = 0;
	}

	אם (options.num_auth_methods == 0)
		החזר 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.num_auth_methods,
	    حجم(*authctxt->auth_methods));
	authctxt->num_auth_methods = 0;
	עבור (i = 0; i < options.num_auth_methods; i++) {
		אם (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			استمر;
		}
		debug("authentication methods list %d: %s",
		    authctxt->num_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->num_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	אם (authctxt->num_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		החזר -1;
	}
	החזר 0;
}

ساكن صحيح
list_starts_with(ثابت حرف *methods, ثابت حرف *method,
    ثابت حرف *submethod)
{
	size_t l = strlen(method);
	صحيح match;
	ثابت حرف *p;

	אם (strncmp(methods, method, l) != 0)
		החזר MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	אם (*p == ':') {
		אם (!submethod)
			החזר MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		אם (strncmp(submethod, p, l))
			החזר MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	אם (*p != ',' && *p != '\0')
		החזר MATCH_NONE;
	החזר match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ساكن صحيح
remove_method(حرف **methods, ثابت حرف *method, ثابت حرف *submethod)
{
	حرف *omethods = *methods, *p;
	size_t l = strlen(method);
	صحيح match;

	match = list_starts_with(omethods, method, submethod);
	אם (match != MATCH_METHOD && match != MATCH_BOTH)
		החזר 0;
	p = omethods + l;
	אם (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	אם (*p == ',')
		p++;
	*methods = xstrdup(p);
	حرر(omethods);
	החזר 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
صحيح
auth2_update_methods_lists(Authctxt *authctxt, ثابت حرف *method,
    ثابت حرف *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	עבור (i = 0; i < authctxt->num_auth_methods; i++) {
		אם (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			استمر;
		found = 1;
		אם (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			החזר 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	אם (!found)
		fatal_f("method not in AuthenticationMethods");
	החזר 0;
}

/* Reset method-specific information */
فراغ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_key);
	حرر(authctxt->auth_method_info);
	authctxt->auth_method_key = عدم;
	authctxt->auth_method_info = عدم;
}

/* Record auth method-specific information for logs */
فراغ
auth2_record_info(Authctxt *authctxt, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح i;

	حرر(authctxt->auth_method_info);
	authctxt->auth_method_info = عدم;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	אם (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
فراغ
auth2_record_key(Authctxt *authctxt, صحيح authenticated,
    ثابت بنية sshkey *key)
{
	بنية sshkey **tmp, *dup;
	صحيح r;

	אם ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_key);
	authctxt->auth_method_key = dup;

	אם (!authenticated)
		החזר;

	/* If authenticated, make sure we don't accept this key again */
	אם ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	אם (authctxt->nprev_keys >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_keys, authctxt->nprev_keys,
	    authctxt->nprev_keys + 1, حجم(*authctxt->prev_keys))) == عدم)
		fatal_f("reallocarray failed");
	authctxt->prev_keys = tmp;
	authctxt->prev_keys[authctxt->nprev_keys] = dup;
	authctxt->nprev_keys++;

}

/* Checks whether a key has already been previously used for authentication */
صحيح
auth2_key_already_used(Authctxt *authctxt, ثابت بنية sshkey *key)
{
	u_int i;
	حرف *fp;

	עבור (i = 0; i < authctxt->nprev_keys; i++) {
		אם (sshkey_equal_public(key, authctxt->prev_keys[i])) {
			fp = sshkey_fingerprint(authctxt->prev_keys[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_keys[i]),
			    fp == عدم ? "UNKNOWN" : fp);
			حرر(fp);
			החזר 1;
		}
	}
	החזר 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
فراغ
auth2_update_session_info(Authctxt *authctxt, ثابت حرف *method,
    ثابت حرف *submethod)
{
	صحيح r;

	אם (authctxt->session_info == عدم) {
		אם ((authctxt->session_info = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	אם ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == عدم ? "" : "/",
	    submethod == عدم ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	אם (authctxt->auth_method_key != عدم) {
		אם ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_key,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	אם (authctxt->auth_method_info != عدم) {
		/* Ensure no ambiguity here */
		אם (strchr(authctxt->auth_method_info, '\n') != عدم)
			fatal_f("auth_method_info contains \\n");
		אם ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	אם ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

