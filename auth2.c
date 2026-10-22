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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "stdlib.h"
#include "atomicio.h"
#include "xmalloc.h"
#include "ssh2.h"
#include "packet.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "dispatch.h"
#include "pathnames.h"
#include "ssherr.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "digest.h"
#include "kex.h"

/* import */
extern ServerOptions options;
extern struct sshbuf *loginmsg;

/* methods */

extern Authmethod method_none;
extern Authmethod method_pubkey;
extern Authmethod method_passwd;
extern Authmethod method_kbdint;
extern Authmethod method_hostbased;
#ifdef GSSAPI
extern Authmethod method_gssapi;
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
	NULL
};

/* protocol */

static 整数 input_service_request(整数, uint32_t, struct ssh *);
static 整数 input_userauth_request(整数, uint32_t, struct ssh *);

/* helper */
static Authmethod *authmethod_byname(const char *);
static Authmethod *authmethod_lookup(Authctxt *, const char *);
static char *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
static 整数 list_starts_with(const char *, const char *, const char *);

char *
auth2_read_banner(void)
{
	struct stat st;
	char *banner = NULL;
	size_t len, n;
	整数 fd;

	如果 ((fd = open(options.banner, O_RDONLY)) == -1)
		返回 (NULL);
	如果 (fstat(fd, &st) == -1) {
		close(fd);
		返回 (NULL);
	}
	如果 (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		返回 (NULL);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(read, fd, banner, len);
	close(fd);

	如果 (n != len) {
		free(banner);
		返回 (NULL);
	}
	banner[n] = '\0';

	返回 (banner);
}

static void
userauth_send_banner(struct ssh *ssh, const char *msg)
{
	整数 r;

	如果 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, msg)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

static void
userauth_banner(struct ssh *ssh)
{
	char *banner = NULL;

	如果 (options.banner == NULL)
		返回;

	如果 ((banner = mm_auth2_read_banner()) == NULL)
		goto done;
	userauth_send_banner(ssh, banner);

done:
	free(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
void
do_authentication2(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	如果 (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = NULL;
}

static 整数
input_service_request(整数 type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	char *service = NULL;
	整数 r, acceptit = 0;

	如果 ((r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	如果 (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	如果 (strcmp(service, "ssh-userauth") == 0) {
		如果 (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
			    &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	如果 (acceptit) {
		如果 ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			goto out;
	} 否则 {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	free(service);
	返回 r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
static double
user_specific_delay(const char *user)
{
	char b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	double delay;

	(void)snprintf(b, sizeof b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	如果 (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (double)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	返回 MIN_FAIL_DELAY_SECONDS + delay;
}

static void
ensure_minimum_time_since(double start, double seconds)
{
	struct timespec ts;
	double elapsed = monotime_double() - start, req = seconds, remain;

	如果 (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		返回;
	}

	/* if we've already passed the requested time, scale up */
	当 ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, NULL);
}

void
auth_failure_delay(Authctxt *authctxt, double tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

static 整数
input_userauth_request(整数 type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	char *user = NULL, *service = NULL, *method = NULL, *style = NULL;
	整数 r, authenticated = 0;
	double tstart = monotime_double();

	如果 (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	如果 ((r = sshpkt_get_cstring(ssh, &user, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, NULL)) != 0)
		goto out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	如果 ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	如果 (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	如果 (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		如果 (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} 否则 {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		如果 (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		如果 ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		如果 (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} 否则 如果 (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	如果 (m != NULL && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	如果 (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, NULL);
	r = 0;
 out:
	free(service);
	free(user);
	free(method);
	返回 r;
}

void
userauth_finish(struct ssh *ssh, 整数 authenticated, const char *packet_method,
    const char *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	const char *method = packet_method;
	char *methods;
	整数 r, partial = 0;

	如果 (authenticated) {
		如果 (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		如果 (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		如果 ((m = authmethod_byname(method)) == NULL)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	如果 (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ROOT_DENIED);
#endif
	}

	如果 (authenticated && options.num_auth_methods != 0) {
		如果 (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	如果 (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	如果 (authctxt->postponed)
		返回;

#ifdef USE_PAM
	如果 (options.use_pam && authenticated) {
		整数 r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		如果 (sshbuf_len(loginmsg) > 0) {
			如果 ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			如果 ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		如果 (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	如果 (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		如果 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} 否则 {
		/* Allow initial try of "none" auth without failure penalty */
		如果 (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		如果 (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		如果 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		free(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
整数
auth2_method_allowed(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	如果 (options.num_auth_methods == 0)
		返回 1;
	为 (i = 0; i < authctxt->num_auth_methods; i++) {
		如果 (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			返回 1;
	}
	返回 0;
}

static char *
authmethods_get(Authctxt *authctxt)
{
	struct sshbuf *b;
	char *list;
	整数 i, r;

	如果 ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	为 (i = 0; authmethods[i] != NULL; i++) {
		如果 (strcmp(authmethods[i]->cfg->name, "none") == 0)
			continue;
		如果 (authmethods[i]->cfg->enabled == NULL ||
		    *(authmethods[i]->cfg->enabled) == 0)
			continue;
		如果 (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    NULL))
			continue;
		如果 ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	如果 ((list = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	返回 list;
}

static Authmethod *
authmethod_byname(const char *name)
{
	整数 i;

	如果 (name == NULL)
		fatal_f("NULL authentication method name");
	为 (i = 0; authmethods[i] != NULL; i++) {
		如果 (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != NULL &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			返回 authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	返回 NULL;
}

static Authmethod *
authmethod_lookup(Authctxt *authctxt, const char *name)
{
	Authmethod *method;

	如果 ((method = authmethod_byname(name)) == NULL)
		返回 NULL;

	如果 (method->cfg->enabled == NULL || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		返回 NULL;
	}
	如果 (!auth2_method_allowed(authctxt, method->cfg->name, NULL)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		返回 NULL;
	}
	返回 method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
整数
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	如果 (options.num_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		free(options.auth_methods[0]);
		options.auth_methods[0] = NULL;
		options.num_auth_methods = 0;
	}

	如果 (options.num_auth_methods == 0)
		返回 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.num_auth_methods,
	    sizeof(*authctxt->auth_methods));
	authctxt->num_auth_methods = 0;
	为 (i = 0; i < options.num_auth_methods; i++) {
		如果 (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			continue;
		}
		debug("authentication methods list %d: %s",
		    authctxt->num_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->num_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	如果 (authctxt->num_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		返回 -1;
	}
	返回 0;
}

static 整数
list_starts_with(const char *methods, const char *method,
    const char *submethod)
{
	size_t l = strlen(method);
	整数 match;
	const char *p;

	如果 (strncmp(methods, method, l) != 0)
		返回 MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	如果 (*p == ':') {
		如果 (!submethod)
			返回 MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		如果 (strncmp(submethod, p, l))
			返回 MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	如果 (*p != ',' && *p != '\0')
		返回 MATCH_NONE;
	返回 match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
static 整数
remove_method(char **methods, const char *method, const char *submethod)
{
	char *omethods = *methods, *p;
	size_t l = strlen(method);
	整数 match;

	match = list_starts_with(omethods, method, submethod);
	如果 (match != MATCH_METHOD && match != MATCH_BOTH)
		返回 0;
	p = omethods + l;
	如果 (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	如果 (*p == ',')
		p++;
	*methods = xstrdup(p);
	free(omethods);
	返回 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
整数
auth2_update_methods_lists(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	为 (i = 0; i < authctxt->num_auth_methods; i++) {
		如果 (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			continue;
		found = 1;
		如果 (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			返回 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	如果 (!found)
		fatal_f("method not in AuthenticationMethods");
	返回 0;
}

/* Reset method-specific information */
void auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_key);
	free(authctxt->auth_method_info);
	authctxt->auth_method_key = NULL;
	authctxt->auth_method_info = NULL;
}

/* Record auth method-specific information for logs */
void
auth2_record_info(Authctxt *authctxt, const char *fmt, ...)
{
	va_list ap;
	整数 i;

	free(authctxt->auth_method_info);
	authctxt->auth_method_info = NULL;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	如果 (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
void
auth2_record_key(Authctxt *authctxt, 整数 authenticated,
    const struct sshkey *key)
{
	struct sshkey **tmp, *dup;
	整数 r;

	如果 ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_key);
	authctxt->auth_method_key = dup;

	如果 (!authenticated)
		返回;

	/* If authenticated, make sure we don't accept this key again */
	如果 ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	如果 (authctxt->nprev_keys >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_keys, authctxt->nprev_keys,
	    authctxt->nprev_keys + 1, sizeof(*authctxt->prev_keys))) == NULL)
		fatal_f("reallocarray failed");
	authctxt->prev_keys = tmp;
	authctxt->prev_keys[authctxt->nprev_keys] = dup;
	authctxt->nprev_keys++;

}

/* Checks whether a key has already been previously used for authentication */
整数
auth2_key_already_used(Authctxt *authctxt, const struct sshkey *key)
{
	u_int i;
	char *fp;

	为 (i = 0; i < authctxt->nprev_keys; i++) {
		如果 (sshkey_equal_public(key, authctxt->prev_keys[i])) {
			fp = sshkey_fingerprint(authctxt->prev_keys[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_keys[i]),
			    fp == NULL ? "UNKNOWN" : fp);
			free(fp);
			返回 1;
		}
	}
	返回 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
void
auth2_update_session_info(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	整数 r;

	如果 (authctxt->session_info == NULL) {
		如果 ((authctxt->session_info = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	如果 ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == NULL ? "" : "/",
	    submethod == NULL ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	如果 (authctxt->auth_method_key != NULL) {
		如果 ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_key,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	如果 (authctxt->auth_method_info != NULL) {
		/* Ensure no ambiguity here */
		如果 (strchr(authctxt->auth_method_info, '\n') != NULL)
			fatal_f("auth_method_info contains \\n");
		如果 ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	如果 ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

