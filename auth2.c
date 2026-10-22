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

static 정수 input_service_request(정수, uint32_t, struct ssh *);
static 정수 input_userauth_request(정수, uint32_t, struct ssh *);

/* helper */
static Authmethod *authmethod_byname(const char *);
static Authmethod *authmethod_lookup(Authctxt *, const char *);
static char *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
static 정수 list_starts_with(const char *, const char *, const char *);

char *
auth2_read_banner(void)
{
	struct stat st;
	char *banner = NULL;
	size_t len, n;
	정수 fd;

	만약 ((fd = open(options.banner, O_RDONLY)) == -1)
		반환 (NULL);
	만약 (fstat(fd, &st) == -1) {
		close(fd);
		반환 (NULL);
	}
	만약 (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		반환 (NULL);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(read, fd, banner, len);
	close(fd);

	만약 (n != len) {
		free(banner);
		반환 (NULL);
	}
	banner[n] = '\0';

	반환 (banner);
}

static void
userauth_send_banner(struct ssh *ssh, const char *msg)
{
	정수 r;

	만약 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_BANNER)) != 0 ||
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

	만약 (options.banner == NULL)
		반환;

	만약 ((banner = mm_auth2_read_banner()) == NULL)
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
	만약 (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = NULL;
}

static 정수
input_service_request(정수 type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	char *service = NULL;
	정수 r, acceptit = 0;

	만약 ((r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	만약 (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	만약 (strcmp(service, "ssh-userauth") == 0) {
		만약 (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
			    &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	만약 (acceptit) {
		만약 ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			goto out;
	} 아니면 {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	free(service);
	반환 r;
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
	만약 (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (double)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	반환 MIN_FAIL_DELAY_SECONDS + delay;
}

static void
ensure_minimum_time_since(double start, double seconds)
{
	struct timespec ts;
	double elapsed = monotime_double() - start, req = seconds, remain;

	만약 (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		반환;
	}

	/* if we've already passed the requested time, scale up */
	동안 ((remain = seconds - elapsed) < 0.0)
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

static 정수
input_userauth_request(정수 type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	char *user = NULL, *service = NULL, *method = NULL, *style = NULL;
	정수 r, authenticated = 0;
	double tstart = monotime_double();

	만약 (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	만약 ((r = sshpkt_get_cstring(ssh, &user, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, NULL)) != 0)
		goto out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	만약 ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	만약 (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	만약 (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		만약 (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} 아니면 {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		만약 (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		만약 ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		만약 (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} 아니면 만약 (strcmp(user, authctxt->user) != 0 ||
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
	만약 (m != NULL && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	만약 (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, NULL);
	r = 0;
 out:
	free(service);
	free(user);
	free(method);
	반환 r;
}

void
userauth_finish(struct ssh *ssh, 정수 authenticated, const char *packet_method,
    const char *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	const char *method = packet_method;
	char *methods;
	정수 r, partial = 0;

	만약 (authenticated) {
		만약 (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		만약 (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		만약 ((m = authmethod_byname(method)) == NULL)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	만약 (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ROOT_DENIED);
#endif
	}

	만약 (authenticated && options.num_auth_methods != 0) {
		만약 (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	만약 (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	만약 (authctxt->postponed)
		반환;

#ifdef USE_PAM
	만약 (options.use_pam && authenticated) {
		정수 r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		만약 (sshbuf_len(loginmsg) > 0) {
			만약 ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			만약 ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		만약 (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	만약 (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		만약 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} 아니면 {
		/* Allow initial try of "none" auth without failure penalty */
		만약 (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		만약 (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		만약 ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
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
정수
auth2_method_allowed(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	만약 (options.num_auth_methods == 0)
		반환 1;
	위해 (i = 0; i < authctxt->num_auth_methods; i++) {
		만약 (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			반환 1;
	}
	반환 0;
}

static char *
authmethods_get(Authctxt *authctxt)
{
	struct sshbuf *b;
	char *list;
	정수 i, r;

	만약 ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	위해 (i = 0; authmethods[i] != NULL; i++) {
		만약 (strcmp(authmethods[i]->cfg->name, "none") == 0)
			continue;
		만약 (authmethods[i]->cfg->enabled == NULL ||
		    *(authmethods[i]->cfg->enabled) == 0)
			continue;
		만약 (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    NULL))
			continue;
		만약 ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	만약 ((list = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	반환 list;
}

static Authmethod *
authmethod_byname(const char *name)
{
	정수 i;

	만약 (name == NULL)
		fatal_f("NULL authentication method name");
	위해 (i = 0; authmethods[i] != NULL; i++) {
		만약 (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != NULL &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			반환 authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	반환 NULL;
}

static Authmethod *
authmethod_lookup(Authctxt *authctxt, const char *name)
{
	Authmethod *method;

	만약 ((method = authmethod_byname(name)) == NULL)
		반환 NULL;

	만약 (method->cfg->enabled == NULL || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		반환 NULL;
	}
	만약 (!auth2_method_allowed(authctxt, method->cfg->name, NULL)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		반환 NULL;
	}
	반환 method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
정수
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	만약 (options.num_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		free(options.auth_methods[0]);
		options.auth_methods[0] = NULL;
		options.num_auth_methods = 0;
	}

	만약 (options.num_auth_methods == 0)
		반환 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.num_auth_methods,
	    sizeof(*authctxt->auth_methods));
	authctxt->num_auth_methods = 0;
	위해 (i = 0; i < options.num_auth_methods; i++) {
		만약 (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
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
	만약 (authctxt->num_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		반환 -1;
	}
	반환 0;
}

static 정수
list_starts_with(const char *methods, const char *method,
    const char *submethod)
{
	size_t l = strlen(method);
	정수 match;
	const char *p;

	만약 (strncmp(methods, method, l) != 0)
		반환 MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	만약 (*p == ':') {
		만약 (!submethod)
			반환 MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		만약 (strncmp(submethod, p, l))
			반환 MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	만약 (*p != ',' && *p != '\0')
		반환 MATCH_NONE;
	반환 match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
static 정수
remove_method(char **methods, const char *method, const char *submethod)
{
	char *omethods = *methods, *p;
	size_t l = strlen(method);
	정수 match;

	match = list_starts_with(omethods, method, submethod);
	만약 (match != MATCH_METHOD && match != MATCH_BOTH)
		반환 0;
	p = omethods + l;
	만약 (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	만약 (*p == ',')
		p++;
	*methods = xstrdup(p);
	free(omethods);
	반환 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
정수
auth2_update_methods_lists(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	위해 (i = 0; i < authctxt->num_auth_methods; i++) {
		만약 (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			continue;
		found = 1;
		만약 (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			반환 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	만약 (!found)
		fatal_f("method not in AuthenticationMethods");
	반환 0;
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
	정수 i;

	free(authctxt->auth_method_info);
	authctxt->auth_method_info = NULL;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	만약 (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
void
auth2_record_key(Authctxt *authctxt, 정수 authenticated,
    const struct sshkey *key)
{
	struct sshkey **tmp, *dup;
	정수 r;

	만약 ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_key);
	authctxt->auth_method_key = dup;

	만약 (!authenticated)
		반환;

	/* If authenticated, make sure we don't accept this key again */
	만약 ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	만약 (authctxt->nprev_keys >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_keys, authctxt->nprev_keys,
	    authctxt->nprev_keys + 1, sizeof(*authctxt->prev_keys))) == NULL)
		fatal_f("reallocarray failed");
	authctxt->prev_keys = tmp;
	authctxt->prev_keys[authctxt->nprev_keys] = dup;
	authctxt->nprev_keys++;

}

/* Checks whether a key has already been previously used for authentication */
정수
auth2_key_already_used(Authctxt *authctxt, const struct sshkey *key)
{
	u_int i;
	char *fp;

	위해 (i = 0; i < authctxt->nprev_keys; i++) {
		만약 (sshkey_equal_public(key, authctxt->prev_keys[i])) {
			fp = sshkey_fingerprint(authctxt->prev_keys[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_keys[i]),
			    fp == NULL ? "UNKNOWN" : fp);
			free(fp);
			반환 1;
		}
	}
	반환 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
void
auth2_update_session_info(Authctxt *authctxt, const char *method,
    const char *submethod)
{
	정수 r;

	만약 (authctxt->session_info == NULL) {
		만약 ((authctxt->session_info = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	만약 ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == NULL ? "" : "/",
	    submethod == NULL ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	만약 (authctxt->auth_method_key != NULL) {
		만약 ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_key,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	만약 (authctxt->auth_method_info != NULL) {
		/* Ensure no ambiguity here */
		만약 (strchr(authctxt->auth_method_info, '\n') != NULL)
			fatal_f("auth_method_info contains \\n");
		만약 ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	만약 ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

