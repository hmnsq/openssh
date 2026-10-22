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
extern sa_nracanaa sshbuf *loginmsg;

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

static ကိန်းပြည့် input_service_request(ကိန်းပြည့်, uint32_t, sa_nracanaa ssh *);
static ကိန်းပြည့် input_userauth_request(ကိန်းပြည့်, uint32_t, sa_nracanaa ssh *);

/* helper */
static Authmethod *authmethod_byname(const var_na *);
static Authmethod *authmethod_lookup(Authctxt *, const var_na *);
static var_na *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
static ကိန်းပြည့် list_starts_with(const var_na *, const var_na *, const var_na *);

var_na *
auth2_read_banner(void)
{
	sa_nracanaa stat st;
	var_na *banner = NULL;
	size_t len, n;
	ကိန်းပြည့် fd;

	အကယ်၍ ((fd = open(options.banner, O_RDONLY)) == -1)
		ပြန်ပေး (NULL);
	အကယ်၍ (fstat(fd, &st) == -1) {
		close(fd);
		ပြန်ပေး (NULL);
	}
	အကယ်၍ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ပြန်ပေး (NULL);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(read, fd, banner, len);
	close(fd);

	အကယ်၍ (n != len) {
		free(banner);
		ပြန်ပေး (NULL);
	}
	banner[n] = '\0';

	ပြန်ပေး (banner);
}

static void
userauth_send_banner(sa_nracanaa ssh *ssh, const var_na *msg)
{
	ကိန်းပြည့် r;

	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, msg)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

static void
userauth_banner(sa_nracanaa ssh *ssh)
{
	var_na *banner = NULL;

	အကယ်၍ (options.banner == NULL)
		ပြန်ပေး;

	အကယ်၍ ((banner = mm_auth2_read_banner()) == NULL)
		goto done;
	userauth_send_banner(ssh, banner);

done:
	free(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
void
do_authentication2(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	အကယ်၍ (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = NULL;
}

static ကိန်းပြည့်
input_service_request(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	var_na *service = NULL;
	ကိန်းပြည့် r, acceptit = 0;

	အကယ်၍ ((r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	အကယ်၍ (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	အကယ်၍ (strcmp(service, "ssh-userauth") == 0) {
		အကယ်၍ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
			    &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	အကယ်၍ (acceptit) {
		အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			goto out;
	} မဟုတ်ပါက {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	free(service);
	ပြန်ပေး r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
static dviguu_na
user_specific_delay(const var_na *user)
{
	var_na b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	dviguu_na delay;

	(void)snprintf(b, parimaa_na b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	အကယ်၍ (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (dviguu_na)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ပြန်ပေး MIN_FAIL_DELAY_SECONDS + delay;
}

static void
ensure_minimum_time_since(dviguu_na start, dviguu_na seconds)
{
	sa_nracanaa timespec ts;
	dviguu_na elapsed = monotime_double() - start, req = seconds, remain;

	အကယ်၍ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ပြန်ပေး;
	}

	/* if we've already passed the requested time, scale up */
	နေစဉ် ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, NULL);
}

void
auth_failure_delay(Authctxt *authctxt, dviguu_na tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

static ကိန်းပြည့်
input_userauth_request(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	var_na *user = NULL, *service = NULL, *method = NULL, *style = NULL;
	ကိန်းပြည့် r, authenticated = 0;
	dviguu_na tstart = monotime_double();

	အကယ်၍ (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	အကယ်၍ ((r = sshpkt_get_cstring(ssh, &user, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, NULL)) != 0)
		goto out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	အကယ်၍ ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	အကယ်၍ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	အကယ်၍ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		အကယ်၍ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} မဟုတ်ပါက {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		အကယ်၍ (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		အကယ်၍ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		အကယ်၍ (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} မဟုတ်ပါက အကယ်၍ (strcmp(user, authctxt->user) != 0 ||
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
	အကယ်၍ (m != NULL && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	အကယ်၍ (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, NULL);
	r = 0;
 out:
	free(service);
	free(user);
	free(method);
	ပြန်ပေး r;
}

void
userauth_finish(sa_nracanaa ssh *ssh, ကိန်းပြည့် authenticated, const var_na *packet_method,
    const var_na *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = NULL;
	const var_na *method = packet_method;
	var_na *methods;
	ကိန်းပြည့် r, partial = 0;

	အကယ်၍ (authenticated) {
		အကယ်၍ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		အကယ်၍ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		အကယ်၍ ((m = authmethod_byname(method)) == NULL)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	အကယ်၍ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ROOT_DENIED);
#endif
	}

	အကယ်၍ (authenticated && options.num_auth_methods != 0) {
		အကယ်၍ (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	အကယ်၍ (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	အကယ်၍ (authctxt->postponed)
		ပြန်ပေး;

#ifdef USE_PAM
	အကယ်၍ (options.use_pam && authenticated) {
		ကိန်းပြည့် r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		အကယ်၍ (sshbuf_len(loginmsg) > 0) {
			အကယ်၍ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			အကယ်၍ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		အကယ်၍ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	အကယ်၍ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} မဟုတ်ပါက {
		/* Allow initial try of "none" auth without failure penalty */
		အကယ်၍ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		အကယ်၍ (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
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
ကိန်းပြည့်
auth2_method_allowed(Authctxt *authctxt, const var_na *method,
    const var_na *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	အကယ်၍ (options.num_auth_methods == 0)
		ပြန်ပေး 1;
	အတွက် (i = 0; i < authctxt->num_auth_methods; i++) {
		အကယ်၍ (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			ပြန်ပေး 1;
	}
	ပြန်ပေး 0;
}

static var_na *
authmethods_get(Authctxt *authctxt)
{
	sa_nracanaa sshbuf *b;
	var_na *list;
	ကိန်းပြည့် i, r;

	အကယ်၍ ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	အတွက် (i = 0; authmethods[i] != NULL; i++) {
		အကယ်၍ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			continue;
		အကယ်၍ (authmethods[i]->cfg->enabled == NULL ||
		    *(authmethods[i]->cfg->enabled) == 0)
			continue;
		အကယ်၍ (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    NULL))
			continue;
		အကယ်၍ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	အကယ်၍ ((list = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ပြန်ပေး list;
}

static Authmethod *
authmethod_byname(const var_na *name)
{
	ကိန်းပြည့် i;

	အကယ်၍ (name == NULL)
		fatal_f("NULL authentication method name");
	အတွက် (i = 0; authmethods[i] != NULL; i++) {
		အကယ်၍ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != NULL &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ပြန်ပေး authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ပြန်ပေး NULL;
}

static Authmethod *
authmethod_lookup(Authctxt *authctxt, const var_na *name)
{
	Authmethod *method;

	အကယ်၍ ((method = authmethod_byname(name)) == NULL)
		ပြန်ပေး NULL;

	အကယ်၍ (method->cfg->enabled == NULL || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ပြန်ပေး NULL;
	}
	အကယ်၍ (!auth2_method_allowed(authctxt, method->cfg->name, NULL)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ပြန်ပေး NULL;
	}
	ပြန်ပေး method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
ကိန်းပြည့်
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	အကယ်၍ (options.num_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		free(options.auth_methods[0]);
		options.auth_methods[0] = NULL;
		options.num_auth_methods = 0;
	}

	အကယ်၍ (options.num_auth_methods == 0)
		ပြန်ပေး 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.num_auth_methods,
	    parimaa_na(*authctxt->auth_methods));
	authctxt->num_auth_methods = 0;
	အတွက် (i = 0; i < options.num_auth_methods; i++) {
		အကယ်၍ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
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
	အကယ်၍ (authctxt->num_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ပြန်ပေး -1;
	}
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
list_starts_with(const var_na *methods, const var_na *method,
    const var_na *submethod)
{
	size_t l = strlen(method);
	ကိန်းပြည့် match;
	const var_na *p;

	အကယ်၍ (strncmp(methods, method, l) != 0)
		ပြန်ပေး MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	အကယ်၍ (*p == ':') {
		အကယ်၍ (!submethod)
			ပြန်ပေး MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		အကယ်၍ (strncmp(submethod, p, l))
			ပြန်ပေး MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	အကယ်၍ (*p != ',' && *p != '\0')
		ပြန်ပေး MATCH_NONE;
	ပြန်ပေး match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
static ကိန်းပြည့်
remove_method(var_na **methods, const var_na *method, const var_na *submethod)
{
	var_na *omethods = *methods, *p;
	size_t l = strlen(method);
	ကိန်းပြည့် match;

	match = list_starts_with(omethods, method, submethod);
	အကယ်၍ (match != MATCH_METHOD && match != MATCH_BOTH)
		ပြန်ပေး 0;
	p = omethods + l;
	အကယ်၍ (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	အကယ်၍ (*p == ',')
		p++;
	*methods = xstrdup(p);
	free(omethods);
	ပြန်ပေး 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
ကိန်းပြည့်
auth2_update_methods_lists(Authctxt *authctxt, const var_na *method,
    const var_na *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	အတွက် (i = 0; i < authctxt->num_auth_methods; i++) {
		အကယ်၍ (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			continue;
		found = 1;
		အကယ်၍ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ပြန်ပေး 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	အကယ်၍ (!found)
		fatal_f("method not in AuthenticationMethods");
	ပြန်ပေး 0;
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
auth2_record_info(Authctxt *authctxt, const var_na *fmt, ...)
{
	va_list ap;
	ကိန်းပြည့် i;

	free(authctxt->auth_method_info);
	authctxt->auth_method_info = NULL;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	အကယ်၍ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
void
auth2_record_key(Authctxt *authctxt, ကိန်းပြည့် authenticated,
    const sa_nracanaa sshkey *key)
{
	sa_nracanaa sshkey **tmp, *dup;
	ကိန်းပြည့် r;

	အကယ်၍ ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_key);
	authctxt->auth_method_key = dup;

	အကယ်၍ (!authenticated)
		ပြန်ပေး;

	/* If authenticated, make sure we don't accept this key again */
	အကယ်၍ ((r = sshkey_from_private(key, &dup)) != 0)
		fatal_fr(r, "copy key");
	အကယ်၍ (authctxt->nprev_keys >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_keys, authctxt->nprev_keys,
	    authctxt->nprev_keys + 1, parimaa_na(*authctxt->prev_keys))) == NULL)
		fatal_f("reallocarray failed");
	authctxt->prev_keys = tmp;
	authctxt->prev_keys[authctxt->nprev_keys] = dup;
	authctxt->nprev_keys++;

}

/* Checks whether a key has already been previously used for authentication */
ကိန်းပြည့်
auth2_key_already_used(Authctxt *authctxt, const sa_nracanaa sshkey *key)
{
	u_int i;
	var_na *fp;

	အတွက် (i = 0; i < authctxt->nprev_keys; i++) {
		အကယ်၍ (sshkey_equal_public(key, authctxt->prev_keys[i])) {
			fp = sshkey_fingerprint(authctxt->prev_keys[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_keys[i]),
			    fp == NULL ? "UNKNOWN" : fp);
			free(fp);
			ပြန်ပေး 1;
		}
	}
	ပြန်ပေး 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
void
auth2_update_session_info(Authctxt *authctxt, const var_na *method,
    const var_na *submethod)
{
	ကိန်းပြည့် r;

	အကယ်၍ (authctxt->session_info == NULL) {
		အကယ်၍ ((authctxt->session_info = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	အကယ်၍ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == NULL ? "" : "/",
	    submethod == NULL ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	အကယ်၍ (authctxt->auth_method_key != NULL) {
		အကယ်၍ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_key,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	အကယ်၍ (authctxt->auth_method_info != NULL) {
		/* Ensure no ambiguity here */
		အကယ်၍ (strchr(authctxt->auth_method_info, '\n') != NULL)
			fatal_f("auth_method_info contains \\n");
		အကယ်၍ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	အကယ်၍ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

