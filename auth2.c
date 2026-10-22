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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "stdlib.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssherr.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "kex.h"

/* import */
બાહ્ય ServerOptions options;
બાહ્ય સંરચના sshbuf *loginmsg;

/* methods */

બાહ્ય Authmethod method_none;
બાહ્ય Authmethod method_pubkey;
બાહ્ય Authmethod method_passwd;
બાહ્ય Authmethod method_kbdint;
બાહ્ય Authmethod method_hostbased;
#ifdef GSSAPI
બાહ્ય Authmethod method_gssapi;
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
	ખાલી
};

/* protocol */

સ્થિર પૂર્ણાંક આગત_service_request(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_request(પૂર્ણાંક, uint32_t, સંરચના ssh *);

/* helper */
સ્થિર Authmethod *authmethod_byname(અચલ અક્ષર *);
સ્થિર Authmethod *authmethod_lookup(Authctxt *, અચલ અક્ષર *);
સ્થિર અક્ષર *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
સ્થિર પૂર્ણાંક list_starts_with(અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);

અક્ષર *
auth2_read_banner(શૂન્ય)
{
	સંરચના stat st;
	અક્ષર *banner = ખાલી;
	size_t len, n;
	પૂર્ણાંક fd;

	જો ((fd = open(options.banner, O_RDONLY)) == -1)
		પાછા (ખાલી);
	જો (fstat(fd, &st) == -1) {
		close(fd);
		પાછા (ખાલી);
	}
	જો (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		પાછા (ખાલી);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(પઠ, fd, banner, len);
	close(fd);

	જો (n != len) {
		મુક્ત(banner);
		પાછા (ખાલી);
	}
	banner[n] = '\0';

	પાછા (banner);
}

સ્થિર શૂન્ય
userauth_send_banner(સંરચના ssh *ssh, અચલ અક્ષર *સંદેશ)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, સંદેશ)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

સ્થિર શૂન્ય
userauth_banner(સંરચના ssh *ssh)
{
	અક્ષર *banner = ખાલી;

	જો (options.banner == ખાલી)
		પાછા;

	જો ((banner = mm_auth2_read_banner()) == ખાલી)
		જાઓ done;
	userauth_send_banner(ssh, banner);

done:
	મુક્ત(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
શૂન્ય
do_authentication2(સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	જો (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, &kex_આગત_ext_info);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_SERVICE_REQUEST, &આગત_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = ખાલી;
}

સ્થિર પૂર્ણાંક
આગત_service_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	અક્ષર *service = ખાલી;
	પૂર્ણાંક r, acceptit = 0;

	જો ((r = sshpkt_get_cstring(ssh, &service, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;

	જો (authctxt == ખાલી)
		fatal("input_service_request: no authctxt");

	જો (strcmp(service, "ssh-userauth") == 0) {
		જો (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_REQUEST,
			    &આગત_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	જો (acceptit) {
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			જાઓ out;
	} નહીંતર {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	મુક્ત(service);
	પાછા r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
સ્થિર દ્વિગુણ
user_specific_delay(અચલ અક્ષર *user)
{
	અક્ષર b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	દ્વિગુણ delay;

	(શૂન્ય)snprintf(b, કદ b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	જો (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (દ્વિગુણ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	પાછા MIN_FAIL_DELAY_SECONDS + delay;
}

સ્થિર શૂન્ય
ensure_minimum_time_since(દ્વિગુણ start, દ્વિગુણ seconds)
{
	સંરચના timespec ts;
	દ્વિગુણ elapsed = monotime_double() - start, req = seconds, remain;

	જો (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		પાછા;
	}

	/* if we've already passed the requested time, scale up */
	જ્યારે ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ખાલી);
}

શૂન્ય
auth_failure_delay(Authctxt *authctxt, દ્વિગુણ tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

સ્થિર પૂર્ણાંક
આગત_userauth_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ખાલી;
	અક્ષર *user = ખાલી, *service = ખાલી, *method = ખાલી, *style = ખાલી;
	પૂર્ણાંક r, authenticated = 0;
	દ્વિગુણ tstart = monotime_double();

	જો (authctxt == ખાલી)
		fatal("input_userauth_request: no authctxt");

	જો ((r = sshpkt_get_cstring(ssh, &user, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, ખાલી)) != 0)
		જાઓ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	જો ((style = strchr(user, ':')) != ખાલી)
		*style++ = 0;

	જો (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	જો (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ખાલી;
		જો (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} નહીંતર {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		જો (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		જો ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		જો (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} નહીંતર જો (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ખાલી);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	જો (m != ખાલી && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	જો (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, ખાલી);
	r = 0;
 out:
	મુક્ત(service);
	મુક્ત(user);
	મુક્ત(method);
	પાછા r;
}

શૂન્ય
userauth_finish(સંરચના ssh *ssh, પૂર્ણાંક authenticated, અચલ અક્ષર *packet_method,
    અચલ અક્ષર *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ખાલી;
	અચલ અક્ષર *method = packet_method;
	અક્ષર *methods;
	પૂર્ણાંક r, partial = 0;

	જો (authenticated) {
		જો (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		જો (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		જો ((m = authmethod_byname(method)) == ખાલી)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	જો (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_મૂળ_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_મૂળ_DENIED);
#endif
	}

	જો (authenticated && options.અંક_auth_methods != 0) {
		જો (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	જો (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	જો (authctxt->postponed)
		પાછા;

#ifdef USE_PAM
	જો (options.use_pam && authenticated) {
		પૂર્ણાંક r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		જો (sshbuf_len(loginmsg) > 0) {
			જો ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			જો ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		જો (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	જો (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} નહીંતર {
		/* Allow initial try of "none" auth without failure penalty */
		જો (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		જો (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		મુક્ત(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
પૂર્ણાંક
auth2_method_allowed(Authctxt *authctxt, અચલ અક્ષર *method,
    અચલ અક્ષર *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	જો (options.અંક_auth_methods == 0)
		પાછા 1;
	માટે (i = 0; i < authctxt->અંક_auth_methods; i++) {
		જો (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			પાછા 1;
	}
	પાછા 0;
}

સ્થિર અક્ષર *
authmethods_get(Authctxt *authctxt)
{
	સંરચના sshbuf *b;
	અક્ષર *list;
	પૂર્ણાંક i, r;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	માટે (i = 0; authmethods[i] != ખાલી; i++) {
		જો (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ચાલુ;
		જો (authmethods[i]->cfg->enabled == ખાલી ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ચાલુ;
		જો (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    ખાલી))
			ચાલુ;
		જો ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	જો ((list = sshbuf_dup_string(b)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	પાછા list;
}

સ્થિર Authmethod *
authmethod_byname(અચલ અક્ષર *name)
{
	પૂર્ણાંક i;

	જો (name == ખાલી)
		fatal_f("NULL authentication method name");
	માટે (i = 0; authmethods[i] != ખાલી; i++) {
		જો (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ખાલી &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			પાછા authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	પાછા ખાલી;
}

સ્થિર Authmethod *
authmethod_lookup(Authctxt *authctxt, અચલ અક્ષર *name)
{
	Authmethod *method;

	જો ((method = authmethod_byname(name)) == ખાલી)
		પાછા ખાલી;

	જો (method->cfg->enabled == ખાલી || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		પાછા ખાલી;
	}
	જો (!auth2_method_allowed(authctxt, method->cfg->name, ખાલી)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		પાછા ખાલી;
	}
	પાછા method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
પૂર્ણાંક
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	જો (options.અંક_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		મુક્ત(options.auth_methods[0]);
		options.auth_methods[0] = ખાલી;
		options.અંક_auth_methods = 0;
	}

	જો (options.અંક_auth_methods == 0)
		પાછા 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.અંક_auth_methods,
	    કદ(*authctxt->auth_methods));
	authctxt->અંક_auth_methods = 0;
	માટે (i = 0; i < options.અંક_auth_methods; i++) {
		જો (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ચાલુ;
		}
		debug("authentication methods list %d: %s",
		    authctxt->અંક_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->અંક_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	જો (authctxt->અંક_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		પાછા -1;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
list_starts_with(અચલ અક્ષર *methods, અચલ અક્ષર *method,
    અચલ અક્ષર *submethod)
{
	size_t l = strlen(method);
	પૂર્ણાંક match;
	અચલ અક્ષર *p;

	જો (strncmp(methods, method, l) != 0)
		પાછા MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	જો (*p == ':') {
		જો (!submethod)
			પાછા MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		જો (strncmp(submethod, p, l))
			પાછા MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	જો (*p != ',' && *p != '\0')
		પાછા MATCH_NONE;
	પાછા match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
સ્થિર પૂર્ણાંક
remove_method(અક્ષર **methods, અચલ અક્ષર *method, અચલ અક્ષર *submethod)
{
	અક્ષર *omethods = *methods, *p;
	size_t l = strlen(method);
	પૂર્ણાંક match;

	match = list_starts_with(omethods, method, submethod);
	જો (match != MATCH_METHOD && match != MATCH_BOTH)
		પાછા 0;
	p = omethods + l;
	જો (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	જો (*p == ',')
		p++;
	*methods = xstrdup(p);
	મુક્ત(omethods);
	પાછા 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
પૂર્ણાંક
auth2_update_methods_lists(Authctxt *authctxt, અચલ અક્ષર *method,
    અચલ અક્ષર *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	માટે (i = 0; i < authctxt->અંક_auth_methods; i++) {
		જો (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			ચાલુ;
		found = 1;
		જો (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			પાછા 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	જો (!found)
		fatal_f("method not in AuthenticationMethods");
	પાછા 0;
}

/* Reset method-specific information */
શૂન્ય auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_ચાવી);
	મુક્ત(authctxt->auth_method_info);
	authctxt->auth_method_ચાવી = ખાલી;
	authctxt->auth_method_info = ખાલી;
}

/* Record auth method-specific information for logs */
શૂન્ય
auth2_record_info(Authctxt *authctxt, અચલ અક્ષર *fmt, ...)
{
	va_list ap;
	પૂર્ણાંક i;

	મુક્ત(authctxt->auth_method_info);
	authctxt->auth_method_info = ખાલી;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	જો (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
શૂન્ય
auth2_record_ચાવી(Authctxt *authctxt, પૂર્ણાંક authenticated,
    અચલ સંરચના sshkey *ચાવી)
{
	સંરચના sshkey **tmp, *dup;
	પૂર્ણાંક r;

	જો ((r = sshkey_from_private(ચાવી, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_ચાવી);
	authctxt->auth_method_ચાવી = dup;

	જો (!authenticated)
		પાછા;

	/* If authenticated, make sure we don't accept this key again */
	જો ((r = sshkey_from_private(ચાવી, &dup)) != 0)
		fatal_fr(r, "copy key");
	જો (authctxt->nprev_ચાવીઓ >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_ચાવીઓ, authctxt->nprev_ચાવીઓ,
	    authctxt->nprev_ચાવીઓ + 1, કદ(*authctxt->prev_ચાવીઓ))) == ખાલી)
		fatal_f("reallocarray failed");
	authctxt->prev_ચાવીઓ = tmp;
	authctxt->prev_ચાવીઓ[authctxt->nprev_ચાવીઓ] = dup;
	authctxt->nprev_ચાવીઓ++;

}

/* Checks whether a key has already been previously used for authentication */
પૂર્ણાંક
auth2_ચાવી_already_used(Authctxt *authctxt, અચલ સંરચના sshkey *ચાવી)
{
	u_int i;
	અક્ષર *fp;

	માટે (i = 0; i < authctxt->nprev_ચાવીઓ; i++) {
		જો (sshkey_equal_public(ચાવી, authctxt->prev_ચાવીઓ[i])) {
			fp = sshkey_fingerprint(authctxt->prev_ચાવીઓ[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_ચાવીઓ[i]),
			    fp == ખાલી ? "UNKNOWN" : fp);
			મુક્ત(fp);
			પાછા 1;
		}
	}
	પાછા 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
શૂન્ય
auth2_update_session_info(Authctxt *authctxt, અચલ અક્ષર *method,
    અચલ અક્ષર *submethod)
{
	પૂર્ણાંક r;

	જો (authctxt->session_info == ખાલી) {
		જો ((authctxt->session_info = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	જો ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == ખાલી ? "" : "/",
	    submethod == ખાલી ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	જો (authctxt->auth_method_ચાવી != ખાલી) {
		જો ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_ચાવી,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	જો (authctxt->auth_method_info != ખાલી) {
		/* Ensure no ambiguity here */
		જો (strchr(authctxt->auth_method_info, '\n') != ખાલી)
			fatal_f("auth_method_info contains \\n");
		જો ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	જો ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

