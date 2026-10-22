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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "stdlib.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssherr.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "kex.h"

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന sshbuf *loginmsg;

/* methods */

ബാഹ്യ Authmethod method_none;
ബാഹ്യ Authmethod method_pubkey;
ബാഹ്യ Authmethod method_passwd;
ബാഹ്യ Authmethod method_kbdint;
ബാഹ്യ Authmethod method_hostbased;
#ifdef GSSAPI
ബാഹ്യ Authmethod method_gssapi;
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
	ശൂന്യ
};

/* protocol */

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_service_request(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_request(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

/* helper */
സ്ഥിതം Authmethod *authmethod_byname(സ്ഥിരം അക്ഷരം *);
സ്ഥിതം Authmethod *authmethod_lookup(Authctxt *, സ്ഥിരം അക്ഷരം *);
സ്ഥിതം അക്ഷരം *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
സ്ഥിതം പൂർണ്ണസംഖ്യ list_starts_with(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

അക്ഷരം *
auth2_read_banner(ശൂന്യം)
{
	ഘടന stat st;
	അക്ഷരം *banner = ശൂന്യ;
	size_t len, n;
	പൂർണ്ണസംഖ്യ fd;

	എങ്കിൽ ((fd = open(options.banner, O_RDONLY)) == -1)
		തിരികെ (ശൂന്യ);
	എങ്കിൽ (fstat(fd, &st) == -1) {
		close(fd);
		തിരികെ (ശൂന്യ);
	}
	എങ്കിൽ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		തിരികെ (ശൂന്യ);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(പഠ, fd, banner, len);
	close(fd);

	എങ്കിൽ (n != len) {
		സ്വതന്ത്രം(banner);
		തിരികെ (ശൂന്യ);
	}
	banner[n] = '\0';

	തിരികെ (banner);
}

സ്ഥിതം ശൂന്യം
userauth_send_banner(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *സന്ദേശം)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, സന്ദേശം)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

സ്ഥിതം ശൂന്യം
userauth_banner(ഘടന ssh *ssh)
{
	അക്ഷരം *banner = ശൂന്യ;

	എങ്കിൽ (options.banner == ശൂന്യ)
		തിരികെ;

	എങ്കിൽ ((banner = mm_auth2_read_banner()) == ശൂന്യ)
		പോകുക done;
	userauth_send_banner(ssh, banner);

done:
	സ്വതന്ത്രം(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
ശൂന്യം
do_authentication2(ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	എങ്കിൽ (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, &kex_നിവേശം_ext_info);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_SERVICE_REQUEST, &നിവേശം_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_service_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	അക്ഷരം *service = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, acceptit = 0;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &service, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_service_request: no authctxt");

	എങ്കിൽ (strcmp(service, "ssh-userauth") == 0) {
		എങ്കിൽ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST,
			    &നിവേശം_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	എങ്കിൽ (acceptit) {
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	സ്വതന്ത്രം(service);
	തിരികെ r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
സ്ഥിതം ഇരട്ട
user_specific_delay(സ്ഥിരം അക്ഷരം *user)
{
	അക്ഷരം b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ഇരട്ട delay;

	(ശൂന്യം)snprintf(b, വലുപ്പം b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	എങ്കിൽ (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ഇരട്ട)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	തിരികെ MIN_FAIL_DELAY_SECONDS + delay;
}

സ്ഥിതം ശൂന്യം
ensure_minimum_time_since(ഇരട്ട start, ഇരട്ട seconds)
{
	ഘടന timespec ts;
	ഇരട്ട elapsed = monotime_double() - start, req = seconds, remain;

	എങ്കിൽ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		തിരികെ;
	}

	/* if we've already passed the requested time, scale up */
	ആകുമ്പോൾ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ശൂന്യ);
}

ശൂന്യം
auth_failure_delay(Authctxt *authctxt, ഇരട്ട tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ശൂന്യ;
	അക്ഷരം *user = ശൂന്യ, *service = ശൂന്യ, *method = ശൂന്യ, *style = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, authenticated = 0;
	ഇരട്ട tstart = monotime_double();

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_userauth_request: no authctxt");

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &user, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, ശൂന്യ)) != 0)
		പോകുക out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	എങ്കിൽ ((style = strchr(user, ':')) != ശൂന്യ)
		*style++ = 0;

	എങ്കിൽ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	എങ്കിൽ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ശൂന്യ;
		എങ്കിൽ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} അല്ലെങ്കിൽ {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		എങ്കിൽ (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		എങ്കിൽ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		എങ്കിൽ (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ശൂന്യ);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	എങ്കിൽ (m != ശൂന്യ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	എങ്കിൽ (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, ശൂന്യ);
	r = 0;
 out:
	സ്വതന്ത്രം(service);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(method);
	തിരികെ r;
}

ശൂന്യം
userauth_finish(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ authenticated, സ്ഥിരം അക്ഷരം *packet_method,
    സ്ഥിരം അക്ഷരം *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *method = packet_method;
	അക്ഷരം *methods;
	പൂർണ്ണസംഖ്യ r, partial = 0;

	എങ്കിൽ (authenticated) {
		എങ്കിൽ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		എങ്കിൽ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		എങ്കിൽ ((m = authmethod_byname(method)) == ശൂന്യ)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	എങ്കിൽ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_വേര്_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_വേര്_DENIED);
#endif
	}

	എങ്കിൽ (authenticated && options.അക്കം_auth_methods != 0) {
		എങ്കിൽ (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	എങ്കിൽ (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	എങ്കിൽ (authctxt->postponed)
		തിരികെ;

#ifdef USE_PAM
	എങ്കിൽ (options.use_pam && authenticated) {
		പൂർണ്ണസംഖ്യ r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		എങ്കിൽ (sshbuf_len(loginmsg) > 0) {
			എങ്കിൽ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			എങ്കിൽ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		എങ്കിൽ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	എങ്കിൽ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} അല്ലെങ്കിൽ {
		/* Allow initial try of "none" auth without failure penalty */
		എങ്കിൽ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		എങ്കിൽ (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		സ്വതന്ത്രം(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
പൂർണ്ണസംഖ്യ
auth2_method_allowed(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *method,
    സ്ഥിരം അക്ഷരം *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	എങ്കിൽ (options.അക്കം_auth_methods == 0)
		തിരികെ 1;
	വേണ്ടി (i = 0; i < authctxt->അക്കം_auth_methods; i++) {
		എങ്കിൽ (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			തിരികെ 1;
	}
	തിരികെ 0;
}

സ്ഥിതം അക്ഷരം *
authmethods_get(Authctxt *authctxt)
{
	ഘടന sshbuf *b;
	അക്ഷരം *list;
	പൂർണ്ണസംഖ്യ i, r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	വേണ്ടി (i = 0; authmethods[i] != ശൂന്യ; i++) {
		എങ്കിൽ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			തുടരുക;
		എങ്കിൽ (authmethods[i]->cfg->enabled == ശൂന്യ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			തുടരുക;
		എങ്കിൽ (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    ശൂന്യ))
			തുടരുക;
		എങ്കിൽ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	എങ്കിൽ ((list = sshbuf_dup_string(b)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	തിരികെ list;
}

സ്ഥിതം Authmethod *
authmethod_byname(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (name == ശൂന്യ)
		fatal_f("NULL authentication method name");
	വേണ്ടി (i = 0; authmethods[i] != ശൂന്യ; i++) {
		എങ്കിൽ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ശൂന്യ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			തിരികെ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	തിരികെ ശൂന്യ;
}

സ്ഥിതം Authmethod *
authmethod_lookup(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *name)
{
	Authmethod *method;

	എങ്കിൽ ((method = authmethod_byname(name)) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	എങ്കിൽ (method->cfg->enabled == ശൂന്യ || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (!auth2_method_allowed(authctxt, method->cfg->name, ശൂന്യ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		തിരികെ ശൂന്യ;
	}
	തിരികെ method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
പൂർണ്ണസംഖ്യ
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	എങ്കിൽ (options.അക്കം_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		സ്വതന്ത്രം(options.auth_methods[0]);
		options.auth_methods[0] = ശൂന്യ;
		options.അക്കം_auth_methods = 0;
	}

	എങ്കിൽ (options.അക്കം_auth_methods == 0)
		തിരികെ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.അക്കം_auth_methods,
	    വലുപ്പം(*authctxt->auth_methods));
	authctxt->അക്കം_auth_methods = 0;
	വേണ്ടി (i = 0; i < options.അക്കം_auth_methods; i++) {
		എങ്കിൽ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			തുടരുക;
		}
		debug("authentication methods list %d: %s",
		    authctxt->അക്കം_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->അക്കം_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	എങ്കിൽ (authctxt->അക്കം_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		തിരികെ -1;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
list_starts_with(സ്ഥിരം അക്ഷരം *methods, സ്ഥിരം അക്ഷരം *method,
    സ്ഥിരം അക്ഷരം *submethod)
{
	size_t l = strlen(method);
	പൂർണ്ണസംഖ്യ match;
	സ്ഥിരം അക്ഷരം *p;

	എങ്കിൽ (strncmp(methods, method, l) != 0)
		തിരികെ MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	എങ്കിൽ (*p == ':') {
		എങ്കിൽ (!submethod)
			തിരികെ MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		എങ്കിൽ (strncmp(submethod, p, l))
			തിരികെ MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	എങ്കിൽ (*p != ',' && *p != '\0')
		തിരികെ MATCH_NONE;
	തിരികെ match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
remove_method(അക്ഷരം **methods, സ്ഥിരം അക്ഷരം *method, സ്ഥിരം അക്ഷരം *submethod)
{
	അക്ഷരം *omethods = *methods, *p;
	size_t l = strlen(method);
	പൂർണ്ണസംഖ്യ match;

	match = list_starts_with(omethods, method, submethod);
	എങ്കിൽ (match != MATCH_METHOD && match != MATCH_BOTH)
		തിരികെ 0;
	p = omethods + l;
	എങ്കിൽ (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	എങ്കിൽ (*p == ',')
		p++;
	*methods = xstrdup(p);
	സ്വതന്ത്രം(omethods);
	തിരികെ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
പൂർണ്ണസംഖ്യ
auth2_update_methods_lists(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *method,
    സ്ഥിരം അക്ഷരം *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	വേണ്ടി (i = 0; i < authctxt->അക്കം_auth_methods; i++) {
		എങ്കിൽ (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			തുടരുക;
		found = 1;
		എങ്കിൽ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			തിരികെ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	എങ്കിൽ (!found)
		fatal_f("method not in AuthenticationMethods");
	തിരികെ 0;
}

/* Reset method-specific information */
ശൂന്യം auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_താക്കോൽ);
	സ്വതന്ത്രം(authctxt->auth_method_info);
	authctxt->auth_method_താക്കോൽ = ശൂന്യ;
	authctxt->auth_method_info = ശൂന്യ;
}

/* Record auth method-specific information for logs */
ശൂന്യം
auth2_record_info(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;
	പൂർണ്ണസംഖ്യ i;

	സ്വതന്ത്രം(authctxt->auth_method_info);
	authctxt->auth_method_info = ശൂന്യ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	എങ്കിൽ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
ശൂന്യം
auth2_record_താക്കോൽ(Authctxt *authctxt, പൂർണ്ണസംഖ്യ authenticated,
    സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	ഘടന sshkey **tmp, *dup;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_from_private(താക്കോൽ, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_താക്കോൽ);
	authctxt->auth_method_താക്കോൽ = dup;

	എങ്കിൽ (!authenticated)
		തിരികെ;

	/* If authenticated, make sure we don't accept this key again */
	എങ്കിൽ ((r = sshkey_from_private(താക്കോൽ, &dup)) != 0)
		fatal_fr(r, "copy key");
	എങ്കിൽ (authctxt->nprev_താക്കോലുകൾ >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_താക്കോലുകൾ, authctxt->nprev_താക്കോലുകൾ,
	    authctxt->nprev_താക്കോലുകൾ + 1, വലുപ്പം(*authctxt->prev_താക്കോലുകൾ))) == ശൂന്യ)
		fatal_f("reallocarray failed");
	authctxt->prev_താക്കോലുകൾ = tmp;
	authctxt->prev_താക്കോലുകൾ[authctxt->nprev_താക്കോലുകൾ] = dup;
	authctxt->nprev_താക്കോലുകൾ++;

}

/* Checks whether a key has already been previously used for authentication */
പൂർണ്ണസംഖ്യ
auth2_താക്കോൽ_already_used(Authctxt *authctxt, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	u_int i;
	അക്ഷരം *fp;

	വേണ്ടി (i = 0; i < authctxt->nprev_താക്കോലുകൾ; i++) {
		എങ്കിൽ (sshkey_equal_public(താക്കോൽ, authctxt->prev_താക്കോലുകൾ[i])) {
			fp = sshkey_fingerprint(authctxt->prev_താക്കോലുകൾ[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_താക്കോലുകൾ[i]),
			    fp == ശൂന്യ ? "UNKNOWN" : fp);
			സ്വതന്ത്രം(fp);
			തിരികെ 1;
		}
	}
	തിരികെ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
ശൂന്യം
auth2_update_session_info(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *method,
    സ്ഥിരം അക്ഷരം *submethod)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt->session_info == ശൂന്യ) {
		എങ്കിൽ ((authctxt->session_info = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	എങ്കിൽ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == ശൂന്യ ? "" : "/",
	    submethod == ശൂന്യ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	എങ്കിൽ (authctxt->auth_method_താക്കോൽ != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_താക്കോൽ,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	എങ്കിൽ (authctxt->auth_method_info != ശൂന്യ) {
		/* Ensure no ambiguity here */
		എങ്കിൽ (strchr(authctxt->auth_method_info, '\n') != ശൂന്യ)
			fatal_f("auth_method_info contains \\n");
		എങ്കിൽ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	എങ്കിൽ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

