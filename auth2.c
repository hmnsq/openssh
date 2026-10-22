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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/uio.h>

#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <time.h>

#অন্তর্ভাৱ "stdlib.h"
#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "ssherr.h"
#ifdef GSSAPI
#অন্তর্ভাৱ "ssh-gss.h"
#endif
#অন্তর্ভাৱ "monitor_wrap.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "kex.h"

/* import */
বাহ্য ServerOptions options;
বাহ্য সংরচনা sshbuf *loginmsg;

/* methods */

বাহ্য Authmethod method_none;
বাহ্য Authmethod method_pubkey;
বাহ্য Authmethod method_passwd;
বাহ্য Authmethod method_kbdint;
বাহ্য Authmethod method_hostbased;
#ifdef GSSAPI
বাহ্য Authmethod method_gssapi;
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
	রিক্ত
};

/* protocol */

স্থির পূর্ণাঙ্ক প্ৰবেশ_service_request(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্ৰবেশ_userauth_request(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);

/* helper */
স্থির Authmethod *authmethod_byname(ধ্রুৱ ৱর্ণ *);
স্থির Authmethod *authmethod_lookup(Authctxt *, ধ্রুৱ ৱর্ণ *);
স্থির ৱর্ণ *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
স্থির পূর্ণাঙ্ক list_starts_with(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

ৱর্ণ *
auth2_read_banner(শূন্য)
{
	সংরচনা stat st;
	ৱর্ণ *banner = রিক্ত;
	size_t len, n;
	পূর্ণাঙ্ক fd;

	যদি ((fd = open(options.banner, O_RDONLY)) == -1)
		ঘূৰাই (রিক্ত);
	যদি (fstat(fd, &st) == -1) {
		close(fd);
		ঘূৰাই (রিক্ত);
	}
	যদি (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ঘূৰাই (রিক্ত);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(পঠ, fd, banner, len);
	close(fd);

	যদি (n != len) {
		মুক্ত(banner);
		ঘূৰাই (রিক্ত);
	}
	banner[n] = '\0';

	ঘূৰাই (banner);
}

স্থির শূন্য
userauth_send_banner(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *বাৰ্তা)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, বাৰ্তা)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

স্থির শূন্য
userauth_banner(সংরচনা ssh *ssh)
{
	ৱর্ণ *banner = রিক্ত;

	যদি (options.banner == রিক্ত)
		ঘূৰাই;

	যদি ((banner = mm_auth2_read_banner()) == রিক্ত)
		গচ্ছ done;
	userauth_send_banner(ssh, banner);

done:
	মুক্ত(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
শূন্য
do_authentication2(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	যদি (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_বাৰ্তা_EXT_INFO, &kex_প্ৰবেশ_ext_info);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_SERVICE_REQUEST, &প্ৰবেশ_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = রিক্ত;
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_service_request(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ৱর্ণ *service = রিক্ত;
	পূর্ণাঙ্ক r, acceptit = 0;

	যদি ((r = sshpkt_get_cstring(ssh, &service, রিক্ত)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ out;

	যদি (authctxt == রিক্ত)
		fatal("input_service_request: no authctxt");

	যদি (strcmp(service, "ssh-userauth") == 0) {
		যদি (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_REQUEST,
			    &প্ৰবেশ_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	যদি (acceptit) {
		যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			গচ্ছ out;
	} অন্যথা {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	মুক্ত(service);
	ঘূৰাই r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
স্থির দ্ৱিগুণ
user_specific_delay(ধ্রুৱ ৱর্ণ *user)
{
	ৱর্ণ b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	দ্ৱিগুণ delay;

	(শূন্য)snprintf(b, পরিমাণ b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	যদি (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (দ্ৱিগুণ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ঘূৰাই MIN_FAIL_DELAY_SECONDS + delay;
}

স্থির শূন্য
ensure_minimum_time_since(দ্ৱিগুণ start, দ্ৱিগুণ seconds)
{
	সংরচনা timespec ts;
	দ্ৱিগুণ elapsed = monotime_double() - start, req = seconds, remain;

	যদি (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ঘূৰাই;
	}

	/* if we've already passed the requested time, scale up */
	যেতিয়ালৈ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, রিক্ত);
}

শূন্য
auth_failure_delay(Authctxt *authctxt, দ্ৱিগুণ tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_userauth_request(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = রিক্ত;
	ৱর্ণ *user = রিক্ত, *service = রিক্ত, *method = রিক্ত, *style = রিক্ত;
	পূর্ণাঙ্ক r, authenticated = 0;
	দ্ৱিগুণ tstart = monotime_double();

	যদি (authctxt == রিক্ত)
		fatal("input_userauth_request: no authctxt");

	যদি ((r = sshpkt_get_cstring(ssh, &user, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, রিক্ত)) != 0)
		গচ্ছ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	যদি ((style = strchr(user, ':')) != রিক্ত)
		*style++ = 0;

	যদি (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	যদি (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : রিক্ত;
		যদি (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} অন্যথা {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		যদি (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		যদি ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		যদি (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} অন্যথা যদি (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, রিক্ত);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	যদি (m != রিক্ত && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	যদি (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, রিক্ত);
	r = 0;
 out:
	মুক্ত(service);
	মুক্ত(user);
	মুক্ত(method);
	ঘূৰাই r;
}

শূন্য
userauth_finish(সংরচনা ssh *ssh, পূর্ণাঙ্ক authenticated, ধ্রুৱ ৱর্ণ *packet_method,
    ধ্রুৱ ৱর্ণ *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = রিক্ত;
	ধ্রুৱ ৱর্ণ *method = packet_method;
	ৱর্ণ *methods;
	পূর্ণাঙ্ক r, partial = 0;

	যদি (authenticated) {
		যদি (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		যদি (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		যদি ((m = authmethod_byname(method)) == রিক্ত)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	যদি (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_মূল_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_মূল_DENIED);
#endif
	}

	যদি (authenticated && options.অঙ্ক_auth_methods != 0) {
		যদি (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	যদি (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	যদি (authctxt->postponed)
		ঘূৰাই;

#ifdef USE_PAM
	যদি (options.use_pam && authenticated) {
		পূর্ণাঙ্ক r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		যদি (sshbuf_len(loginmsg) > 0) {
			যদি ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			যদি ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		যদি (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	যদি (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} অন্যথা {
		/* Allow initial try of "none" auth without failure penalty */
		যদি (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		যদি (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		মুক্ত(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
পূর্ণাঙ্ক
auth2_method_allowed(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *method,
    ধ্রুৱ ৱর্ণ *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	যদি (options.অঙ্ক_auth_methods == 0)
		ঘূৰাই 1;
	বাবে (i = 0; i < authctxt->অঙ্ক_auth_methods; i++) {
		যদি (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			ঘূৰাই 1;
	}
	ঘূৰাই 0;
}

স্থির ৱর্ণ *
authmethods_get(Authctxt *authctxt)
{
	সংরচনা sshbuf *b;
	ৱর্ণ *list;
	পূর্ণাঙ্ক i, r;

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	বাবে (i = 0; authmethods[i] != রিক্ত; i++) {
		যদি (strcmp(authmethods[i]->cfg->name, "none") == 0)
			অনুৱর্ত;
		যদি (authmethods[i]->cfg->enabled == রিক্ত ||
		    *(authmethods[i]->cfg->enabled) == 0)
			অনুৱর্ত;
		যদি (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    রিক্ত))
			অনুৱর্ত;
		যদি ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	যদি ((list = sshbuf_dup_string(b)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ঘূৰাই list;
}

স্থির Authmethod *
authmethod_byname(ধ্রুৱ ৱর্ণ *name)
{
	পূর্ণাঙ্ক i;

	যদি (name == রিক্ত)
		fatal_f("NULL authentication method name");
	বাবে (i = 0; authmethods[i] != রিক্ত; i++) {
		যদি (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != রিক্ত &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ঘূৰাই authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ঘূৰাই রিক্ত;
}

স্থির Authmethod *
authmethod_lookup(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *name)
{
	Authmethod *method;

	যদি ((method = authmethod_byname(name)) == রিক্ত)
		ঘূৰাই রিক্ত;

	যদি (method->cfg->enabled == রিক্ত || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ঘূৰাই রিক্ত;
	}
	যদি (!auth2_method_allowed(authctxt, method->cfg->name, রিক্ত)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ঘূৰাই রিক্ত;
	}
	ঘূৰাই method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
পূর্ণাঙ্ক
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	যদি (options.অঙ্ক_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		মুক্ত(options.auth_methods[0]);
		options.auth_methods[0] = রিক্ত;
		options.অঙ্ক_auth_methods = 0;
	}

	যদি (options.অঙ্ক_auth_methods == 0)
		ঘূৰাই 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.অঙ্ক_auth_methods,
	    পরিমাণ(*authctxt->auth_methods));
	authctxt->অঙ্ক_auth_methods = 0;
	বাবে (i = 0; i < options.অঙ্ক_auth_methods; i++) {
		যদি (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			অনুৱর্ত;
		}
		debug("authentication methods list %d: %s",
		    authctxt->অঙ্ক_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->অঙ্ক_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	যদি (authctxt->অঙ্ক_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
list_starts_with(ধ্রুৱ ৱর্ণ *methods, ধ্রুৱ ৱর্ণ *method,
    ধ্রুৱ ৱর্ণ *submethod)
{
	size_t l = strlen(method);
	পূর্ণাঙ্ক match;
	ধ্রুৱ ৱর্ণ *p;

	যদি (strncmp(methods, method, l) != 0)
		ঘূৰাই MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	যদি (*p == ':') {
		যদি (!submethod)
			ঘূৰাই MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		যদি (strncmp(submethod, p, l))
			ঘূৰাই MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	যদি (*p != ',' && *p != '\0')
		ঘূৰাই MATCH_NONE;
	ঘূৰাই match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
স্থির পূর্ণাঙ্ক
remove_method(ৱর্ণ **methods, ধ্রুৱ ৱর্ণ *method, ধ্রুৱ ৱর্ণ *submethod)
{
	ৱর্ণ *omethods = *methods, *p;
	size_t l = strlen(method);
	পূর্ণাঙ্ক match;

	match = list_starts_with(omethods, method, submethod);
	যদি (match != MATCH_METHOD && match != MATCH_BOTH)
		ঘূৰাই 0;
	p = omethods + l;
	যদি (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	যদি (*p == ',')
		p++;
	*methods = xstrdup(p);
	মুক্ত(omethods);
	ঘূৰাই 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
পূর্ণাঙ্ক
auth2_update_methods_lists(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *method,
    ধ্রুৱ ৱর্ণ *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	বাবে (i = 0; i < authctxt->অঙ্ক_auth_methods; i++) {
		যদি (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			অনুৱর্ত;
		found = 1;
		যদি (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ঘূৰাই 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	যদি (!found)
		fatal_f("method not in AuthenticationMethods");
	ঘূৰাই 0;
}

/* Reset method-specific information */
শূন্য auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_চাবি);
	মুক্ত(authctxt->auth_method_info);
	authctxt->auth_method_চাবি = রিক্ত;
	authctxt->auth_method_info = রিক্ত;
}

/* Record auth method-specific information for logs */
শূন্য
auth2_record_info(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list ap;
	পূর্ণাঙ্ক i;

	মুক্ত(authctxt->auth_method_info);
	authctxt->auth_method_info = রিক্ত;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	যদি (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
শূন্য
auth2_record_চাবি(Authctxt *authctxt, পূর্ণাঙ্ক authenticated,
    ধ্রুৱ সংরচনা sshkey *চাবি)
{
	সংরচনা sshkey **tmp, *dup;
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_from_private(চাবি, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_চাবি);
	authctxt->auth_method_চাবি = dup;

	যদি (!authenticated)
		ঘূৰাই;

	/* If authenticated, make sure we don't accept this key again */
	যদি ((r = sshkey_from_private(চাবি, &dup)) != 0)
		fatal_fr(r, "copy key");
	যদি (authctxt->nprev_চাবিগুলি >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_চাবিগুলি, authctxt->nprev_চাবিগুলি,
	    authctxt->nprev_চাবিগুলি + 1, পরিমাণ(*authctxt->prev_চাবিগুলি))) == রিক্ত)
		fatal_f("reallocarray failed");
	authctxt->prev_চাবিগুলি = tmp;
	authctxt->prev_চাবিগুলি[authctxt->nprev_চাবিগুলি] = dup;
	authctxt->nprev_চাবিগুলি++;

}

/* Checks whether a key has already been previously used for authentication */
পূর্ণাঙ্ক
auth2_চাবি_already_used(Authctxt *authctxt, ধ্রুৱ সংরচনা sshkey *চাবি)
{
	u_int i;
	ৱর্ণ *fp;

	বাবে (i = 0; i < authctxt->nprev_চাবিগুলি; i++) {
		যদি (sshkey_equal_public(চাবি, authctxt->prev_চাবিগুলি[i])) {
			fp = sshkey_fingerprint(authctxt->prev_চাবিগুলি[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_চাবিগুলি[i]),
			    fp == রিক্ত ? "UNKNOWN" : fp);
			মুক্ত(fp);
			ঘূৰাই 1;
		}
	}
	ঘূৰাই 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
শূন্য
auth2_update_session_info(Authctxt *authctxt, ধ্রুৱ ৱর্ণ *method,
    ধ্রুৱ ৱর্ণ *submethod)
{
	পূর্ণাঙ্ক r;

	যদি (authctxt->session_info == রিক্ত) {
		যদি ((authctxt->session_info = sshbuf_new()) == রিক্ত)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	যদি ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == রিক্ত ? "" : "/",
	    submethod == রিক্ত ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	যদি (authctxt->auth_method_চাবি != রিক্ত) {
		যদি ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_চাবি,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	যদি (authctxt->auth_method_info != রিক্ত) {
		/* Ensure no ambiguity here */
		যদি (strchr(authctxt->auth_method_info, '\n') != রিক্ত)
			fatal_f("auth_method_info contains \\n");
		যদি ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	যদি ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

