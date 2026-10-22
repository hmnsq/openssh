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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "stdlib.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "kex.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;

/* methods */

ಬಾಹ್ಯ Authmethod method_none;
ಬಾಹ್ಯ Authmethod method_pubkey;
ಬಾಹ್ಯ Authmethod method_passwd;
ಬಾಹ್ಯ Authmethod method_kbdint;
ಬಾಹ್ಯ Authmethod method_hostbased;
#ifdef GSSAPI
ಬಾಹ್ಯ Authmethod method_gssapi;
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
	ರಿಕ್ತ
};

/* protocol */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_service_request(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_request(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

/* helper */
ಸ್ಥಿರ Authmethod *authmethod_byname(ಧ್ರುವ ವರ್ಣ *);
ಸ್ಥಿರ Authmethod *authmethod_lookup(Authctxt *, ಧ್ರುವ ವರ್ಣ *);
ಸ್ಥಿರ ವರ್ಣ *authmethods_get(Authctxt *authctxt);

#define MATCH_NONE	0	/* method or submethod mismatch */
#define MATCH_METHOD	1	/* method matches (no submethod specified) */
#define MATCH_BOTH	2	/* method and submethod match */
#define MATCH_PARTIAL	3	/* method matches, submethod can't be checked */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ list_starts_with(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

ವರ್ಣ *
auth2_read_banner(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ stat st;
	ವರ್ಣ *banner = ರಿಕ್ತ;
	size_t len, n;
	ಪೂರ್ಣಾಙ್ಕ fd;

	ಯದಿ ((fd = open(options.banner, O_RDONLY)) == -1)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	ಯದಿ (fstat(fd, &st) == -1) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	ಯದಿ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	len = (size_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(ಪಠ, fd, banner, len);
	close(fd);

	ಯದಿ (n != len) {
		ಮುಕ್ತ(banner);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	banner[n] = '\0';

	ಪ್ರತ್ಯಾಗಮ (banner);
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_send_banner(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ಸಂದೇಶ)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_banner(ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *banner = ರಿಕ್ತ;

	ಯದಿ (options.banner == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ ((banner = mm_auth2_read_banner()) == ರಿಕ್ತ)
		ಗಚ್ಛ done;
	userauth_send_banner(ssh, banner);

done:
	ಮುಕ್ತ(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
ಶೂನ್ಯ
do_authentication2(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ಯದಿ (ssh->kex->ext_info_c)
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_SERVICE_REQUEST, &ಒಳಹರಿವು_service_request);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt->success);
	ssh->authctxt = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_service_request(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ವರ್ಣ *service = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, acceptit = 0;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &service, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_service_request: no authctxt");

	ಯದಿ (strcmp(service, "ssh-userauth") == 0) {
		ಯದಿ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
			    &ಒಳಹರಿವು_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	ಯದಿ (acceptit) {
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 out:
	ಮುಕ್ತ(service);
	ಪ್ರತ್ಯಾಗಮ r;
}

#define MIN_FAIL_DELAY_SECONDS 0.005
#define MAX_FAIL_DELAY_SECONDS 5.0
ಸ್ಥಿರ ದ್ವಿಗುಣ
user_specific_delay(ಧ್ರುವ ವರ್ಣ *user)
{
	ವರ್ಣ b[512];
	size_t len = ssh_digest_bytes(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ದ್ವಿಗುಣ delay;

	(ಶೂನ್ಯ)snprintf(b, ಪರಿಮಾಣ b, "%llu%s",
	    (unsigned long long)options.timing_secret, user);
	ಯದಿ (ssh_digest_memory(SSH_DIGEST_SHA512, b, strlen(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ದ್ವಿಗುಣ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ಪ್ರತ್ಯಾಗಮ MIN_FAIL_DELAY_SECONDS + delay;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ensure_minimum_time_since(ದ್ವಿಗುಣ start, ದ್ವಿಗುಣ seconds)
{
	ಸಂರಚನಾ timespec ts;
	ದ್ವಿಗುಣ elapsed = monotime_double() - start, req = seconds, remain;

	ಯದಿ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ಪ್ರತ್ಯಾಗಮ;
	}

	/* if we've already passed the requested time, scale up */
	ಯಾವತ್ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ರಿಕ್ತ);
}

ಶೂನ್ಯ
auth_failure_delay(Authctxt *authctxt, ದ್ವಿಗುಣ tstart)
{
	ensure_minimum_time_since(tstart, user_specific_delay(authctxt->user));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_request(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ರಿಕ್ತ;
	ವರ್ಣ *user = ರಿಕ್ತ, *service = ರಿಕ್ತ, *method = ರಿಕ್ತ, *style = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated = 0;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_userauth_request: no authctxt");

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &user, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	debug("userauth-request for user %s service %s method %s", user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	ಯದಿ ((style = strchr(user, ':')) != ರಿಕ್ತ)
		*style++ = 0;

	ಯದಿ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	ಯದಿ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ರಿಕ್ತ;
		ಯದಿ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} ಅನ್ಯಥಾ {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#endif
		}
#ifdef USE_PAM
		ಯದಿ (options.use_pam)
			mm_start_pam(ssh);
#endif
		ssh_packet_set_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		ಯದಿ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		ಯದಿ (auth2_setup_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(user, authctxt->user) != 0 ||
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
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ರಿಕ್ತ);
#endif

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, method);
	ಯದಿ (m != ರಿಕ್ತ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", method);
		authenticated =	m->userauth(ssh, method);
	}
	ಯದಿ (!authctxt->authenticated && strcmp(method, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_finish(ssh, authenticated, method, ರಿಕ್ತ);
	r = 0;
 out:
	ಮುಕ್ತ(service);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(method);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಶೂನ್ಯ
userauth_finish(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ authenticated, ಧ್ರುವ ವರ್ಣ *packet_method,
    ಧ್ರುವ ವರ್ಣ *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *method = packet_method;
	ವರ್ಣ *methods;
	ಪೂರ್ಣಾಙ್ಕ r, partial = 0;

	ಯದಿ (authenticated) {
		ಯದಿ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		ಯದಿ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		ಯದಿ ((m = authmethod_byname(method)) == ರಿಕ್ತ)
			fatal("INTERNAL ERROR: bad method %s", method);
		method = m->cfg->name;
	}

	/* Special handling for root */
	ಯದಿ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_ಬೇರು_allowed(ssh, method)) {
		authenticated = 0;
#ifdef SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ಬೇರು_DENIED);
#endif
	}

	ಯದಿ (authenticated && options.ಅಂಕೆ_auth_methods != 0) {
		ಯದಿ (!auth2_update_methods_lists(authctxt, method, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, method, submethod);

	/* Update information exposed to session */
	ಯದಿ (authenticated || partial)
		auth2_update_session_info(authctxt, method, submethod);

	ಯದಿ (authctxt->postponed)
		ಪ್ರತ್ಯಾಗಮ;

#ifdef USE_PAM
	ಯದಿ (options.use_pam && authenticated) {
		ಪೂರ್ಣಾಙ್ಕ r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		ಯದಿ (sshbuf_len(loginmsg) > 0) {
			ಯದಿ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			ಯದಿ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		ಯದಿ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#endif

	ಯದಿ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
	} ಅನ್ಯಥಾ {
		/* Allow initial try of "none" auth without failure penalty */
		ಯದಿ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(method, "none") != 0))
			authctxt->failures++;
		ಯದಿ (authctxt->failures >= options.max_authtries) {
#ifdef SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#endif
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		ಮುಕ್ತ(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
auth2_method_allowed(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *method,
    ಧ್ರುವ ವರ್ಣ *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	ಯದಿ (options.ಅಂಕೆ_auth_methods == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಪ್ರತಿ (i = 0; i < authctxt->ಅಂಕೆ_auth_methods; i++) {
		ಯದಿ (list_starts_with(authctxt->auth_methods[i], method,
		    submethod) != MATCH_NONE)
			ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ವರ್ಣ *
authmethods_get(Authctxt *authctxt)
{
	ಸಂರಚನಾ sshbuf *b;
	ವರ್ಣ *list;
	ಪೂರ್ಣಾಙ್ಕ i, r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಪ್ರತಿ (i = 0; authmethods[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ಅನುವರ್ತ;
		ಯದಿ (authmethods[i]->cfg->enabled == ರಿಕ್ತ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ಅನುವರ್ತ;
		ಯದಿ (!auth2_method_allowed(authctxt, authmethods[i]->cfg->name,
		    ರಿಕ್ತ))
			ಅನುವರ್ತ;
		ಯದಿ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	ಯದಿ ((list = sshbuf_dup_string(b)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ list;
}

ಸ್ಥಿರ Authmethod *
authmethod_byname(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (name == ರಿಕ್ತ)
		fatal_f("NULL authentication method name");
	ಪ್ರತಿ (i = 0; authmethods[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ರಿಕ್ತ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ಪ್ರತ್ಯಾಗಮ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ Authmethod *
authmethod_lookup(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *name)
{
	Authmethod *method;

	ಯದಿ ((method = authmethod_byname(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ಯದಿ (method->cfg->enabled == ರಿಕ್ತ || *(method->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (!auth2_method_allowed(authctxt, method->cfg->name, ರಿಕ್ತ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ method;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
ಪೂರ್ಣಾಙ್ಕ
auth2_setup_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	ಯದಿ (options.ಅಂಕೆ_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		ಮುಕ್ತ(options.auth_methods[0]);
		options.auth_methods[0] = ರಿಕ್ತ;
		options.ಅಂಕೆ_auth_methods = 0;
	}

	ಯದಿ (options.ಅಂಕೆ_auth_methods == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.ಅಂಕೆ_auth_methods,
	    ಪರಿಮಾಣ(*authctxt->auth_methods));
	authctxt->ಅಂಕೆ_auth_methods = 0;
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_auth_methods; i++) {
		ಯದಿ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ಅನುವರ್ತ;
		}
		debug("authentication methods list %d: %s",
		    authctxt->ಅಂಕೆ_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->ಅಂಕೆ_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	ಯದಿ (authctxt->ಅಂಕೆ_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
list_starts_with(ಧ್ರುವ ವರ್ಣ *methods, ಧ್ರುವ ವರ್ಣ *method,
    ಧ್ರುವ ವರ್ಣ *submethod)
{
	size_t l = strlen(method);
	ಪೂರ್ಣಾಙ್ಕ match;
	ಧ್ರುವ ವರ್ಣ *p;

	ಯದಿ (strncmp(methods, method, l) != 0)
		ಪ್ರತ್ಯಾಗಮ MATCH_NONE;
	p = methods + l;
	match = MATCH_METHOD;
	ಯದಿ (*p == ':') {
		ಯದಿ (!submethod)
			ಪ್ರತ್ಯಾಗಮ MATCH_PARTIAL;
		l = strlen(submethod);
		p += 1;
		ಯದಿ (strncmp(submethod, p, l))
			ಪ್ರತ್ಯಾಗಮ MATCH_NONE;
		p += l;
		match = MATCH_BOTH;
	}
	ಯದಿ (*p != ',' && *p != '\0')
		ಪ್ರತ್ಯಾಗಮ MATCH_NONE;
	ಪ್ರತ್ಯಾಗಮ match;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
remove_method(ವರ್ಣ **methods, ಧ್ರುವ ವರ್ಣ *method, ಧ್ರುವ ವರ್ಣ *submethod)
{
	ವರ್ಣ *omethods = *methods, *p;
	size_t l = strlen(method);
	ಪೂರ್ಣಾಙ್ಕ match;

	match = list_starts_with(omethods, method, submethod);
	ಯದಿ (match != MATCH_METHOD && match != MATCH_BOTH)
		ಪ್ರತ್ಯಾಗಮ 0;
	p = omethods + l;
	ಯದಿ (submethod && match == MATCH_BOTH)
		p += 1 + strlen(submethod); /* include colon */
	ಯದಿ (*p == ',')
		p++;
	*methods = xstrdup(p);
	ಮುಕ್ತ(omethods);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
ಪೂರ್ಣಾಙ್ಕ
auth2_update_methods_lists(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *method,
    ಧ್ರುವ ವರ್ಣ *submethod)
{
	u_int i, found = 0;

	debug3_f("updating methods list after \"%s\"", method);
	ಪ್ರತಿ (i = 0; i < authctxt->ಅಂಕೆ_auth_methods; i++) {
		ಯದಿ (!remove_method(&(authctxt->auth_methods[i]), method,
		    submethod))
			ಅನುವರ್ತ;
		found = 1;
		ಯದಿ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ಪ್ರತ್ಯಾಗಮ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	ಯದಿ (!found)
		fatal_f("method not in AuthenticationMethods");
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Reset method-specific information */
ಶೂನ್ಯ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_method_ಕೀಲಿ);
	ಮುಕ್ತ(authctxt->auth_method_info);
	authctxt->auth_method_ಕೀಲಿ = ರಿಕ್ತ;
	authctxt->auth_method_info = ರಿಕ್ತ;
}

/* Record auth method-specific information for logs */
ಶೂನ್ಯ
auth2_record_info(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಮುಕ್ತ(authctxt->auth_method_info);
	authctxt->auth_method_info = ರಿಕ್ತ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_method_info, fmt, ap);
	va_end(ap);

	ಯದಿ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
ಶೂನ್ಯ
auth2_record_ಕೀಲಿ(Authctxt *authctxt, ಪೂರ್ಣಾಙ್ಕ authenticated,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ sshkey **tmp, *dup;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_from_private(ಕೀಲಿ, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_method_ಕೀಲಿ);
	authctxt->auth_method_ಕೀಲಿ = dup;

	ಯದಿ (!authenticated)
		ಪ್ರತ್ಯಾಗಮ;

	/* If authenticated, make sure we don't accept this key again */
	ಯದಿ ((r = sshkey_from_private(ಕೀಲಿ, &dup)) != 0)
		fatal_fr(r, "copy key");
	ಯದಿ (authctxt->nprev_ಕೀಲಿಗಳು >= INT_MAX ||
	    (tmp = recallocarray(authctxt->prev_ಕೀಲಿಗಳು, authctxt->nprev_ಕೀಲಿಗಳು,
	    authctxt->nprev_ಕೀಲಿಗಳು + 1, ಪರಿಮಾಣ(*authctxt->prev_ಕೀಲಿಗಳು))) == ರಿಕ್ತ)
		fatal_f("reallocarray failed");
	authctxt->prev_ಕೀಲಿಗಳು = tmp;
	authctxt->prev_ಕೀಲಿಗಳು[authctxt->nprev_ಕೀಲಿಗಳು] = dup;
	authctxt->nprev_ಕೀಲಿಗಳು++;

}

/* Checks whether a key has already been previously used for authentication */
ಪೂರ್ಣಾಙ್ಕ
auth2_ಕೀಲಿ_already_used(Authctxt *authctxt, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	u_int i;
	ವರ್ಣ *fp;

	ಪ್ರತಿ (i = 0; i < authctxt->nprev_ಕೀಲಿಗಳು; i++) {
		ಯದಿ (sshkey_equal_public(ಕೀಲಿ, authctxt->prev_ಕೀಲಿಗಳು[i])) {
			fp = sshkey_fingerprint(authctxt->prev_ಕೀಲಿಗಳು[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_ಕೀಲಿಗಳು[i]),
			    fp == ರಿಕ್ತ ? "UNKNOWN" : fp);
			ಮುಕ್ತ(fp);
			ಪ್ರತ್ಯಾಗಮ 1;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
ಶೂನ್ಯ
auth2_update_session_info(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *method,
    ಧ್ರುವ ವರ್ಣ *submethod)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt->session_info == ರಿಕ್ತ) {
		ಯದಿ ((authctxt->session_info = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	ಯದಿ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    method, submethod == ರಿಕ್ತ ? "" : "/",
	    submethod == ರಿಕ್ತ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	ಯದಿ (authctxt->auth_method_ಕೀಲಿ != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_text(authctxt->auth_method_ಕೀಲಿ,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	ಯದಿ (authctxt->auth_method_info != ರಿಕ್ತ) {
		/* Ensure no ambiguity here */
		ಯದಿ (strchr(authctxt->auth_method_info, '\n') != ರಿಕ್ತ)
			fatal_f("auth_method_info contains \\n");
		ಯದಿ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_method_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	ಯದಿ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

