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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "stdlib.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"

/* import */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;

/* methods */

ਬਾਹਰੀ Authmethod ਵਿਧੀ_none;
ਬਾਹਰੀ Authmethod ਵਿਧੀ_pubkey;
ਬਾਹਰੀ Authmethod ਵਿਧੀ_passwd;
ਬਾਹਰੀ Authmethod ਵਿਧੀ_kbdint;
ਬਾਹਰੀ Authmethod ਵਿਧੀ_hostbased;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਬਾਹਰੀ Authmethod ਵਿਧੀ_gssapi;
#ਜੇ_ਅੰਤ

Authmethod *authmethods[] = {
	&ਵਿਧੀ_none,
	&ਵਿਧੀ_pubkey,
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	&ਵਿਧੀ_gssapi,
#ਜੇ_ਅੰਤ
	&ਵਿਧੀ_passwd,
	&ਵਿਧੀ_kbdint,
	&ਵਿਧੀ_hostbased,
	ਨਿਰਾ
};

/* protocol */

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_service_request(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_request(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

/* helper */
ਸਥਿਰ Authmethod *authmethod_byname(ਅਚਲ ਅੱਖਰ *);
ਸਥਿਰ Authmethod *authmethod_lookup(Authctxt *, ਅਚਲ ਅੱਖਰ *);
ਸਥਿਰ ਅੱਖਰ *authmethods_get(Authctxt *authctxt);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੇਲ_NONE	0	/* method or submethod mismatch */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੇਲ_ਵਿਧੀ	1	/* method matches (no submethod specified) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੇਲ_BOTH	2	/* method and submethod match */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੇਲ_PARTIAL	3	/* method matches, submethod can't be checked */
ਸਥਿਰ ਪੂਰਨ list_starts_with(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

ਅੱਖਰ *
auth2_read_banner(ਖਾਲੀ)
{
	ਬਣਤਰ stat st;
	ਅੱਖਰ *banner = ਨਿਰਾ;
	ਮਾਪ_t len, n;
	ਪੂਰਨ fd;

	ਜੇ ((fd = open(options.banner, O_RDONLY)) == -1)
		ਵਾਪਸ (ਨਿਰਾ);
	ਜੇ (fstat(fd, &st) == -1) {
		close(fd);
		ਵਾਪਸ (ਨਿਰਾ);
	}
	ਜੇ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	len = (ਮਾਪ_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(ਪਠ, fd, banner, len);
	close(fd);

	ਜੇ (n != len) {
		ਮੁਕਤ(banner);
		ਵਾਪਸ (ਨਿਰਾ);
	}
	banner[n] = '\0';

	ਵਾਪਸ (banner);
}

ਸਥਿਰ ਖਾਲੀ
userauth_send_banner(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ਸੁਨੇਹਾ)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ਸਥਿਰ ਖਾਲੀ
userauth_banner(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *banner = ਨਿਰਾ;

	ਜੇ (options.banner == ਨਿਰਾ)
		ਵਾਪਸ;

	ਜੇ ((banner = mm_auth2_read_banner()) == ਨਿਰਾ)
		ਜਾਓ ਪੂਰਾ;
	userauth_send_banner(ssh, banner);

ਪੂਰਾ:
	ਮੁਕਤ(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
ਖਾਲੀ
do_authentication2(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ਜੇ (ssh->kex->ext_info_c)
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, &kex_ਨਿਵੇਸ਼_ext_info);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_SERVICE_REQUEST, &ਨਿਵੇਸ਼_service_request);
	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_ਖੰਡ, &authctxt->success);
	ssh->authctxt = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_service_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਅੱਖਰ *service = ਨਿਰਾ;
	ਪੂਰਨ r, acceptit = 0;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &service, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_service_request: no authctxt");

	ਜੇ (strcmp(service, "ssh-userauth") == 0) {
		ਜੇ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST,
			    &ਨਿਵੇਸ਼_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	ਜੇ (acceptit) {
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(service);
	ਵਾਪਸ r;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MIN_FAIL_DELAY_SECONDS 0.005
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_FAIL_DELAY_SECONDS 5.0
ਸਥਿਰ ਦੁੱਗਣਾ
user_specific_delay(ਅਚਲ ਅੱਖਰ *user)
{
	ਅੱਖਰ b[512];
	ਮਾਪ_t len = ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ਦੁੱਗਣਾ delay;

	(ਖਾਲੀ)snprintf(b, ਆਕਾਰ b, "%llu%s",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)options.timing_secret, user);
	ਜੇ (ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA512, b, ਲੜੀ_ਲੰਬਾਈ(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ਦੁੱਗਣਾ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ਵਾਪਸ MIN_FAIL_DELAY_SECONDS + delay;
}

ਸਥਿਰ ਖਾਲੀ
ensure_minimum_ਸਮਾਂ_since(ਦੁੱਗਣਾ ਸ਼ੁਰੂ, ਦੁੱਗਣਾ seconds)
{
	ਬਣਤਰ timespec ts;
	ਦੁੱਗਣਾ elapsed = monotime_double() - ਸ਼ੁਰੂ, req = seconds, remain;

	ਜੇ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ਵਾਪਸ;
	}

	/* if we've already passed the requested time, scale up */
	ਜਦੋਂ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ਨਿਰਾ);
}

ਖਾਲੀ
auth_failure_delay(Authctxt *authctxt, ਦੁੱਗਣਾ tstart)
{
	ensure_minimum_ਸਮਾਂ_since(tstart, user_specific_delay(authctxt->user));
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ਨਿਰਾ;
	ਅੱਖਰ *user = ਨਿਰਾ, *service = ਨਿਰਾ, *ਵਿਧੀ = ਨਿਰਾ, *style = ਨਿਰਾ;
	ਪੂਰਨ r, authenticated = 0;
	ਦੁੱਗਣਾ tstart = monotime_double();

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_userauth_request: no authctxt");

	ਜੇ ((r = sshpkt_get_cstring(ssh, &user, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &ਵਿਧੀ, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug("userauth-request for user %s service %s method %s", user, service, ਵਿਧੀ);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	ਜੇ ((style = strchr(user, ':')) != ਨਿਰਾ)
		*style++ = 0;

	ਜੇ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	ਜੇ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ਨਿਰਾ;
		ਜੇ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} ਨਹੀਂਤਾਂ {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#ਜੇ_ਅੰਤ
		}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
		ਜੇ (options.use_pam)
			mm_ਸ਼ੁਰੂ_pam(ssh);
#ਜੇ_ਅੰਤ
		ssh_packet_ਸੈੱਟ_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		ਜੇ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		ਜੇ (auth2_ਤਿਆਰੀ_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ਨਿਰਾ);
#ਜੇ_ਅੰਤ

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, ਵਿਧੀ);
	ਜੇ (m != ਨਿਰਾ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", ਵਿਧੀ);
		authenticated =	m->userauth(ssh, ਵਿਧੀ);
	}
	ਜੇ (!authctxt->authenticated && strcmp(ਵਿਧੀ, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_ਅੰਤ(ssh, authenticated, ਵਿਧੀ, ਨਿਰਾ);
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(service);
	ਮੁਕਤ(user);
	ਮੁਕਤ(ਵਿਧੀ);
	ਵਾਪਸ r;
}

ਖਾਲੀ
userauth_ਅੰਤ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ authenticated, ਅਚਲ ਅੱਖਰ *packet_ਵਿਧੀ,
    ਅਚਲ ਅੱਖਰ *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ਵਿਧੀ = packet_ਵਿਧੀ;
	ਅੱਖਰ *methods;
	ਪੂਰਨ r, partial = 0;

	ਜੇ (authenticated) {
		ਜੇ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		ਜੇ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		ਜੇ ((m = authmethod_byname(ਵਿਧੀ)) == ਨਿਰਾ)
			fatal("INTERNAL ERROR: bad method %s", ਵਿਧੀ);
		ਵਿਧੀ = m->cfg->name;
	}

	/* Special handling for root */
	ਜੇ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_ਜੜ੍ਹ_allowed(ssh, ਵਿਧੀ)) {
		authenticated = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ਜੜ੍ਹ_DENIED);
#ਜੇ_ਅੰਤ
	}

	ਜੇ (authenticated && options.ਅੰਕ_auth_methods != 0) {
		ਜੇ (!auth2_update_methods_lists(authctxt, ਵਿਧੀ, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, ਵਿਧੀ, submethod);

	/* Update information exposed to session */
	ਜੇ (authenticated || partial)
		auth2_update_session_info(authctxt, ਵਿਧੀ, submethod);

	ਜੇ (authctxt->postponed)
		ਵਾਪਸ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam && authenticated) {
		ਪੂਰਨ r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		ਜੇ (sshbuf_len(loginmsg) > 0) {
			ਜੇ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			ਜੇ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		ਜੇ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#ਜੇ_ਅੰਤ

	ਜੇ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_ਸੈੱਟ_log_preamble(ssh, "user %s", authctxt->user);
	} ਨਹੀਂਤਾਂ {
		/* Allow initial try of "none" auth without failure penalty */
		ਜੇ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(ਵਿਧੀ, "none") != 0))
			authctxt->failures++;
		ਜੇ (authctxt->failures >= options.max_authtries) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#ਜੇ_ਅੰਤ
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		ਮੁਕਤ(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
ਪੂਰਨ
auth2_ਵਿਧੀ_allowed(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ,
    ਅਚਲ ਅੱਖਰ *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	ਜੇ (options.ਅੰਕ_auth_methods == 0)
		ਵਾਪਸ 1;
	ਲਈ (i = 0; i < authctxt->ਅੰਕ_auth_methods; i++) {
		ਜੇ (list_starts_with(authctxt->auth_methods[i], ਵਿਧੀ,
		    submethod) != ਮੇਲ_NONE)
			ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅੱਖਰ *
authmethods_get(Authctxt *authctxt)
{
	ਬਣਤਰ sshbuf *b;
	ਅੱਖਰ *list;
	ਪੂਰਨ i, r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਲਈ (i = 0; authmethods[i] != ਨਿਰਾ; i++) {
		ਜੇ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ਜਾਰੀ;
		ਜੇ (authmethods[i]->cfg->enabled == ਨਿਰਾ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ਜਾਰੀ;
		ਜੇ (!auth2_ਵਿਧੀ_allowed(authctxt, authmethods[i]->cfg->name,
		    ਨਿਰਾ))
			ਜਾਰੀ;
		ਜੇ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	ਜੇ ((list = sshbuf_dup_string(b)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ਵਾਪਸ list;
}

ਸਥਿਰ Authmethod *
authmethod_byname(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ i;

	ਜੇ (name == ਨਿਰਾ)
		fatal_f("NULL authentication method name");
	ਲਈ (i = 0; authmethods[i] != ਨਿਰਾ; i++) {
		ਜੇ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ਨਿਰਾ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ਵਾਪਸ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ Authmethod *
authmethod_lookup(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *name)
{
	Authmethod *ਵਿਧੀ;

	ਜੇ ((ਵਿਧੀ = authmethod_byname(name)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	ਜੇ (ਵਿਧੀ->cfg->enabled == ਨਿਰਾ || *(ਵਿਧੀ->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (!auth2_ਵਿਧੀ_allowed(authctxt, ਵਿਧੀ->cfg->name, ਨਿਰਾ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ਵਿਧੀ;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
ਪੂਰਨ
auth2_ਤਿਆਰੀ_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	ਜੇ (options.ਅੰਕ_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		ਮੁਕਤ(options.auth_methods[0]);
		options.auth_methods[0] = ਨਿਰਾ;
		options.ਅੰਕ_auth_methods = 0;
	}

	ਜੇ (options.ਅੰਕ_auth_methods == 0)
		ਵਾਪਸ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.ਅੰਕ_auth_methods,
	    ਆਕਾਰ(*authctxt->auth_methods));
	authctxt->ਅੰਕ_auth_methods = 0;
	ਲਈ (i = 0; i < options.ਅੰਕ_auth_methods; i++) {
		ਜੇ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ਜਾਰੀ;
		}
		debug("authentication methods list %d: %s",
		    authctxt->ਅੰਕ_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->ਅੰਕ_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	ਜੇ (authctxt->ਅੰਕ_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
list_starts_with(ਅਚਲ ਅੱਖਰ *methods, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ,
    ਅਚਲ ਅੱਖਰ *submethod)
{
	ਮਾਪ_t l = ਲੜੀ_ਲੰਬਾਈ(ਵਿਧੀ);
	ਪੂਰਨ ਮੇਲ;
	ਅਚਲ ਅੱਖਰ *p;

	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(methods, ਵਿਧੀ, l) != 0)
		ਵਾਪਸ ਮੇਲ_NONE;
	p = methods + l;
	ਮੇਲ = ਮੇਲ_ਵਿਧੀ;
	ਜੇ (*p == ':') {
		ਜੇ (!submethod)
			ਵਾਪਸ ਮੇਲ_PARTIAL;
		l = ਲੜੀ_ਲੰਬਾਈ(submethod);
		p += 1;
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(submethod, p, l))
			ਵਾਪਸ ਮੇਲ_NONE;
		p += l;
		ਮੇਲ = ਮੇਲ_BOTH;
	}
	ਜੇ (*p != ',' && *p != '\0')
		ਵਾਪਸ ਮੇਲ_NONE;
	ਵਾਪਸ ਮੇਲ;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ਸਥਿਰ ਪੂਰਨ
remove_ਵਿਧੀ(ਅੱਖਰ **methods, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ, ਅਚਲ ਅੱਖਰ *submethod)
{
	ਅੱਖਰ *omethods = *methods, *p;
	ਮਾਪ_t l = ਲੜੀ_ਲੰਬਾਈ(ਵਿਧੀ);
	ਪੂਰਨ ਮੇਲ;

	ਮੇਲ = list_starts_with(omethods, ਵਿਧੀ, submethod);
	ਜੇ (ਮੇਲ != ਮੇਲ_ਵਿਧੀ && ਮੇਲ != ਮੇਲ_BOTH)
		ਵਾਪਸ 0;
	p = omethods + l;
	ਜੇ (submethod && ਮੇਲ == ਮੇਲ_BOTH)
		p += 1 + ਲੜੀ_ਲੰਬਾਈ(submethod); /* include colon */
	ਜੇ (*p == ',')
		p++;
	*methods = xstrdup(p);
	ਮੁਕਤ(omethods);
	ਵਾਪਸ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
ਪੂਰਨ
auth2_update_methods_lists(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ,
    ਅਚਲ ਅੱਖਰ *submethod)
{
	u_int i, ਮਿਲਿਆ = 0;

	debug3_f("updating methods list after \"%s\"", ਵਿਧੀ);
	ਲਈ (i = 0; i < authctxt->ਅੰਕ_auth_methods; i++) {
		ਜੇ (!remove_ਵਿਧੀ(&(authctxt->auth_methods[i]), ਵਿਧੀ,
		    submethod))
			ਜਾਰੀ;
		ਮਿਲਿਆ = 1;
		ਜੇ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ਵਾਪਸ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	ਜੇ (!ਮਿਲਿਆ)
		fatal_f("method not in AuthenticationMethods");
	ਵਾਪਸ 0;
}

/* Reset method-specific information */
ਖਾਲੀ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ);
	ਮੁਕਤ(authctxt->auth_ਵਿਧੀ_info);
	authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ = ਨਿਰਾ;
	authctxt->auth_ਵਿਧੀ_info = ਨਿਰਾ;
}

/* Record auth method-specific information for logs */
ਖਾਲੀ
auth2_ਰਿਕਾਰਡ_info(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਪੂਰਨ i;

	ਮੁਕਤ(authctxt->auth_ਵਿਧੀ_info);
	authctxt->auth_ਵਿਧੀ_info = ਨਿਰਾ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_ਵਿਧੀ_info, fmt, ap);
	va_end(ap);

	ਜੇ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
ਖਾਲੀ
auth2_ਰਿਕਾਰਡ_ਕੁੰਜੀ(Authctxt *authctxt, ਪੂਰਨ authenticated,
    ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ sshkey **tmp, *dup;
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਕੁੰਜੀ, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ);
	authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ = dup;

	ਜੇ (!authenticated)
		ਵਾਪਸ;

	/* If authenticated, make sure we don't accept this key again */
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਕੁੰਜੀ, &dup)) != 0)
		fatal_fr(r, "copy key");
	ਜੇ (authctxt->nprev_ਕੁੰਜੀਆਂ >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ ||
	    (tmp = recallocarray(authctxt->prev_ਕੁੰਜੀਆਂ, authctxt->nprev_ਕੁੰਜੀਆਂ,
	    authctxt->nprev_ਕੁੰਜੀਆਂ + 1, ਆਕਾਰ(*authctxt->prev_ਕੁੰਜੀਆਂ))) == ਨਿਰਾ)
		fatal_f("reallocarray failed");
	authctxt->prev_ਕੁੰਜੀਆਂ = tmp;
	authctxt->prev_ਕੁੰਜੀਆਂ[authctxt->nprev_ਕੁੰਜੀਆਂ] = dup;
	authctxt->nprev_ਕੁੰਜੀਆਂ++;

}

/* Checks whether a key has already been previously used for authentication */
ਪੂਰਨ
auth2_ਕੁੰਜੀ_already_ਵਰਤਿਆ(Authctxt *authctxt, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	u_int i;
	ਅੱਖਰ *fp;

	ਲਈ (i = 0; i < authctxt->nprev_ਕੁੰਜੀਆਂ; i++) {
		ਜੇ (sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ, authctxt->prev_ਕੁੰਜੀਆਂ[i])) {
			fp = sshkey_fingerprint(authctxt->prev_ਕੁੰਜੀਆਂ[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_ਕੁੰਜੀਆਂ[i]),
			    fp == ਨਿਰਾ ? "UNKNOWN" : fp);
			ਮੁਕਤ(fp);
			ਵਾਪਸ 1;
		}
	}
	ਵਾਪਸ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
ਖਾਲੀ
auth2_update_session_info(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ,
    ਅਚਲ ਅੱਖਰ *submethod)
{
	ਪੂਰਨ r;

	ਜੇ (authctxt->session_info == ਨਿਰਾ) {
		ਜੇ ((authctxt->session_info = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	ਜੇ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    ਵਿਧੀ, submethod == ਨਿਰਾ ? "" : "/",
	    submethod == ਨਿਰਾ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	ਜੇ (authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_ਪਾਠ(authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	ਜੇ (authctxt->auth_ਵਿਧੀ_info != ਨਿਰਾ) {
		/* Ensure no ambiguity here */
		ਜੇ (strchr(authctxt->auth_ਵਿਧੀ_info, '\n') != ਨਿਰਾ)
			fatal_f("auth_method_info contains \\n");
		ਜੇ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_ਵਿਧੀ_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	ਜੇ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

