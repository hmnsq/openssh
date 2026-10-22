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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "kex.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;

/* methods */

ಬಾಹ್ಯ Authmethod ವಿಧಾನ_none;
ಬಾಹ್ಯ Authmethod ವಿಧಾನ_pubkey;
ಬಾಹ್ಯ Authmethod ವಿಧಾನ_passwd;
ಬಾಹ್ಯ Authmethod ವಿಧಾನ_kbdint;
ಬಾಹ್ಯ Authmethod ವಿಧಾನ_hostbased;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಬಾಹ್ಯ Authmethod ವಿಧಾನ_gssapi;
#ಆದರೆ_ಅಂತ್ಯ

Authmethod *authmethods[] = {
	&ವಿಧಾನ_none,
	&ವಿಧಾನ_pubkey,
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	&ವಿಧಾನ_gssapi,
#ಆದರೆ_ಅಂತ್ಯ
	&ವಿಧಾನ_passwd,
	&ವಿಧಾನ_kbdint,
	&ವಿಧಾನ_hostbased,
	ಖಾಲಿ
};

/* protocol */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_service_request(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_request(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

/* helper */
ಸ್ಥಿರ Authmethod *authmethod_byname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರ Authmethod *authmethod_lookup(Authctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರ ಅಕ್ಷರ *authmethods_get(Authctxt *authctxt);

#ವ್ಯಾಖ್ಯಾನಿಸು ಹೊಂದಿಕೆ_NONE	0	/* method or submethod mismatch */
#ವ್ಯಾಖ್ಯಾನಿಸು ಹೊಂದಿಕೆ_ವಿಧಾನ	1	/* method matches (no submethod specified) */
#ವ್ಯಾಖ್ಯಾನಿಸು ಹೊಂದಿಕೆ_BOTH	2	/* method and submethod match */
#ವ್ಯಾಖ್ಯಾನಿಸು ಹೊಂದಿಕೆ_PARTIAL	3	/* method matches, submethod can't be checked */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ list_starts_with(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಅಕ್ಷರ *
auth2_read_banner(ಶೂನ್ಯ)
{
	ರಚನೆ stat st;
	ಅಕ್ಷರ *banner = ಖಾಲಿ;
	ಗಾತ್ರ_t len, n;
	ಪೂರ್ಣಾಂಕ fd;

	ಆದರೆ ((fd = open(options.banner, O_RDONLY)) == -1)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	ಆದರೆ (fstat(fd, &st) == -1) {
		close(fd);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	ಆದರೆ (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	len = (ಗಾತ್ರ_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(ಪಠ, fd, banner, len);
	close(fd);

	ಆದರೆ (n != len) {
		ಬಿಡುಗಡೆ(banner);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	banner[n] = '\0';

	ಹಿಂತಿರುಗಿ (banner);
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_send_banner(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ಸಂದೇಶ)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_banner(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *banner = ಖಾಲಿ;

	ಆದರೆ (options.banner == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ ((banner = mm_auth2_read_banner()) == ಖಾಲಿ)
		ಹೋಗು ಮುಗಿದ;
	userauth_send_banner(ssh, banner);

ಮುಗಿದ:
	ಬಿಡುಗಡೆ(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
ಶೂನ್ಯ
do_authentication2(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ಆದರೆ (ssh->kex->ext_info_c)
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_SERVICE_REQUEST, &ಒಳಹರಿವು_service_request);
	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_ಖಂಡ, &authctxt->success);
	ssh->authctxt = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_service_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಅಕ್ಷರ *service = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, acceptit = 0;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &service, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_service_request: no authctxt");

	ಆದರೆ (strcmp(service, "ssh-userauth") == 0) {
		ಆದರೆ (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
			    &ಒಳಹರಿವು_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	ಆದರೆ (acceptit) {
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(service);
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿಸು MIN_FAIL_DELAY_SECONDS 0.005
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_FAIL_DELAY_SECONDS 5.0
ಸ್ಥಿರ ದ್ವಿಗುಣ
user_specific_delay(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	ಅಕ್ಷರ b[512];
	ಗಾತ್ರ_t len = ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	ದ್ವಿಗುಣ delay;

	(ಶೂನ್ಯ)snprintf(b, ಗಾತ್ರ b, "%llu%s",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)options.timing_secret, user);
	ಆದರೆ (ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA512, b, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (ದ್ವಿಗುಣ)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	ಹಿಂತಿರುಗಿ MIN_FAIL_DELAY_SECONDS + delay;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ensure_minimum_ಸಮಯ_since(ದ್ವಿಗುಣ ಆರಂಭ, ದ್ವಿಗುಣ seconds)
{
	ರಚನೆ timespec ts;
	ದ್ವಿಗುಣ elapsed = monotime_double() - ಆರಂಭ, req = seconds, remain;

	ಆದರೆ (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		ಹಿಂತಿರುಗಿ;
	}

	/* if we've already passed the requested time, scale up */
	ಆಗ ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, ಖಾಲಿ);
}

ಶೂನ್ಯ
auth_failure_delay(Authctxt *authctxt, ದ್ವಿಗುಣ tstart)
{
	ensure_minimum_ಸಮಯ_since(tstart, user_specific_delay(authctxt->user));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ಖಾಲಿ;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *service = ಖಾಲಿ, *ವಿಧಾನ = ಖಾಲಿ, *style = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, authenticated = 0;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_userauth_request: no authctxt");

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &user, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &ವಿಧಾನ, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug("userauth-request for user %s service %s method %s", user, service, ವಿಧಾನ);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	ಆದರೆ ((style = strchr(user, ':')) != ಖಾಲಿ)
		*style++ = 0;

	ಆದರೆ (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	ಆದರೆ (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : ಖಾಲಿ;
		ಆದರೆ (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} ಇಲ್ಲದಿದ್ದರೆ {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#ಆದರೆ_ಅಂತ್ಯ
		}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
		ಆದರೆ (options.use_pam)
			mm_ಆರಂಭ_pam(ssh);
#ಆದರೆ_ಅಂತ್ಯ
		ssh_packet_ಗಣ_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		ಆದರೆ ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		ಆದರೆ (auth2_ಸಿದ್ಧತೆ_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, ವಿಧಾನ);
	ಆದರೆ (m != ಖಾಲಿ && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", ವಿಧಾನ);
		authenticated =	m->userauth(ssh, ವಿಧಾನ);
	}
	ಆದರೆ (!authctxt->authenticated && strcmp(ವಿಧಾನ, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_ಮುಕ್ತಾಯ(ssh, authenticated, ವಿಧಾನ, ಖಾಲಿ);
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(service);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(ವಿಧಾನ);
	ಹಿಂತಿರುಗಿ r;
}

ಶೂನ್ಯ
userauth_ಮುಕ್ತಾಯ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ authenticated, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *packet_ವಿಧಾನ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ = packet_ವಿಧಾನ;
	ಅಕ್ಷರ *methods;
	ಪೂರ್ಣಾಂಕ r, partial = 0;

	ಆದರೆ (authenticated) {
		ಆದರೆ (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		ಆದರೆ (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		ಆದರೆ ((m = authmethod_byname(ವಿಧಾನ)) == ಖಾಲಿ)
			fatal("INTERNAL ERROR: bad method %s", ವಿಧಾನ);
		ವಿಧಾನ = m->cfg->name;
	}

	/* Special handling for root */
	ಆದರೆ (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_ಬೇರು_allowed(ssh, ವಿಧಾನ)) {
		authenticated = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_ಬೇರು_DENIED);
#ಆದರೆ_ಅಂತ್ಯ
	}

	ಆದರೆ (authenticated && options.ಅಂಕೆ_auth_methods != 0) {
		ಆದರೆ (!auth2_update_methods_lists(authctxt, ವಿಧಾನ, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, ವಿಧಾನ, submethod);

	/* Update information exposed to session */
	ಆದರೆ (authenticated || partial)
		auth2_update_session_info(authctxt, ವಿಧಾನ, submethod);

	ಆದರೆ (authctxt->postponed)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam && authenticated) {
		ಪೂರ್ಣಾಂಕ r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		ಆದರೆ (sshbuf_len(loginmsg) > 0) {
			ಆದರೆ ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			ಆದರೆ ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		ಆದರೆ (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_ಗಣ_log_preamble(ssh, "user %s", authctxt->user);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Allow initial try of "none" auth without failure penalty */
		ಆದರೆ (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(ವಿಧಾನ, "none") != 0))
			authctxt->failures++;
		ಆದರೆ (authctxt->failures >= options.max_authtries) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#ಆದರೆ_ಅಂತ್ಯ
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		ಬಿಡುಗಡೆ(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
ಪೂರ್ಣಾಂಕ
auth2_ವಿಧಾನ_allowed(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	ಆದರೆ (options.ಅಂಕೆ_auth_methods == 0)
		ಹಿಂತಿರುಗಿ 1;
	ಗಾಗಿ (i = 0; i < authctxt->ಅಂಕೆ_auth_methods; i++) {
		ಆದರೆ (list_starts_with(authctxt->auth_methods[i], ವಿಧಾನ,
		    submethod) != ಹೊಂದಿಕೆ_NONE)
			ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
authmethods_get(Authctxt *authctxt)
{
	ರಚನೆ sshbuf *b;
	ಅಕ್ಷರ *list;
	ಪೂರ್ಣಾಂಕ i, r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಗಾಗಿ (i = 0; authmethods[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (strcmp(authmethods[i]->cfg->name, "none") == 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (authmethods[i]->cfg->enabled == ಖಾಲಿ ||
		    *(authmethods[i]->cfg->enabled) == 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (!auth2_ವಿಧಾನ_allowed(authctxt, authmethods[i]->cfg->name,
		    ಖಾಲಿ))
			ಮುಂದುವರಿ;
		ಆದರೆ ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	ಆದರೆ ((list = sshbuf_dup_string(b)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ list;
}

ಸ್ಥಿರ Authmethod *
authmethod_byname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (name == ಖಾಲಿ)
		fatal_f("NULL authentication method name");
	ಗಾಗಿ (i = 0; authmethods[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != ಖಾಲಿ &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			ಹಿಂತಿರುಗಿ authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ Authmethod *
authmethod_lookup(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	Authmethod *ವಿಧಾನ;

	ಆದರೆ ((ವಿಧಾನ = authmethod_byname(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆದರೆ (ವಿಧಾನ->cfg->enabled == ಖಾಲಿ || *(ವಿಧಾನ->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (!auth2_ವಿಧಾನ_allowed(authctxt, ವಿಧಾನ->cfg->name, ಖಾಲಿ)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ವಿಧಾನ;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
ಪೂರ್ಣಾಂಕ
auth2_ಸಿದ್ಧತೆ_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	ಆದರೆ (options.ಅಂಕೆ_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		ಬಿಡುಗಡೆ(options.auth_methods[0]);
		options.auth_methods[0] = ಖಾಲಿ;
		options.ಅಂಕೆ_auth_methods = 0;
	}

	ಆದರೆ (options.ಅಂಕೆ_auth_methods == 0)
		ಹಿಂತಿರುಗಿ 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.ಅಂಕೆ_auth_methods,
	    ಗಾತ್ರ(*authctxt->auth_methods));
	authctxt->ಅಂಕೆ_auth_methods = 0;
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_auth_methods; i++) {
		ಆದರೆ (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			ಮುಂದುವರಿ;
		}
		debug("authentication methods list %d: %s",
		    authctxt->ಅಂಕೆ_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->ಅಂಕೆ_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	ಆದರೆ (authctxt->ಅಂಕೆ_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
list_starts_with(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *methods, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	ಗಾತ್ರ_t l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ವಿಧಾನ);
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p;

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(methods, ವಿಧಾನ, l) != 0)
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_NONE;
	p = methods + l;
	ಹೊಂದಿಕೆ = ಹೊಂದಿಕೆ_ವಿಧಾನ;
	ಆದರೆ (*p == ':') {
		ಆದರೆ (!submethod)
			ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_PARTIAL;
		l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(submethod);
		p += 1;
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(submethod, p, l))
			ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_NONE;
		p += l;
		ಹೊಂದಿಕೆ = ಹೊಂದಿಕೆ_BOTH;
	}
	ಆದರೆ (*p != ',' && *p != '\0')
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_NONE;
	ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
remove_ವಿಧಾನ(ಅಕ್ಷರ **methods, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	ಅಕ್ಷರ *omethods = *methods, *p;
	ಗಾತ್ರ_t l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ವಿಧಾನ);
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ;

	ಹೊಂದಿಕೆ = list_starts_with(omethods, ವಿಧಾನ, submethod);
	ಆದರೆ (ಹೊಂದಿಕೆ != ಹೊಂದಿಕೆ_ವಿಧಾನ && ಹೊಂದಿಕೆ != ಹೊಂದಿಕೆ_BOTH)
		ಹಿಂತಿರುಗಿ 0;
	p = omethods + l;
	ಆದರೆ (submethod && ಹೊಂದಿಕೆ == ಹೊಂದಿಕೆ_BOTH)
		p += 1 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(submethod); /* include colon */
	ಆದರೆ (*p == ',')
		p++;
	*methods = xstrdup(p);
	ಬಿಡುಗಡೆ(omethods);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
ಪೂರ್ಣಾಂಕ
auth2_update_methods_lists(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	u_int i, ಸಿಕ್ಕಿತು = 0;

	debug3_f("updating methods list after \"%s\"", ವಿಧಾನ);
	ಗಾಗಿ (i = 0; i < authctxt->ಅಂಕೆ_auth_methods; i++) {
		ಆದರೆ (!remove_ವಿಧಾನ(&(authctxt->auth_methods[i]), ವಿಧಾನ,
		    submethod))
			ಮುಂದುವರಿ;
		ಸಿಕ್ಕಿತು = 1;
		ಆದರೆ (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			ಹಿಂತಿರುಗಿ 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	ಆದರೆ (!ಸಿಕ್ಕಿತು)
		fatal_f("method not in AuthenticationMethods");
	ಹಿಂತಿರುಗಿ 0;
}

/* Reset method-specific information */
ಶೂನ್ಯ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_ವಿಧಾನ_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(authctxt->auth_ವಿಧಾನ_info);
	authctxt->auth_ವಿಧಾನ_ಕೀಲಿ = ಖಾಲಿ;
	authctxt->auth_ವಿಧಾನ_info = ಖಾಲಿ;
}

/* Record auth method-specific information for logs */
ಶೂನ್ಯ
auth2_ದಾಖಲೆ_info(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಂಕ i;

	ಬಿಡುಗಡೆ(authctxt->auth_ವಿಧಾನ_info);
	authctxt->auth_ವಿಧಾನ_info = ಖಾಲಿ;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_ವಿಧಾನ_info, fmt, ap);
	va_end(ap);

	ಆದರೆ (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
ಶೂನ್ಯ
auth2_ದಾಖಲೆ_ಕೀಲಿ(Authctxt *authctxt, ಪೂರ್ಣಾಂಕ authenticated,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ sshkey **tmp, *dup;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಕೀಲಿ, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_ವಿಧಾನ_ಕೀಲಿ);
	authctxt->auth_ವಿಧಾನ_ಕೀಲಿ = dup;

	ಆದರೆ (!authenticated)
		ಹಿಂತಿರುಗಿ;

	/* If authenticated, make sure we don't accept this key again */
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಕೀಲಿ, &dup)) != 0)
		fatal_fr(r, "copy key");
	ಆದರೆ (authctxt->nprev_ಕೀಲಿಗಳು >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ ||
	    (tmp = recallocarray(authctxt->prev_ಕೀಲಿಗಳು, authctxt->nprev_ಕೀಲಿಗಳು,
	    authctxt->nprev_ಕೀಲಿಗಳು + 1, ಗಾತ್ರ(*authctxt->prev_ಕೀಲಿಗಳು))) == ಖಾಲಿ)
		fatal_f("reallocarray failed");
	authctxt->prev_ಕೀಲಿಗಳು = tmp;
	authctxt->prev_ಕೀಲಿಗಳು[authctxt->nprev_ಕೀಲಿಗಳು] = dup;
	authctxt->nprev_ಕೀಲಿಗಳು++;

}

/* Checks whether a key has already been previously used for authentication */
ಪೂರ್ಣಾಂಕ
auth2_ಕೀಲಿ_already_ಬಳಸಿದ(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	u_int i;
	ಅಕ್ಷರ *fp;

	ಗಾಗಿ (i = 0; i < authctxt->nprev_ಕೀಲಿಗಳು; i++) {
		ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ, authctxt->prev_ಕೀಲಿಗಳು[i])) {
			fp = sshkey_fingerprint(authctxt->prev_ಕೀಲಿಗಳು[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_ಕೀಲಿಗಳು[i]),
			    fp == ಖಾಲಿ ? "UNKNOWN" : fp);
			ಬಿಡುಗಡೆ(fp);
			ಹಿಂತಿರುಗಿ 1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
ಶೂನ್ಯ
auth2_update_session_info(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt->session_info == ಖಾಲಿ) {
		ಆದರೆ ((authctxt->session_info = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	ಆದರೆ ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    ವಿಧಾನ, submethod == ಖಾಲಿ ? "" : "/",
	    submethod == ಖಾಲಿ ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	ಆದರೆ (authctxt->auth_ವಿಧಾನ_ಕೀಲಿ != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_ಪಠ್ಯ(authctxt->auth_ವಿಧಾನ_ಕೀಲಿ,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	ಆದರೆ (authctxt->auth_ವಿಧಾನ_info != ಖಾಲಿ) {
		/* Ensure no ambiguity here */
		ಆದರೆ (strchr(authctxt->auth_ವಿಧಾನ_info, '\n') != ಖಾಲಿ)
			fatal_f("auth_method_info contains \\n");
		ಆದರೆ ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_ವಿಧಾನ_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	ಆದರೆ ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

