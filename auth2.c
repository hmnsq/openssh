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
#جے_تعریف_شدہ GSSAPI
#ضمن "ssh-gss.h"
#جے_انت
#ضمن "monitor_wrap.h"
#ضمن "digest.h"
#ضمن "kex.h"

/* import */
خارجي ServerOptions options;
خارجي بنية sshbuf *loginmsg;

/* methods */

خارجي Authmethod طریقہ_none;
خارجي Authmethod طریقہ_pubkey;
خارجي Authmethod طریقہ_passwd;
خارجي Authmethod طریقہ_kbdint;
خارجي Authmethod طریقہ_hostbased;
#جے_تعریف_شدہ GSSAPI
خارجي Authmethod طریقہ_gssapi;
#جے_انت

Authmethod *authmethods[] = {
	&طریقہ_none,
	&طریقہ_pubkey,
#جے_تعریف_شدہ GSSAPI
	&طریقہ_gssapi,
#جے_انت
	&طریقہ_passwd,
	&طریقہ_kbdint,
	&طریقہ_hostbased,
	عدم
};

/* protocol */

ساكن صحيح داخلہ_service_request(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_request(صحيح, uint32_t, بنية ssh *);

/* helper */
ساكن Authmethod *authmethod_byname(ثابت حرف *);
ساكن Authmethod *authmethod_lookup(Authctxt *, ثابت حرف *);
ساكن حرف *authmethods_get(Authctxt *authctxt);

#تعریف_کرو میل_NONE	0	/* method or submethod mismatch */
#تعریف_کرو میل_طریقہ	1	/* method matches (no submethod specified) */
#تعریف_کرو میل_BOTH	2	/* method and submethod match */
#تعریف_کرو میل_PARTIAL	3	/* method matches, submethod can't be checked */
ساكن صحيح list_starts_with(ثابت حرف *, ثابت حرف *, ثابت حرف *);

حرف *
auth2_read_banner(فراغ)
{
	بنية stat st;
	حرف *banner = عدم;
	ناپ_t len, n;
	صحيح fd;

	إذا ((fd = open(options.banner, O_RDONLY)) == -1)
		أرجع (عدم);
	إذا (fstat(fd, &st) == -1) {
		close(fd);
		أرجع (عدم);
	}
	إذا (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		أرجع (عدم);
	}

	len = (ناپ_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(اقرأ, fd, banner, len);
	close(fd);

	إذا (n != len) {
		حرر(banner);
		أرجع (عدم);
	}
	banner[n] = '\0';

	أرجع (banner);
}

ساكن فراغ
userauth_send_banner(بنية ssh *ssh, ثابت حرف *پیغام)
{
	صحيح r;

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, پیغام)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ساكن فراغ
userauth_banner(بنية ssh *ssh)
{
	حرف *banner = عدم;

	إذا (options.banner == عدم)
		أرجع;

	إذا ((banner = mm_auth2_read_banner()) == عدم)
		اذهب پورا;
	userauth_send_banner(ssh, banner);

پورا:
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
	إذا (ssh->kex->ext_info_c)
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_SERVICE_REQUEST, &داخلہ_service_request);
	ssh_dispatch_لگاتار_fatal(ssh, DISPATCH_بلاک, &authctxt->success);
	ssh->authctxt = عدم;
}

ساكن صحيح
داخلہ_service_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *service = عدم;
	صحيح r, acceptit = 0;

	إذا ((r = sshpkt_get_cstring(ssh, &service, عدم)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		اذهب باہرلا;

	إذا (authctxt == عدم)
		fatal("input_service_request: no authctxt");

	إذا (strcmp(service, "ssh-userauth") == 0) {
		إذا (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_REQUEST,
			    &داخلہ_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	إذا (acceptit) {
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			اذهب باہرلا;
	} وإلا {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 باہرلا:
	حرر(service);
	أرجع r;
}

#تعریف_کرو MIN_FAIL_DELAY_SECONDS 0.005
#تعریف_کرو MAX_FAIL_DELAY_SECONDS 5.0
ساكن مزدوج
user_specific_delay(ثابت حرف *user)
{
	حرف b[512];
	ناپ_t len = ssh_digest_بائٹاں(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	مزدوج delay;

	(فراغ)snprintf(b, حجم b, "%llu%s",
	    (بنانشانی لما لما)options.timing_secret, user);
	إذا (ssh_digest_حافظہ(SSH_DIGEST_SHA512, b, لڑی_لمبائی(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (مزدوج)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	أرجع MIN_FAIL_DELAY_SECONDS + delay;
}

ساكن فراغ
ensure_minimum_ویلا_since(مزدوج شروع, مزدوج seconds)
{
	بنية timespec ts;
	مزدوج elapsed = monotime_double() - شروع, req = seconds, remain;

	إذا (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		أرجع;
	}

	/* if we've already passed the requested time, scale up */
	طالما ((remain = seconds - elapsed) < 0.0)
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
	ensure_minimum_ویلا_since(tstart, user_specific_delay(authctxt->user));
}

ساكن صحيح
داخلہ_userauth_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = عدم;
	حرف *user = عدم, *service = عدم, *طریقہ = عدم, *style = عدم;
	صحيح r, authenticated = 0;
	مزدوج tstart = monotime_double();

	إذا (authctxt == عدم)
		fatal("input_userauth_request: no authctxt");

	إذا ((r = sshpkt_get_cstring(ssh, &user, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &طریقہ, عدم)) != 0)
		اذهب باہرلا;
	debug("userauth-request for user %s service %s method %s", user, service, طریقہ);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	إذا ((style = strchr(user, ':')) != عدم)
		*style++ = 0;

	إذا (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	إذا (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : عدم;
		إذا (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} وإلا {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#جے_تعریف_شدہ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#جے_انت
		}
#جے_تعریف_شدہ USE_PAM
		إذا (options.use_pam)
			mm_شروع_pam(ssh);
#جے_انت
		ssh_packet_سیٹ_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		إذا ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		إذا (auth2_تیاری_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} وإلا إذا (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#جے_تعریف_شدہ GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, عدم);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, عدم);
#جے_انت

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, طریقہ);
	إذا (m != عدم && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", طریقہ);
		authenticated =	m->userauth(ssh, طریقہ);
	}
	إذا (!authctxt->authenticated && strcmp(طریقہ, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_انت(ssh, authenticated, طریقہ, عدم);
	r = 0;
 باہرلا:
	حرر(service);
	حرر(user);
	حرر(طریقہ);
	أرجع r;
}

فراغ
userauth_انت(بنية ssh *ssh, صحيح authenticated, ثابت حرف *packet_طریقہ,
    ثابت حرف *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = عدم;
	ثابت حرف *طریقہ = packet_طریقہ;
	حرف *methods;
	صحيح r, partial = 0;

	إذا (authenticated) {
		إذا (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		إذا (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		إذا ((m = authmethod_byname(طریقہ)) == عدم)
			fatal("INTERNAL ERROR: bad method %s", طریقہ);
		طریقہ = m->cfg->name;
	}

	/* Special handling for root */
	إذا (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_جڑ_allowed(ssh, طریقہ)) {
		authenticated = 0;
#جے_تعریف_شدہ SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_جڑ_DENIED);
#جے_انت
	}

	إذا (authenticated && options.عدد_auth_methods != 0) {
		إذا (!auth2_update_methods_lists(authctxt, طریقہ, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, طریقہ, submethod);

	/* Update information exposed to session */
	إذا (authenticated || partial)
		auth2_update_session_info(authctxt, طریقہ, submethod);

	إذا (authctxt->postponed)
		أرجع;

#جے_تعریف_شدہ USE_PAM
	إذا (options.use_pam && authenticated) {
		صحيح r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		إذا (sshbuf_len(loginmsg) > 0) {
			إذا ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			إذا ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		إذا (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#جے_انت

	إذا (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_سیٹ_log_preamble(ssh, "user %s", authctxt->user);
	} وإلا {
		/* Allow initial try of "none" auth without failure penalty */
		إذا (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(طریقہ, "none") != 0))
			authctxt->failures++;
		إذا (authctxt->failures >= options.max_authtries) {
#جے_تعریف_شدہ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#جے_انت
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_FAILURE)) != 0 ||
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
auth2_طریقہ_allowed(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	إذا (options.عدد_auth_methods == 0)
		أرجع 1;
	لكل (i = 0; i < authctxt->عدد_auth_methods; i++) {
		إذا (list_starts_with(authctxt->auth_methods[i], طریقہ,
		    submethod) != میل_NONE)
			أرجع 1;
	}
	أرجع 0;
}

ساكن حرف *
authmethods_get(Authctxt *authctxt)
{
	بنية sshbuf *b;
	حرف *list;
	صحيح i, r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (i = 0; authmethods[i] != عدم; i++) {
		إذا (strcmp(authmethods[i]->cfg->name, "none") == 0)
			استمر;
		إذا (authmethods[i]->cfg->enabled == عدم ||
		    *(authmethods[i]->cfg->enabled) == 0)
			استمر;
		إذا (!auth2_طریقہ_allowed(authctxt, authmethods[i]->cfg->name,
		    عدم))
			استمر;
		إذا ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	إذا ((list = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	أرجع list;
}

ساكن Authmethod *
authmethod_byname(ثابت حرف *name)
{
	صحيح i;

	إذا (name == عدم)
		fatal_f("NULL authentication method name");
	لكل (i = 0; authmethods[i] != عدم; i++) {
		إذا (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != عدم &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			أرجع authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	أرجع عدم;
}

ساكن Authmethod *
authmethod_lookup(Authctxt *authctxt, ثابت حرف *name)
{
	Authmethod *طریقہ;

	إذا ((طریقہ = authmethod_byname(name)) == عدم)
		أرجع عدم;

	إذا (طریقہ->cfg->enabled == عدم || *(طریقہ->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		أرجع عدم;
	}
	إذا (!auth2_طریقہ_allowed(authctxt, طریقہ->cfg->name, عدم)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		أرجع عدم;
	}
	أرجع طریقہ;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
صحيح
auth2_تیاری_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	إذا (options.عدد_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		حرر(options.auth_methods[0]);
		options.auth_methods[0] = عدم;
		options.عدد_auth_methods = 0;
	}

	إذا (options.عدد_auth_methods == 0)
		أرجع 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.عدد_auth_methods,
	    حجم(*authctxt->auth_methods));
	authctxt->عدد_auth_methods = 0;
	لكل (i = 0; i < options.عدد_auth_methods; i++) {
		إذا (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			استمر;
		}
		debug("authentication methods list %d: %s",
		    authctxt->عدد_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->عدد_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	إذا (authctxt->عدد_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		أرجع -1;
	}
	أرجع 0;
}

ساكن صحيح
list_starts_with(ثابت حرف *methods, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	ناپ_t l = لڑی_لمبائی(طریقہ);
	صحيح میل;
	ثابت حرف *p;

	إذا (لڑی_مقابلہ(methods, طریقہ, l) != 0)
		أرجع میل_NONE;
	p = methods + l;
	میل = میل_طریقہ;
	إذا (*p == ':') {
		إذا (!submethod)
			أرجع میل_PARTIAL;
		l = لڑی_لمبائی(submethod);
		p += 1;
		إذا (لڑی_مقابلہ(submethod, p, l))
			أرجع میل_NONE;
		p += l;
		میل = میل_BOTH;
	}
	إذا (*p != ',' && *p != '\0')
		أرجع میل_NONE;
	أرجع میل;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ساكن صحيح
remove_طریقہ(حرف **methods, ثابت حرف *طریقہ, ثابت حرف *submethod)
{
	حرف *omethods = *methods, *p;
	ناپ_t l = لڑی_لمبائی(طریقہ);
	صحيح میل;

	میل = list_starts_with(omethods, طریقہ, submethod);
	إذا (میل != میل_طریقہ && میل != میل_BOTH)
		أرجع 0;
	p = omethods + l;
	إذا (submethod && میل == میل_BOTH)
		p += 1 + لڑی_لمبائی(submethod); /* include colon */
	إذا (*p == ',')
		p++;
	*methods = xstrdup(p);
	حرر(omethods);
	أرجع 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
صحيح
auth2_update_methods_lists(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	u_int i, لبھیا = 0;

	debug3_f("updating methods list after \"%s\"", طریقہ);
	لكل (i = 0; i < authctxt->عدد_auth_methods; i++) {
		إذا (!remove_طریقہ(&(authctxt->auth_methods[i]), طریقہ,
		    submethod))
			استمر;
		لبھیا = 1;
		إذا (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			أرجع 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	إذا (!لبھیا)
		fatal_f("method not in AuthenticationMethods");
	أرجع 0;
}

/* Reset method-specific information */
فراغ auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_طریقہ_کلید);
	حرر(authctxt->auth_طریقہ_info);
	authctxt->auth_طریقہ_کلید = عدم;
	authctxt->auth_طریقہ_info = عدم;
}

/* Record auth method-specific information for logs */
فراغ
auth2_ریکارڈ_info(Authctxt *authctxt, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح i;

	حرر(authctxt->auth_طریقہ_info);
	authctxt->auth_طریقہ_info = عدم;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_طریقہ_info, fmt, ap);
	va_end(ap);

	إذا (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
فراغ
auth2_ریکارڈ_کلید(Authctxt *authctxt, صحيح authenticated,
    ثابت بنية sshkey *کلید)
{
	بنية sshkey **tmp, *dup;
	صحيح r;

	إذا ((r = sshkey_from_نجی(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_طریقہ_کلید);
	authctxt->auth_طریقہ_کلید = dup;

	إذا (!authenticated)
		أرجع;

	/* If authenticated, make sure we don't accept this key again */
	إذا ((r = sshkey_from_نجی(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	إذا (authctxt->nprev_کلیدیں >= ودھ_توں_ودھ_عدد ||
	    (tmp = recallocarray(authctxt->prev_کلیدیں, authctxt->nprev_کلیدیں,
	    authctxt->nprev_کلیدیں + 1, حجم(*authctxt->prev_کلیدیں))) == عدم)
		fatal_f("reallocarray failed");
	authctxt->prev_کلیدیں = tmp;
	authctxt->prev_کلیدیں[authctxt->nprev_کلیدیں] = dup;
	authctxt->nprev_کلیدیں++;

}

/* Checks whether a key has already been previously used for authentication */
صحيح
auth2_کلید_already_ورتیا(Authctxt *authctxt, ثابت بنية sshkey *کلید)
{
	u_int i;
	حرف *fp;

	لكل (i = 0; i < authctxt->nprev_کلیدیں; i++) {
		إذا (sshkey_equal_عوامی(کلید, authctxt->prev_کلیدیں[i])) {
			fp = sshkey_fingerprint(authctxt->prev_کلیدیں[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->prev_کلیدیں[i]),
			    fp == عدم ? "UNKNOWN" : fp);
			حرر(fp);
			أرجع 1;
		}
	}
	أرجع 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
فراغ
auth2_update_session_info(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	صحيح r;

	إذا (authctxt->session_info == عدم) {
		إذا ((authctxt->session_info = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	إذا ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    طریقہ, submethod == عدم ? "" : "/",
	    submethod == عدم ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	إذا (authctxt->auth_طریقہ_کلید != عدم) {
		إذا ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_متن(authctxt->auth_طریقہ_کلید,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	إذا (authctxt->auth_طریقہ_info != عدم) {
		/* Ensure no ambiguity here */
		إذا (strchr(authctxt->auth_طریقہ_info, '\n') != عدم)
			fatal_f("auth_method_info contains \\n");
		إذا ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_طریقہ_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	إذا ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

