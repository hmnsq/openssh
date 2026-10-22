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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/uio.h>

#شامل <fcntl.h>
#شامل <limits.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <time.h>

#شامل "stdlib.h"
#شامل "atomicio.h"
#شامل "xmalloc.h"
#شامل "ssh2.h"
#شامل "packet.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "dispatch.h"
#شامل "pathnames.h"
#شامل "ssherr.h"
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "digest.h"
#شامل "kex.h"

/* import */
خارجی ServerOptions options;
خارجی ساخت sshbuf *loginmsg;

/* methods */

خارجی Authmethod طریقہ_none;
خارجی Authmethod طریقہ_pubkey;
خارجی Authmethod طریقہ_passwd;
خارجی Authmethod طریقہ_kbdint;
خارجی Authmethod طریقہ_hostbased;
#اگر_تعریف_شدہ GSSAPI
خارجی Authmethod طریقہ_gssapi;
#اگر_ختم

Authmethod *authmethods[] = {
	&طریقہ_none,
	&طریقہ_pubkey,
#اگر_تعریف_شدہ GSSAPI
	&طریقہ_gssapi,
#اگر_ختم
	&طریقہ_passwd,
	&طریقہ_kbdint,
	&طریقہ_hostbased,
	تہی
};

/* protocol */

ساکن صحیح داخلہ_service_request(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_request(صحیح, uint32_t, ساخت ssh *);

/* helper */
ساکن Authmethod *authmethod_byname(ثابت حرف *);
ساکن Authmethod *authmethod_lookup(Authctxt *, ثابت حرف *);
ساکن حرف *authmethods_get(Authctxt *authctxt);

#تعریف_کرو مطابقت_NONE	0	/* method or submethod mismatch */
#تعریف_کرو مطابقت_طریقہ	1	/* method matches (no submethod specified) */
#تعریف_کرو مطابقت_BOTH	2	/* method and submethod match */
#تعریف_کرو مطابقت_PARTIAL	3	/* method matches, submethod can't be checked */
ساکن صحیح list_starts_with(ثابت حرف *, ثابت حرف *, ثابت حرف *);

حرف *
auth2_read_banner(خالی)
{
	ساخت stat st;
	حرف *banner = تہی;
	سائز_t len, n;
	صحیح fd;

	اگر ((fd = open(options.banner, O_RDONLY)) == -1)
		واپس (تہی);
	اگر (fstat(fd, &st) == -1) {
		close(fd);
		واپس (تہی);
	}
	اگر (st.st_size <= 0 || st.st_size > 1*1024*1024) {
		close(fd);
		واپس (تہی);
	}

	len = (سائز_t)st.st_size;		/* truncate */
	banner = xmalloc(len + 1);
	n = atomicio(اقرأ, fd, banner, len);
	close(fd);

	اگر (n != len) {
		آزاد(banner);
		واپس (تہی);
	}
	banner[n] = '\0';

	واپس (banner);
}

ساکن خالی
userauth_send_banner(ساخت ssh *ssh, ثابت حرف *پیغام)
{
	صحیح r;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_BANNER)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, پیغام)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language, unused */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	debug_f("sent");
}

ساکن خالی
userauth_banner(ساخت ssh *ssh)
{
	حرف *banner = تہی;

	اگر (options.banner == تہی)
		واپس;

	اگر ((banner = mm_auth2_read_banner()) == تہی)
		جاؤ مکمل;
	userauth_send_banner(ssh, banner);

مکمل:
	آزاد(banner);
}

/*
 * loop until authctxt->success == TRUE
 */
خالی
do_authentication2(ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	اگر (ssh->kex->ext_info_c)
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_SERVICE_REQUEST, &داخلہ_service_request);
	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_بلاک, &authctxt->success);
	ssh->authctxt = تہی;
}

ساکن صحیح
داخلہ_service_request(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *service = تہی;
	صحیح r, acceptit = 0;

	اگر ((r = sshpkt_get_cstring(ssh, &service, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ برآمد;

	اگر (authctxt == تہی)
		fatal("input_service_request: no authctxt");

	اگر (strcmp(service, "ssh-userauth") == 0) {
		اگر (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_REQUEST,
			    &داخلہ_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	اگر (acceptit) {
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_SERVICE_ACCEPT)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			جاؤ برآمد;
	} ورنہ {
		debug("bad service request %s", service);
		ssh_packet_disconnect(ssh, "bad service request %s", service);
	}
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &dispatch_protocol_error);
	r = 0;
 برآمد:
	آزاد(service);
	واپس r;
}

#تعریف_کرو MIN_FAIL_DELAY_SECONDS 0.005
#تعریف_کرو MAX_FAIL_DELAY_SECONDS 5.0
ساکن دوہرا
user_specific_delay(ثابت حرف *user)
{
	حرف b[512];
	سائز_t len = ssh_digest_بائٹیں(SSH_DIGEST_SHA512);
	u_char *hash = xmalloc(len);
	دوہرا delay;

	(خالی)snprintf(b, حجم b, "%llu%s",
	    (غیرعلامتی طویل طویل)options.timing_secret, user);
	اگر (ssh_digest_حافظہ(SSH_DIGEST_SHA512, b, لڑی_لمبائی(b), hash, len) != 0)
		fatal_f("ssh_digest_memory");
	/* 0-4.2 ms of delay */
	delay = (دوہرا)PEEK_U32(hash) / 1000 / 1000 / 1000 / 1000;
	freezero(hash, len);
	debug3_f("user specific delay %0.3lfms", delay*1000);
	واپس MIN_FAIL_DELAY_SECONDS + delay;
}

ساکن خالی
ensure_minimum_وقت_since(دوہرا آغاز, دوہرا seconds)
{
	ساخت timespec ts;
	دوہرا elapsed = monotime_double() - آغاز, req = seconds, remain;

	اگر (elapsed > MAX_FAIL_DELAY_SECONDS) {
		debug3_f("elapsed %0.3lfms exceeded the max delay "
		    "requested %0.3lfms)", elapsed*1000, req*1000);
		واپس;
	}

	/* if we've already passed the requested time, scale up */
	جب ((remain = seconds - elapsed) < 0.0)
		seconds *= 2;

	ts.tv_sec = remain;
	ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
	debug3_f("elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)",
	    elapsed*1000, remain*1000, req*1000);
	nanosleep(&ts, تہی);
}

خالی
auth_failure_delay(Authctxt *authctxt, دوہرا tstart)
{
	ensure_minimum_وقت_since(tstart, user_specific_delay(authctxt->user));
}

ساکن صحیح
داخلہ_userauth_request(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = تہی;
	حرف *user = تہی, *service = تہی, *طریقہ = تہی, *style = تہی;
	صحیح r, authenticated = 0;
	دوہرا tstart = monotime_double();

	اگر (authctxt == تہی)
		fatal("input_userauth_request: no authctxt");

	اگر ((r = sshpkt_get_cstring(ssh, &user, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &طریقہ, تہی)) != 0)
		جاؤ برآمد;
	debug("userauth-request for user %s service %s method %s", user, service, طریقہ);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	اگر ((style = strchr(user, ':')) != تہی)
		*style++ = 0;

	اگر (authctxt->attempt >= 1024)
		auth_maxtries_exceeded(ssh);
	اگر (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->pw = mm_getpwnamallow(ssh, user);
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : تہی;
		اگر (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			authctxt->valid = 1;
			debug2_f("setting up authctxt for %s", user);
		} ورنہ {
			authctxt->valid = 0;
			/* Invalid user, fake password information */
			authctxt->pw = fakepw();
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_INVALID_USER);
#اگر_ختم
		}
#اگر_تعریف_شدہ USE_PAM
		اگر (options.use_pam)
			mm_آغاز_pam(ssh);
#اگر_ختم
		ssh_packet_سیٹ_log_preamble(ssh, "%suser %s",
		    authctxt->valid ? "authenticating " : "invalid ", user);
		setproctitle("%s [net]", authctxt->valid ? user : "unknown");
		mm_inform_authserv(service, style);
		userauth_banner(ssh);
		اگر ((r = kex_server_update_ext_info(ssh)) != 0)
			fatal_fr(r, "kex_server_update_ext_info failed");
		اگر (auth2_تیاری_methods_lists(authctxt) != 0)
			ssh_packet_disconnect(ssh,
			    "no authentication methods enabled");
	} ورنہ اگر (strcmp(user, authctxt->user) != 0 ||
	    strcmp(service, authctxt->service) != 0) {
		ssh_packet_disconnect(ssh, "Change of username or service "
		    "not allowed: (%s,%s) -> (%s,%s)",
		    authctxt->user, authctxt->service, user, service);
	}
	/* reset state */
	auth2_challenge_stop(ssh);

#اگر_تعریف_شدہ GSSAPI
	ssh_gssapi_cleanup_global_client();
	/* XXX move to auth2_gssapi_stop() */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, تہی);
#اگر_ختم

	auth2_authctxt_reset_info(authctxt);
	authctxt->postponed = 0;
	authctxt->server_caused_failure = 0;
	authctxt->auth_failure_already_counted = 0;

	/* try to authenticate user */
	m = authmethod_lookup(authctxt, طریقہ);
	اگر (m != تہی && authctxt->failures < options.max_authtries) {
		debug2("input_userauth_request: try method %s", طریقہ);
		authenticated =	m->userauth(ssh, طریقہ);
	}
	اگر (!authctxt->authenticated && strcmp(طریقہ, "none") != 0)
		auth_failure_delay(authctxt, tstart);

	userauth_اختتام(ssh, authenticated, طریقہ, تہی);
	r = 0;
 برآمد:
	آزاد(service);
	آزاد(user);
	آزاد(طریقہ);
	واپس r;
}

خالی
userauth_اختتام(ساخت ssh *ssh, صحیح authenticated, ثابت حرف *packet_طریقہ,
    ثابت حرف *submethod)
{
	Authctxt *authctxt = ssh->authctxt;
	Authmethod *m = تہی;
	ثابت حرف *طریقہ = packet_طریقہ;
	حرف *methods;
	صحیح r, partial = 0;

	اگر (authenticated) {
		اگر (!authctxt->valid) {
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);
		}
		اگر (authctxt->postponed)
			fatal("INTERNAL ERROR: authenticated and postponed");
		/* prefer primary authmethod name to possible synonym */
		اگر ((m = authmethod_byname(طریقہ)) == تہی)
			fatal("INTERNAL ERROR: bad method %s", طریقہ);
		طریقہ = m->cfg->name;
	}

	/* Special handling for root */
	اگر (authenticated && authctxt->pw->pw_uid == 0 &&
	    !auth_جڑ_allowed(ssh, طریقہ)) {
		authenticated = 0;
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
		mm_audit_event(ssh, SSH_LOGIN_جڑ_DENIED);
#اگر_ختم
	}

	اگر (authenticated && options.عدد_auth_methods != 0) {
		اگر (!auth2_update_methods_lists(authctxt, طریقہ, submethod)) {
			authenticated = 0;
			partial = 1;
		}
	}

	/* Log before sending the reply */
	auth_log(ssh, authenticated, partial, طریقہ, submethod);

	/* Update information exposed to session */
	اگر (authenticated || partial)
		auth2_update_session_info(authctxt, طریقہ, submethod);

	اگر (authctxt->postponed)
		واپس;

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam && authenticated) {
		صحیح r, success = mm_do_pam_account();

		/* If PAM returned a message, send it to the user. */
		اگر (sshbuf_len(loginmsg) > 0) {
			اگر ((r = sshbuf_put(loginmsg, "\0", 1)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			userauth_send_banner(ssh, sshbuf_ptr(loginmsg));
			اگر ((r = ssh_packet_write_wait(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send PAM banner", __func__);
			}
		}
		اگر (!success) {
			fatal("Access denied for user %s by PAM account "
			    "configuration", authctxt->user);
		}
	}
#اگر_ختم

	اگر (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_سیٹ_log_preamble(ssh, "user %s", authctxt->user);
	} ورنہ {
		/* Allow initial try of "none" auth without failure penalty */
		اگر (!partial && !authctxt->server_caused_failure &&
		    !authctxt->auth_failure_already_counted &&
		    (authctxt->attempt > 1 || strcmp(طریقہ, "none") != 0))
			authctxt->failures++;
		اگر (authctxt->failures >= options.max_authtries) {
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
			mm_audit_event(ssh, SSH_LOGIN_EXCEED_MAXTRIES);
#اگر_ختم
			auth_maxtries_exceeded(ssh);
		}
		methods = authmethods_get(authctxt);
		debug3_f("failure partial=%d next methods=\"%s\"",
		    partial, methods);
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_FAILURE)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
		    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send failure packet");
		آزاد(methods);
	}
}

/*
 * Checks whether method is allowed by at least one AuthenticationMethods
 * methods list. Returns 1 if allowed, or no methods lists configured.
 * 0 otherwise.
 */
صحیح
auth2_طریقہ_allowed(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	u_int i;

	/*
	 * NB. authctxt->num_auth_methods might be zero as a result of
	 * auth2_setup_methods_lists(), so check the configuration.
	 */
	اگر (options.عدد_auth_methods == 0)
		واپس 1;
	برائے (i = 0; i < authctxt->عدد_auth_methods; i++) {
		اگر (list_starts_with(authctxt->auth_methods[i], طریقہ,
		    submethod) != مطابقت_NONE)
			واپس 1;
	}
	واپس 0;
}

ساکن حرف *
authmethods_get(Authctxt *authctxt)
{
	ساخت sshbuf *b;
	حرف *list;
	صحیح i, r;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	برائے (i = 0; authmethods[i] != تہی; i++) {
		اگر (strcmp(authmethods[i]->cfg->name, "none") == 0)
			جاری;
		اگر (authmethods[i]->cfg->enabled == تہی ||
		    *(authmethods[i]->cfg->enabled) == 0)
			جاری;
		اگر (!auth2_طریقہ_allowed(authctxt, authmethods[i]->cfg->name,
		    تہی))
			جاری;
		اگر ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) ? "," : "",
		    authmethods[i]->cfg->name)) != 0)
			fatal_fr(r, "buffer error");
	}
	اگر ((list = sshbuf_dup_string(b)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	واپس list;
}

ساکن Authmethod *
authmethod_byname(ثابت حرف *name)
{
	صحیح i;

	اگر (name == تہی)
		fatal_f("NULL authentication method name");
	برائے (i = 0; authmethods[i] != تہی; i++) {
		اگر (strcmp(name, authmethods[i]->cfg->name) == 0 ||
		    (authmethods[i]->cfg->synonym != تہی &&
		    strcmp(name, authmethods[i]->cfg->synonym) == 0))
			واپس authmethods[i];
	}
	debug_f("unrecognized authentication method name: %s", name);
	واپس تہی;
}

ساکن Authmethod *
authmethod_lookup(Authctxt *authctxt, ثابت حرف *name)
{
	Authmethod *طریقہ;

	اگر ((طریقہ = authmethod_byname(name)) == تہی)
		واپس تہی;

	اگر (طریقہ->cfg->enabled == تہی || *(طریقہ->cfg->enabled) == 0) {
		debug3_f("method %s not enabled", name);
		واپس تہی;
	}
	اگر (!auth2_طریقہ_allowed(authctxt, طریقہ->cfg->name, تہی)) {
		debug3_f("method %s not allowed "
		    "by AuthenticationMethods", name);
		واپس تہی;
	}
	واپس طریقہ;
}

/*
 * Prune the AuthenticationMethods supplied in the configuration, removing
 * any methods lists that include disabled methods. Note that this might
 * leave authctxt->num_auth_methods == 0, even when multiple required auth
 * has been requested. For this reason, all tests for whether multiple is
 * enabled should consult options.num_auth_methods directly.
 */
صحیح
auth2_تیاری_methods_lists(Authctxt *authctxt)
{
	u_int i;

	/* First, normalise away the "any" pseudo-method */
	اگر (options.عدد_auth_methods == 1 &&
	    strcmp(options.auth_methods[0], "any") == 0) {
		آزاد(options.auth_methods[0]);
		options.auth_methods[0] = تہی;
		options.عدد_auth_methods = 0;
	}

	اگر (options.عدد_auth_methods == 0)
		واپس 0;
	debug3_f("checking methods");
	authctxt->auth_methods = xcalloc(options.عدد_auth_methods,
	    حجم(*authctxt->auth_methods));
	authctxt->عدد_auth_methods = 0;
	برائے (i = 0; i < options.عدد_auth_methods; i++) {
		اگر (auth2_methods_valid(options.auth_methods[i], 1) != 0) {
			logit("Authentication methods list \"%s\" contains "
			    "disabled method, skipping",
			    options.auth_methods[i]);
			جاری;
		}
		debug("authentication methods list %d: %s",
		    authctxt->عدد_auth_methods, options.auth_methods[i]);
		authctxt->auth_methods[authctxt->عدد_auth_methods++] =
		    xstrdup(options.auth_methods[i]);
	}
	اگر (authctxt->عدد_auth_methods == 0) {
		error("No AuthenticationMethods left after eliminating "
		    "disabled methods");
		واپس -1;
	}
	واپس 0;
}

ساکن صحیح
list_starts_with(ثابت حرف *methods, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	سائز_t l = لڑی_لمبائی(طریقہ);
	صحیح مطابقت;
	ثابت حرف *p;

	اگر (لڑی_موازنہ(methods, طریقہ, l) != 0)
		واپس مطابقت_NONE;
	p = methods + l;
	مطابقت = مطابقت_طریقہ;
	اگر (*p == ':') {
		اگر (!submethod)
			واپس مطابقت_PARTIAL;
		l = لڑی_لمبائی(submethod);
		p += 1;
		اگر (لڑی_موازنہ(submethod, p, l))
			واپس مطابقت_NONE;
		p += l;
		مطابقت = مطابقت_BOTH;
	}
	اگر (*p != ',' && *p != '\0')
		واپس مطابقت_NONE;
	واپس مطابقت;
}

/*
 * Remove method from the start of a comma-separated list of methods.
 * Returns 0 if the list of methods did not start with that method or 1
 * if it did.
 */
ساکن صحیح
remove_طریقہ(حرف **methods, ثابت حرف *طریقہ, ثابت حرف *submethod)
{
	حرف *omethods = *methods, *p;
	سائز_t l = لڑی_لمبائی(طریقہ);
	صحیح مطابقت;

	مطابقت = list_starts_with(omethods, طریقہ, submethod);
	اگر (مطابقت != مطابقت_طریقہ && مطابقت != مطابقت_BOTH)
		واپس 0;
	p = omethods + l;
	اگر (submethod && مطابقت == مطابقت_BOTH)
		p += 1 + لڑی_لمبائی(submethod); /* include colon */
	اگر (*p == ',')
		p++;
	*methods = xstrdup(p);
	آزاد(omethods);
	واپس 1;
}

/*
 * Called after successful authentication. Will remove the successful method
 * from the start of each list in which it occurs. If it was the last method
 * in any list, then authentication is deemed successful.
 * Returns 1 if the method completed any authentication list or 0 otherwise.
 */
صحیح
auth2_update_methods_lists(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	u_int i, ملا = 0;

	debug3_f("updating methods list after \"%s\"", طریقہ);
	برائے (i = 0; i < authctxt->عدد_auth_methods; i++) {
		اگر (!remove_طریقہ(&(authctxt->auth_methods[i]), طریقہ,
		    submethod))
			جاری;
		ملا = 1;
		اگر (*authctxt->auth_methods[i] == '\0') {
			debug2("authentication methods list %d complete", i);
			واپس 1;
		}
		debug3("authentication methods list %d remaining: \"%s\"",
		    i, authctxt->auth_methods[i]);
	}
	/* This should not happen, but would be bad if it did */
	اگر (!ملا)
		fatal_f("method not in AuthenticationMethods");
	واپس 0;
}

/* Reset method-specific information */
خالی auth2_authctxt_reset_info(Authctxt *authctxt)
{
	sshkey_free(authctxt->auth_طریقہ_کلید);
	آزاد(authctxt->auth_طریقہ_info);
	authctxt->auth_طریقہ_کلید = تہی;
	authctxt->auth_طریقہ_info = تہی;
}

/* Record auth method-specific information for logs */
خالی
auth2_ریکارڈ_info(Authctxt *authctxt, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحیح i;

	آزاد(authctxt->auth_طریقہ_info);
	authctxt->auth_طریقہ_info = تہی;

	va_start(ap, fmt);
	i = vasprintf(&authctxt->auth_طریقہ_info, fmt, ap);
	va_end(ap);

	اگر (i == -1)
		fatal_f("vasprintf failed");
}

/*
 * Records a public key used in authentication. This is used for logging
 * and to ensure that the same key is not subsequently accepted again for
 * multiple authentication.
 */
خالی
auth2_ریکارڈ_کلید(Authctxt *authctxt, صحیح authenticated,
    ثابت ساخت sshkey *کلید)
{
	ساخت sshkey **tmp, *dup;
	صحیح r;

	اگر ((r = sshkey_from_نجی(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	sshkey_free(authctxt->auth_طریقہ_کلید);
	authctxt->auth_طریقہ_کلید = dup;

	اگر (!authenticated)
		واپس;

	/* If authenticated, make sure we don't accept this key again */
	اگر ((r = sshkey_from_نجی(کلید, &dup)) != 0)
		fatal_fr(r, "copy key");
	اگر (authctxt->nprev_کلیدیں >= زیادہ_سے_زیادہ_عدد ||
	    (tmp = recallocarray(authctxt->پچھلا_کلیدیں, authctxt->nprev_کلیدیں,
	    authctxt->nprev_کلیدیں + 1, حجم(*authctxt->پچھلا_کلیدیں))) == تہی)
		fatal_f("reallocarray failed");
	authctxt->پچھلا_کلیدیں = tmp;
	authctxt->پچھلا_کلیدیں[authctxt->nprev_کلیدیں] = dup;
	authctxt->nprev_کلیدیں++;

}

/* Checks whether a key has already been previously used for authentication */
صحیح
auth2_کلید_already_مستعمل(Authctxt *authctxt, ثابت ساخت sshkey *کلید)
{
	u_int i;
	حرف *fp;

	برائے (i = 0; i < authctxt->nprev_کلیدیں; i++) {
		اگر (sshkey_equal_عوامی(کلید, authctxt->پچھلا_کلیدیں[i])) {
			fp = sshkey_fingerprint(authctxt->پچھلا_کلیدیں[i],
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			debug3_f("key already used: %s %s",
			    sshkey_type(authctxt->پچھلا_کلیدیں[i]),
			    fp == تہی ? "UNKNOWN" : fp);
			آزاد(fp);
			واپس 1;
		}
	}
	واپس 0;
}

/*
 * Updates authctxt->session_info with details of authentication. Should be
 * whenever an authentication method succeeds.
 */
خالی
auth2_update_session_info(Authctxt *authctxt, ثابت حرف *طریقہ,
    ثابت حرف *submethod)
{
	صحیح r;

	اگر (authctxt->session_info == تہی) {
		اگر ((authctxt->session_info = sshbuf_new()) == تہی)
			fatal_f("sshbuf_new");
	}

	/* Append method[/submethod] */
	اگر ((r = sshbuf_putf(authctxt->session_info, "%s%s%s",
	    طریقہ, submethod == تہی ? "" : "/",
	    submethod == تہی ? "" : submethod)) != 0)
		fatal_fr(r, "append method");

	/* Append key if present */
	اگر (authctxt->auth_طریقہ_کلید != تہی) {
		اگر ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshkey_format_متن(authctxt->auth_طریقہ_کلید,
		    authctxt->session_info)) != 0)
			fatal_fr(r, "append key");
	}

	اگر (authctxt->auth_طریقہ_info != تہی) {
		/* Ensure no ambiguity here */
		اگر (strchr(authctxt->auth_طریقہ_info, '\n') != تہی)
			fatal_f("auth_method_info contains \\n");
		اگر ((r = sshbuf_put_u8(authctxt->session_info, ' ')) != 0 ||
		    (r = sshbuf_putf(authctxt->session_info, "%s",
		    authctxt->auth_طریقہ_info)) != 0) {
			fatal_fr(r, "append method info");
		}
	}
	اگر ((r = sshbuf_put_u8(authctxt->session_info, '\n')) != 0)
		fatal_fr(r, "append");
}

