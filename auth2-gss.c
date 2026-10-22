/* $OpenBSD: auth2-gss.c,v 1.42 2026/07/07 02:17:18 djm Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS'' AND ANY EXPRESS OR
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

#اگر_تعریف_شدہ GSSAPI

#شامل <sys/types.h>

#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "ssh2.h"
#شامل "log.h"
#شامل "dispatch.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "packet.h"
#شامل "kex.h"
#شامل "ssh-gss.h"
#شامل "monitor_wrap.h"

#تعریف_کرو SSH_GSSAPI_MAX_MECHS	2048

خارجی ServerOptions options;
خارجی ساخت authmethod_cfg methodcfg_gssapi;

ساکن صحیح داخلہ_gssapi_token(صحیح type, uint32_t plen, ساخت ssh *ssh);
ساکن صحیح داخلہ_gssapi_mic(صحیح type, uint32_t plen, ساخت ssh *ssh);
ساکن صحیح داخلہ_gssapi_exchange_complete(صحیح type, uint32_t plen, ساخت ssh *ssh);
ساکن صحیح داخلہ_gssapi_errtok(صحیح, uint32_t, ساخت ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ساکن صحیح
userauth_gssapi(ساخت ssh *ssh, ثابت حرف *طریقہ)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, تہی};
	Gssctxt *ctxt = تہی;
	صحیح r, present;
	u_int mechs;
	OM_uint32 ms;
	سائز_t len;
	u_char *doid = تہی;

	اگر ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	اگر (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		واپس (0);
	} ورنہ اگر (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		واپس (0);
	}

	کرو {
		mechs--;

		آزاد(doid);

		present = 0;
		اگر ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		اگر (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.لمبائی   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} ورنہ {
			logit_f("badly formed OID received");
		}
	} جب (mechs > 0 && !present);

	اگر (!present) {
		آزاد(doid);
		authctxt->server_caused_failure = 1;
		واپس (0);
	}

	اگر (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		اگر (ctxt != تہی)
			ssh_gssapi_delete_ctx(&ctxt);
		آزاد(doid);
		authctxt->server_caused_failure = 1;
		واپس (0);
	}

	authctxt->methoddata = (خالی *)ctxt;

	/* Return the OID that we received */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	آزاد(doid);

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, &داخلہ_gssapi_token);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, &داخلہ_gssapi_errtok);
	authctxt->postponed = 1;

	واپس (0);
}

ساکن صحیح
داخلہ_gssapi_token(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_بفر_desc send_tok = GSS_C_خالی_خانے_بفر;
	gss_بفر_desc recv_tok;
	OM_uint32 maj_حالت, min_حالت, flags;
	u_char *p;
	سائز_t len;
	صحیح r;

	اگر (authctxt == تہی)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.قدر = p;
	recv_tok.لمبائی = len;
	maj_حالت = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	آزاد(p);

	اگر (GSS_ERROR(maj_حالت)) {
		اگر (send_tok.لمبائی != 0) {
			اگر ((r = sshpkt_آغاز(ssh,
			    SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.قدر,
			    send_tok.لمبائی)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, تہی);
		userauth_اختتام(ssh, 0, "gssapi-with-mic", تہی);
	} ورنہ {
		اگر (send_tok.لمبائی != 0) {
			اگر ((r = sshpkt_آغاز(ssh,
			    SSH2_پیغام_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.قدر,
			    send_tok.لمبائی)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		اگر (maj_حالت == GSS_S_COMPLETE) {
			ssh_dispatch_سیٹ(ssh,
			    SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			اگر (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_سیٹ(ssh,
				    SSH2_پیغام_USERAUTH_GSSAPI_MIC,
				    &داخلہ_gssapi_mic);
			} ورنہ {
				ssh_dispatch_سیٹ(ssh,
				    SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &داخلہ_gssapi_exchange_complete);
			}
		}
	}

	gss_release_بفر(&min_حالت, &send_tok);
	واپس 0;
}

ساکن صحیح
داخلہ_gssapi_errtok(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	صحیح r;

	اگر (authctxt == تہی)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	اگر ((r = sshpkt_get_string_براہ_راست(ssh, تہی, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_MIC, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, تہی);
	userauth_اختتام(ssh, 0, "gssapi-with-mic", تہی);
	واپس 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ساکن صحیح
داخلہ_gssapi_exchange_complete(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	صحیح r, authenticated;
	دوہرا tstart = monotime_double();

	اگر (authctxt == تہی)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	اگر (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_MIC, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, تہی);
	userauth_اختتام(ssh, authenticated, "gssapi-with-mic", تہی);
	واپس 0;
}

ساکن صحیح
داخلہ_gssapi_mic(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	صحیح r, authenticated = 0;
	ساخت sshbuf *b;
	gss_بفر_desc mic, gssbuf;
	u_char *p;
	سائز_t len;
	دوہرا tstart = monotime_double();

	اگر (authctxt == تہی)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	mic.قدر = p;
	mic.لمبائی = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	اگر ((gssbuf.قدر = sshbuf_mutable_ptr(b)) == تہی)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.لمبائی = sshbuf_len(b);

	اگر (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ورنہ
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	آزاد(mic.قدر);

	اگر (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_MIC, تہی);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, تہی);
	userauth_اختتام(ssh, authenticated, "gssapi-with-mic", تہی);
	واپس 0;
}

Authmethod طریقہ_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#اگر_ختم
