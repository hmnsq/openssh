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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_GSSAPI_MAX_MECHS	2048

ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ authmethod_cfg methodcfg_gssapi;

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_token(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_mic(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_exchange_complete(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_errtok(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ਸਥਿਰ ਪੂਰਨ
userauth_gssapi(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ਨਿਰਾ};
	Gssctxt *ctxt = ਨਿਰਾ;
	ਪੂਰਨ r, present;
	u_int mechs;
	OM_uint32 ms;
	ਮਾਪ_t len;
	u_char *doid = ਨਿਰਾ;

	ਜੇ ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	ਜੇ (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ਵਾਪਸ (0);
	} ਨਹੀਂਤਾਂ ਜੇ (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ਵਾਪਸ (0);
	}

	ਕਰੋ {
		mechs--;

		ਮੁਕਤ(doid);

		present = 0;
		ਜੇ ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		ਜੇ (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.ਲੰਮਾਈ   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} ਨਹੀਂਤਾਂ {
			logit_f("badly formed OID received");
		}
	} ਜਦੋਂ (mechs > 0 && !present);

	ਜੇ (!present) {
		ਮੁਕਤ(doid);
		authctxt->server_caused_failure = 1;
		ਵਾਪਸ (0);
	}

	ਜੇ (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		ਜੇ (ctxt != ਨਿਰਾ)
			ssh_gssapi_delete_ctx(&ctxt);
		ਮੁਕਤ(doid);
		authctxt->server_caused_failure = 1;
		ਵਾਪਸ (0);
	}

	authctxt->methoddata = (ਖਾਲੀ *)ctxt;

	/* Return the OID that we received */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ਮੁਕਤ(doid);

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, &ਨਿਵੇਸ਼_gssapi_token);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, &ਨਿਵੇਸ਼_gssapi_errtok);
	authctxt->postponed = 1;

	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_token(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_ਬਫਰ_desc send_tok = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	gss_ਬਫਰ_desc recv_tok;
	OM_uint32 maj_ਸਥਿਤੀ, min_ਸਥਿਤੀ, flags;
	u_char *p;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	ਜੇ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.ਮੁੱਲ = p;
	recv_tok.ਲੰਮਾਈ = len;
	maj_ਸਥਿਤੀ = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	ਮੁਕਤ(p);

	ਜੇ (GSS_ERROR(maj_ਸਥਿਤੀ)) {
		ਜੇ (send_tok.ਲੰਮਾਈ != 0) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
			    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ਮੁੱਲ,
			    send_tok.ਲੰਮਾਈ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, ਨਿਰਾ);
		userauth_ਅੰਤ(ssh, 0, "gssapi-with-mic", ਨਿਰਾ);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (send_tok.ਲੰਮਾਈ != 0) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
			    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ਮੁੱਲ,
			    send_tok.ਲੰਮਾਈ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		ਜੇ (maj_ਸਥਿਤੀ == GSS_S_COMPLETE) {
			ssh_dispatch_ਸੈੱਟ(ssh,
			    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			ਜੇ (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_ਸੈੱਟ(ssh,
				    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC,
				    &ਨਿਵੇਸ਼_gssapi_mic);
			} ਨਹੀਂਤਾਂ {
				ssh_dispatch_ਸੈੱਟ(ssh,
				    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &ਨਿਵੇਸ਼_gssapi_exchange_complete);
			}
		}
	}

	gss_release_ਬਫਰ(&min_ਸਥਿਤੀ, &send_tok);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_errtok(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ਨਿਰਾ);
	userauth_ਅੰਤ(ssh, 0, "gssapi-with-mic", ਨਿਰਾ);
	ਵਾਪਸ 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_exchange_complete(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਪੂਰਨ r, authenticated;
	ਦੁੱਗਣਾ tstart = monotime_double();

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ਜੇ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ਨਿਰਾ);
	userauth_ਅੰਤ(ssh, authenticated, "gssapi-with-mic", ਨਿਰਾ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_mic(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ਪੂਰਨ r, authenticated = 0;
	ਬਣਤਰ sshbuf *b;
	gss_ਬਫਰ_desc mic, gssbuf;
	u_char *p;
	ਮਾਪ_t len;
	ਦੁੱਗਣਾ tstart = monotime_double();

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	ਜੇ ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	mic.ਮੁੱਲ = p;
	mic.ਲੰਮਾਈ = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	ਜੇ ((gssbuf.ਮੁੱਲ = sshbuf_mutable_ptr(b)) == ਨਿਰਾ)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.ਲੰਮਾਈ = sshbuf_len(b);

	ਜੇ (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ਨਹੀਂਤਾਂ
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	ਮੁਕਤ(mic.ਮੁੱਲ);

	ਜੇ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC, ਨਿਰਾ);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ਨਿਰਾ);
	userauth_ਅੰਤ(ssh, authenticated, "gssapi-with-mic", ਨਿਰਾ);
	ਵਾਪਸ 0;
}

Authmethod ਵਿਧੀ_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#ਜੇ_ਅੰਤ
