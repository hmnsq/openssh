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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_GSSAPI_MAX_MECHS	2048

ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ authmethod_cfg methodcfg_gssapi;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_mic(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_exchange_complete(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_gssapi(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ಖಾಲಿ};
	Gssctxt *ctxt = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, present;
	u_int mechs;
	OM_uint32 ms;
	ಗಾತ್ರ_t len;
	u_char *doid = ಖಾಲಿ;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	ಆದರೆ (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ಹಿಂತಿರುಗಿ (0);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ಹಿಂತಿರುಗಿ (0);
	}

	ಮಾಡು {
		mechs--;

		ಬಿಡುಗಡೆ(doid);

		present = 0;
		ಆದರೆ ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		ಆದರೆ (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.ಉದ್ದಳತೆ   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} ಇಲ್ಲದಿದ್ದರೆ {
			logit_f("badly formed OID received");
		}
	} ಆಗ (mechs > 0 && !present);

	ಆದರೆ (!present) {
		ಬಿಡುಗಡೆ(doid);
		authctxt->server_caused_failure = 1;
		ಹಿಂತಿರುಗಿ (0);
	}

	ಆದರೆ (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		ಆದರೆ (ctxt != ಖಾಲಿ)
			ssh_gssapi_delete_ctx(&ctxt);
		ಬಿಡುಗಡೆ(doid);
		authctxt->server_caused_failure = 1;
		ಹಿಂತಿರುಗಿ (0);
	}

	authctxt->methoddata = (ಶೂನ್ಯ *)ctxt;

	/* Return the OID that we received */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಬಿಡುಗಡೆ(doid);

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, &ಒಳಹರಿವು_gssapi_token);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, &ಒಳಹರಿವು_gssapi_errtok);
	authctxt->postponed = 1;

	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_ಬಫರ್_desc send_tok = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	gss_ಬಫರ್_desc recv_tok;
	OM_uint32 maj_ಸ್ಥಿತಿ, min_ಸ್ಥಿತಿ, flags;
	u_char *p;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	ಆದರೆ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.ಉದ್ದಳತೆ = len;
	maj_ಸ್ಥಿತಿ = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	ಬಿಡುಗಡೆ(p);

	ಆದರೆ (GSS_ERROR(maj_ಸ್ಥಿತಿ)) {
		ಆದರೆ (send_tok.ಉದ್ದಳತೆ != 0) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
			    send_tok.ಉದ್ದಳತೆ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ಖಾಲಿ);
		userauth_ಮುಕ್ತಾಯ(ssh, 0, "gssapi-with-mic", ಖಾಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (send_tok.ಉದ್ದಳತೆ != 0) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
			    send_tok.ಉದ್ದಳತೆ)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		ಆದರೆ (maj_ಸ್ಥಿತಿ == GSS_S_COMPLETE) {
			ssh_dispatch_ಗಣ(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			ಆದರೆ (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_ಗಣ(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC,
				    &ಒಳಹರಿವು_gssapi_mic);
			} ಇಲ್ಲದಿದ್ದರೆ {
				ssh_dispatch_ಗಣ(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &ಒಳಹರಿವು_gssapi_exchange_complete);
			}
		}
	}

	gss_release_ಬಫರ್(&min_ಸ್ಥಿತಿ, &send_tok);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ಖಾಲಿ);
	userauth_ಮುಕ್ತಾಯ(ssh, 0, "gssapi-with-mic", ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_exchange_complete(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಪೂರ್ಣಾಂಕ r, authenticated;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ಆದರೆ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ಖಾಲಿ);
	userauth_ಮುಕ್ತಾಯ(ssh, authenticated, "gssapi-with-mic", ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_mic(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ಪೂರ್ಣಾಂಕ r, authenticated = 0;
	ರಚನೆ sshbuf *b;
	gss_ಬಫರ್_desc mic, gssbuf;
	u_char *p;
	ಗಾತ್ರ_t len;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	ಆದರೆ ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	mic.ಮೌಲ್ಯ = p;
	mic.ಉದ್ದಳತೆ = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	ಆದರೆ ((gssbuf.ಮೌಲ್ಯ = sshbuf_mutable_ptr(b)) == ಖಾಲಿ)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.ಉದ್ದಳತೆ = sshbuf_len(b);

	ಆದರೆ (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ಇಲ್ಲದಿದ್ದರೆ
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	ಬಿಡುಗಡೆ(mic.ಮೌಲ್ಯ);

	ಆದರೆ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ಖಾಲಿ);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ಖಾಲಿ);
	userauth_ಮುಕ್ತಾಯ(ssh, authenticated, "gssapi-with-mic", ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ 0;
}

Authmethod ವಿಧಾನ_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#ಆದರೆ_ಅಂತ್ಯ
