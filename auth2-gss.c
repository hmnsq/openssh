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

#ifdef GSSAPI

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

#define SSH_GSSAPI_MAX_MECHS	2048

ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ authmethod_cfg methodcfg_gssapi;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_mic(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_exchange_complete(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_gssapi(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ರಿಕ್ತ};
	Gssctxt *ctxt = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = ರಿಕ್ತ;

	ಯದಿ ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	ಯದಿ (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ಪ್ರತ್ಯಾಗಮ (0);
	} ಅನ್ಯಥಾ ಯದಿ (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಕುರು {
		mechs--;

		ಮುಕ್ತ(doid);

		present = 0;
		ಯದಿ ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		ಯದಿ (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} ಅನ್ಯಥಾ {
			logit_f("badly formed OID received");
		}
	} ಯಾವತ್ (mechs > 0 && !present);

	ಯದಿ (!present) {
		ಮುಕ್ತ(doid);
		authctxt->server_caused_failure = 1;
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	ಯದಿ (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		ಯದಿ (ctxt != ರಿಕ್ತ)
			ssh_gssapi_delete_ctx(&ctxt);
		ಮುಕ್ತ(doid);
		authctxt->server_caused_failure = 1;
		ಪ್ರತ್ಯಾಗಮ (0);
	}

	authctxt->methoddata = (ಶೂನ್ಯ *)ctxt;

	/* Return the OID that we received */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಮುಕ್ತ(doid);

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, &ಒಳಹರಿವು_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, &ಒಳಹರಿವು_gssapi_errtok);
	authctxt->postponed = 1;

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	ಯದಿ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	ಮುಕ್ತ(p);

	ಯದಿ (GSS_ERROR(maj_status)) {
		ಯದಿ (send_tok.length != 0) {
			ಯದಿ ((r = sshpkt_start(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ರಿಕ್ತ);
		userauth_finish(ssh, 0, "gssapi-with-mic", ರಿಕ್ತ);
	} ಅನ್ಯಥಾ {
		ಯದಿ (send_tok.length != 0) {
			ಯದಿ ((r = sshpkt_start(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		ಯದಿ (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			ಯದಿ (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC,
				    &ಒಳಹರಿವು_gssapi_mic);
			} ಅನ್ಯಥಾ {
				ssh_dispatch_set(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &ಒಳಹರಿವು_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	ಯದಿ ((r = sshpkt_get_string_direct(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ರಿಕ್ತ);
	userauth_finish(ssh, 0, "gssapi-with-mic", ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_exchange_complete(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ಯದಿ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ರಿಕ್ತ);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_mic(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ಪೂರ್ಣಾಙ್ಕ r, authenticated = 0;
	ಸಂರಚನಾ sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	ಯದಿ ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	mic.ಮೌಲ್ಯ = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	ಯದಿ ((gssbuf.ಮೌಲ್ಯ = sshbuf_mutable_ptr(b)) == ರಿಕ್ತ)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	ಯದಿ (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ಅನ್ಯಥಾ
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	ಮುಕ್ತ(mic.ಮೌಲ್ಯ);

	ಯದಿ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC, ರಿಕ್ತ);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ರಿಕ್ತ);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
