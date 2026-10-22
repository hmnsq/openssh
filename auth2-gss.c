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

#அந்தர்பாவ "includes.h"

#ifdef GSSAPI

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "ssh-gss.h"
#அந்தர்பாவ "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

வெளி ServerOptions options;
வெளி கட்டமைப்பு authmethod_cfg methodcfg_gssapi;

நிலையான முழு உள்ளீடு_gssapi_token(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh);
நிலையான முழு உள்ளீடு_gssapi_mic(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh);
நிலையான முழு உள்ளீடு_gssapi_exchange_complete(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh);
நிலையான முழு உள்ளீடு_gssapi_errtok(முழு, uint32_t, கட்டமைப்பு ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
நிலையான முழு
userauth_gssapi(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, வெற்று};
	Gssctxt *ctxt = வெற்று;
	முழு r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = வெற்று;

	எனில் ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	எனில் (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		திரும்பு (0);
	} இல்லையெனில் எனில் (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		திரும்பு (0);
	}

	செய் {
		mechs--;

		விடுவி(doid);

		present = 0;
		எனில் ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		எனில் (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} இல்லையெனில் {
			logit_f("badly formed OID received");
		}
	} போது (mechs > 0 && !present);

	எனில் (!present) {
		விடுவி(doid);
		authctxt->server_caused_failure = 1;
		திரும்பு (0);
	}

	எனில் (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		எனில் (ctxt != வெற்று)
			ssh_gssapi_delete_ctx(&ctxt);
		விடுவி(doid);
		authctxt->server_caused_failure = 1;
		திரும்பு (0);
	}

	authctxt->methoddata = (வெறுமை *)ctxt;

	/* Return the OID that we received */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	விடுவி(doid);

	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, &உள்ளீடு_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, &உள்ளீடு_gssapi_errtok);
	authctxt->postponed = 1;

	திரும்பு (0);
}

நிலையான முழு
உள்ளீடு_gssapi_token(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	எனில் ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.மதிப்பு = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	விடுவி(p);

	எனில் (GSS_ERROR(maj_status)) {
		எனில் (send_tok.length != 0) {
			எனில் ((r = sshpkt_start(ssh,
			    SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.மதிப்பு,
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
		ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
		ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, வெற்று);
		userauth_finish(ssh, 0, "gssapi-with-mic", வெற்று);
	} இல்லையெனில் {
		எனில் (send_tok.length != 0) {
			எனில் ((r = sshpkt_start(ssh,
			    SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.மதிப்பு,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		எனில் (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			எனில் (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_செய்தி_USERAUTH_GSSAPI_MIC,
				    &உள்ளீடு_gssapi_mic);
			} இல்லையெனில் {
				ssh_dispatch_set(ssh,
				    SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &உள்ளீடு_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_gssapi_errtok(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	எனில் ((r = sshpkt_get_string_direct(ssh, வெற்று, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_MIC, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, வெற்று);
	userauth_finish(ssh, 0, "gssapi-with-mic", வெற்று);
	திரும்பு 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

நிலையான முழு
உள்ளீடு_gssapi_exchange_complete(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	முழு r, authenticated;
	இரட்டை tstart = monotime_double();

	எனில் (authctxt == வெற்று)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	எனில் (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_MIC, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, வெற்று);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", வெற்று);
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_gssapi_mic(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	முழு r, authenticated = 0;
	கட்டமைப்பு sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	இரட்டை tstart = monotime_double();

	எனில் (authctxt == வெற்று)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	எனில் ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	mic.மதிப்பு = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	எனில் ((gssbuf.மதிப்பு = sshbuf_mutable_ptr(b)) == வெற்று)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	எனில் (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	இல்லையெனில்
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	விடுவி(mic.மதிப்பு);

	எனில் (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_MIC, வெற்று);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, வெற்று);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", வெற்று);
	திரும்பு 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
