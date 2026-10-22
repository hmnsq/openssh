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

#અન્તર્ભાવ "includes.h"

#ifdef GSSAPI

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "ssh-gss.h"
#અન્તર્ભાવ "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

બાહ્ય ServerOptions options;
બાહ્ય સંરચના authmethod_cfg methodcfg_gssapi;

સ્થિર પૂર્ણાંક આગત_gssapi_token(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh);
સ્થિર પૂર્ણાંક આગત_gssapi_mic(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh);
સ્થિર પૂર્ણાંક આગત_gssapi_exchange_complete(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh);
સ્થિર પૂર્ણાંક આગત_gssapi_errtok(પૂર્ણાંક, uint32_t, સંરચના ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
સ્થિર પૂર્ણાંક
userauth_gssapi(સંરચના ssh *ssh, અચલ અક્ષર *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ખાલી};
	Gssctxt *ctxt = ખાલી;
	પૂર્ણાંક r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = ખાલી;

	જો ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	જો (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		પાછા (0);
	} નહીંતર જો (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		પાછા (0);
	}

	કરો {
		mechs--;

		મુક્ત(doid);

		present = 0;
		જો ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		જો (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} નહીંતર {
			logit_f("badly formed OID received");
		}
	} જ્યારે (mechs > 0 && !present);

	જો (!present) {
		મુક્ત(doid);
		authctxt->server_caused_failure = 1;
		પાછા (0);
	}

	જો (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		જો (ctxt != ખાલી)
			ssh_gssapi_delete_ctx(&ctxt);
		મુક્ત(doid);
		authctxt->server_caused_failure = 1;
		પાછા (0);
	}

	authctxt->methoddata = (શૂન્ય *)ctxt;

	/* Return the OID that we received */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	મુક્ત(doid);

	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, &આગત_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, &આગત_gssapi_errtok);
	authctxt->postponed = 1;

	પાછા (0);
}

સ્થિર પૂર્ણાંક
આગત_gssapi_token(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	જો ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.કિંમત = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	મુક્ત(p);

	જો (GSS_ERROR(maj_status)) {
		જો (send_tok.length != 0) {
			જો ((r = sshpkt_start(ssh,
			    SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.કિંમત,
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
		ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
		ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, ખાલી);
		userauth_finish(ssh, 0, "gssapi-with-mic", ખાલી);
	} નહીંતર {
		જો (send_tok.length != 0) {
			જો ((r = sshpkt_start(ssh,
			    SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.કિંમત,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		જો (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			જો (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_સંદેશ_USERAUTH_GSSAPI_MIC,
				    &આગત_gssapi_mic);
			} નહીંતર {
				ssh_dispatch_set(ssh,
				    SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &આગત_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_errtok(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	જો ((r = sshpkt_get_string_direct(ssh, ખાલી, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_MIC, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ખાલી);
	userauth_finish(ssh, 0, "gssapi-with-mic", ખાલી);
	પાછા 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

સ્થિર પૂર્ણાંક
આગત_gssapi_exchange_complete(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	પૂર્ણાંક r, authenticated;
	દ્વિગુણ tstart = monotime_double();

	જો (authctxt == ખાલી)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	જો ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	જો (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_MIC, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ખાલી);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ખાલી);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_mic(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	પૂર્ણાંક r, authenticated = 0;
	સંરચના sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	દ્વિગુણ tstart = monotime_double();

	જો (authctxt == ખાલી)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	જો ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	mic.કિંમત = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	જો ((gssbuf.કિંમત = sshbuf_mutable_ptr(b)) == ખાલી)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	જો (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	નહીંતર
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	મુક્ત(mic.કિંમત);

	જો (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_MIC, ખાલી);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ખાલી);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ખાલી);
	પાછા 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
