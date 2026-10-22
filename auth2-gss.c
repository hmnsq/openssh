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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే GSSAPI

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "ssh-gss.h"
#అన్తర్భావ "monitor_wrap.h"

#నిర్వచించు SSH_GSSAPI_MAX_MECHS	2048

బాహ్య ServerOptions options;
బాహ్య నిర్మాణం authmethod_cfg methodcfg_gssapi;

స్థిర పూర్ణాంకం ఆదానం_gssapi_token(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh);
స్థిర పూర్ణాంకం ఆదానం_gssapi_mic(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh);
స్థిర పూర్ణాంకం ఆదానం_gssapi_exchange_complete(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh);
స్థిర పూర్ణాంకం ఆదానం_gssapi_errtok(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
స్థిర పూర్ణాంకం
userauth_gssapi(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ఖాళీ};
	Gssctxt *ctxt = ఖాళీ;
	పూర్ణాంకం r, present;
	u_int mechs;
	OM_uint32 ms;
	కొలత_t len;
	u_char *doid = ఖాళీ;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	ఒకవేళ (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		తిరిగి (0);
	} లేకపోతే ఒకవేళ (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		తిరిగి (0);
	}

	చేయి {
		mechs--;

		విడుదల(doid);

		present = 0;
		ఒకవేళ ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		ఒకవేళ (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.నిడివి   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} లేకపోతే {
			logit_f("badly formed OID received");
		}
	} అయితే (mechs > 0 && !present);

	ఒకవేళ (!present) {
		విడుదల(doid);
		authctxt->server_caused_failure = 1;
		తిరిగి (0);
	}

	ఒకవేళ (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		ఒకవేళ (ctxt != ఖాళీ)
			ssh_gssapi_delete_ctx(&ctxt);
		విడుదల(doid);
		authctxt->server_caused_failure = 1;
		తిరిగి (0);
	}

	authctxt->methoddata = (శూన్య *)ctxt;

	/* Return the OID that we received */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	విడుదల(doid);

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, &ఆదానం_gssapi_token);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, &ఆదానం_gssapi_errtok);
	authctxt->postponed = 1;

	తిరిగి (0);
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_token(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_బఫరు_desc send_tok = GSS_C_ఖాళీలు_బఫరు;
	gss_బఫరు_desc recv_tok;
	OM_uint32 maj_స్థితి, min_స్థితి, flags;
	u_char *p;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	ఒకవేళ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.విలువ = p;
	recv_tok.నిడివి = len;
	maj_స్థితి = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	విడుదల(p);

	ఒకవేళ (GSS_ERROR(maj_స్థితి)) {
		ఒకవేళ (send_tok.నిడివి != 0) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
			    SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.విలువ,
			    send_tok.నిడివి)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, ఖాళీ);
		userauth_ముగింపు(ssh, 0, "gssapi-with-mic", ఖాళీ);
	} లేకపోతే {
		ఒకవేళ (send_tok.నిడివి != 0) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
			    SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.విలువ,
			    send_tok.నిడివి)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		ఒకవేళ (maj_స్థితి == GSS_S_COMPLETE) {
			ssh_dispatch_సమితి(ssh,
			    SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			ఒకవేళ (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_సమితి(ssh,
				    SSH2_సందేశం_USERAUTH_GSSAPI_MIC,
				    &ఆదానం_gssapi_mic);
			} లేకపోతే {
				ssh_dispatch_సమితి(ssh,
				    SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &ఆదానం_gssapi_exchange_complete);
			}
		}
	}

	gss_release_బఫరు(&min_స్థితి, &send_tok);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_errtok(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_MIC, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ఖాళీ);
	userauth_ముగింపు(ssh, 0, "gssapi-with-mic", ఖాళీ);
	తిరిగి 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

స్థిర పూర్ణాంకం
ఆదానం_gssapi_exchange_complete(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	పూర్ణాంకం r, authenticated;
	ద్విగుణ tstart = monotime_double();

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ఒకవేళ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_MIC, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ఖాళీ);
	userauth_ముగింపు(ssh, authenticated, "gssapi-with-mic", ఖాళీ);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_mic(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	పూర్ణాంకం r, authenticated = 0;
	నిర్మాణం sshbuf *b;
	gss_బఫరు_desc mic, gssbuf;
	u_char *p;
	కొలత_t len;
	ద్విగుణ tstart = monotime_double();

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	ఒకవేళ ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	mic.విలువ = p;
	mic.నిడివి = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	ఒకవేళ ((gssbuf.విలువ = sshbuf_mutable_ptr(b)) == ఖాళీ)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.నిడివి = sshbuf_len(b);

	ఒకవేళ (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	లేకపోతే
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	విడుదల(mic.విలువ);

	ఒకవేళ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_MIC, ఖాళీ);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ఖాళీ);
	userauth_ముగింపు(ssh, authenticated, "gssapi-with-mic", ఖాళీ);
	తిరిగి 0;
}

Authmethod పద్ధతి_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#అయితే_ముగింపు
