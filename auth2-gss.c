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

#अन्तर्भाव "includes.h"

#ifdef GSSAPI

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "ssh-gss.h"
#अन्तर्भाव "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

बाह्य ServerOptions options;
बाह्य संरचना authmethod_cfg methodcfg_gssapi;

स्थिर पूर्णाङ्क निवेश_gssapi_token(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh);
स्थिर पूर्णाङ्क निवेश_gssapi_mic(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh);
स्थिर पूर्णाङ्क निवेश_gssapi_exchange_complete(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh);
स्थिर पूर्णाङ्क निवेश_gssapi_errtok(पूर्णाङ्क, uint32_t, संरचना ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
स्थिर पूर्णाङ्क
userauth_gssapi(संरचना ssh *ssh, ध्रुव वर्ण *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, रिक्त};
	Gssctxt *ctxt = रिक्त;
	पूर्णाङ्क r, present;
	u_int mechs;
	OM_uint32 ms;
	माप_प्रकार len;
	u_char *doid = रिक्त;

	यदि ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	यदि (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		प्रत्यागम (0);
	} अन्यथा यदि (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		प्रत्यागम (0);
	}

	कुरु {
		mechs--;

		मुक्त(doid);

		present = 0;
		यदि ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		यदि (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} अन्यथा {
			logit_f("badly formed OID received");
		}
	} यावत् (mechs > 0 && !present);

	यदि (!present) {
		मुक्त(doid);
		authctxt->server_caused_failure = 1;
		प्रत्यागम (0);
	}

	यदि (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		यदि (ctxt != रिक्त)
			ssh_gssapi_delete_ctx(&ctxt);
		मुक्त(doid);
		authctxt->server_caused_failure = 1;
		प्रत्यागम (0);
	}

	authctxt->methoddata = (शून्य *)ctxt;

	/* Return the OID that we received */
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	मुक्त(doid);

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, &निवेश_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, &निवेश_gssapi_errtok);
	authctxt->postponed = 1;

	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
निवेश_gssapi_token(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	माप_प्रकार len;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	यदि ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.मूल्य = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	मुक्त(p);

	यदि (GSS_ERROR(maj_status)) {
		यदि (send_tok.length != 0) {
			यदि ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
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
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, रिक्त);
		userauth_finish(ssh, 0, "gssapi-with-mic", रिक्त);
	} अन्यथा {
		यदि (send_tok.length != 0) {
			यदि ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		यदि (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			यदि (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_संदेश_USERAUTH_GSSAPI_MIC,
				    &निवेश_gssapi_mic);
			} अन्यथा {
				ssh_dispatch_set(ssh,
				    SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &निवेश_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेश_gssapi_errtok(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	यदि ((r = sshpkt_get_string_direct(ssh, रिक्त, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
	userauth_finish(ssh, 0, "gssapi-with-mic", रिक्त);
	प्रत्यागम 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

स्थिर पूर्णाङ्क
निवेश_gssapi_exchange_complete(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	पूर्णाङ्क r, authenticated;
	द्विगुण tstart = monotime_double();

	यदि (authctxt == रिक्त)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	यदि ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	यदि (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", रिक्त);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेश_gssapi_mic(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	पूर्णाङ्क r, authenticated = 0;
	संरचना sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	माप_प्रकार len;
	द्विगुण tstart = monotime_double();

	यदि (authctxt == रिक्त)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	यदि ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	mic.मूल्य = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	यदि ((gssbuf.मूल्य = sshbuf_mutable_ptr(b)) == रिक्त)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	यदि (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	अन्यथा
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	मुक्त(mic.मूल्य);

	यदि (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, रिक्त);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, रिक्त);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", रिक्त);
	प्रत्यागम 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
