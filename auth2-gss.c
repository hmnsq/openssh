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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef GSSAPI

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା authmethod_cfg methodcfg_gssapi;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_token(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_mic(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_exchange_complete(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_errtok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_gssapi(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ଖାଲି};
	Gssctxt *ctxt = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = ଖାଲି;

	ଯଦି ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	ଯଦି (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ଫେରନ୍ତୁ (0);
	} ଅନ୍ୟଥା ଯଦି (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ଫେରନ୍ତୁ (0);
	}

	କର {
		mechs--;

		ମୁକ୍ତ(doid);

		present = 0;
		ଯଦି ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		ଯଦି (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} ଅନ୍ୟଥା {
			logit_f("badly formed OID received");
		}
	} ଯେତେବେଳେ (mechs > 0 && !present);

	ଯଦି (!present) {
		ମୁକ୍ତ(doid);
		authctxt->server_caused_failure = 1;
		ଫେରନ୍ତୁ (0);
	}

	ଯଦି (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		ଯଦି (ctxt != ଖାଲି)
			ssh_gssapi_delete_ctx(&ctxt);
		ମୁକ୍ତ(doid);
		authctxt->server_caused_failure = 1;
		ଫେରନ୍ତୁ (0);
	}

	authctxt->methoddata = (ଶୂନ୍ୟ *)ctxt;

	/* Return the OID that we received */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ମୁକ୍ତ(doid);

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, &ନିବେଶ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, &ନିବେଶ_gssapi_errtok);
	authctxt->postponed = 1;

	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_token(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	ଯଦି ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.ମୂଲ୍ୟ = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	ମୁକ୍ତ(p);

	ଯଦି (GSS_ERROR(maj_status)) {
		ଯଦି (send_tok.length != 0) {
			ଯଦି ((r = sshpkt_start(ssh,
			    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ମୂଲ୍ୟ,
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
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, ଖାଲି);
		userauth_finish(ssh, 0, "gssapi-with-mic", ଖାଲି);
	} ଅନ୍ୟଥା {
		ଯଦି (send_tok.length != 0) {
			ଯଦି ((r = sshpkt_start(ssh,
			    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.ମୂଲ୍ୟ,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		ଯଦି (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			ଯଦି (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_MIC,
				    &ନିବେଶ_gssapi_mic);
			} ଅନ୍ୟଥା {
				ssh_dispatch_set(ssh,
				    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &ନିବେଶ_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_errtok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	ଯଦି ((r = sshpkt_get_string_direct(ssh, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_MIC, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ଖାଲି);
	userauth_finish(ssh, 0, "gssapi-with-mic", ଖାଲି);
	ଫେରନ୍ତୁ 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_exchange_complete(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated;
	ଦ୍ୱିଗୁଣ tstart = monotime_double();

	ଯଦି (authctxt == ଖାଲି)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ଯଦି (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_MIC, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ଖାଲି);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ଖାଲି);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_mic(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authenticated = 0;
	ସଂରଚନା sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	ଦ୍ୱିଗୁଣ tstart = monotime_double();

	ଯଦି (authctxt == ଖାଲି)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	ଯଦି ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	mic.ମୂଲ୍ୟ = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	ଯଦି ((gssbuf.ମୂଲ୍ୟ = sshbuf_mutable_ptr(b)) == ଖାଲି)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	ଯଦି (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	ଅନ୍ୟଥା
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	ମୁକ୍ତ(mic.ମୂଲ୍ୟ);

	ଯଦି (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_MIC, ଖାଲି);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ଖାଲି);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ଖାଲି);
	ଫେରନ୍ତୁ 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
