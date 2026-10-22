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

#অন্তর্ভাব "includes.h"

#ifdef GSSAPI

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "ssh-gss.h"
#অন্তর্ভাব "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

বাহ্যিক ServerOptions options;
বাহ্যিক কাঠামো authmethod_cfg methodcfg_gssapi;

স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_token(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_mic(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_exchange_complete(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_errtok(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
স্থির পূর্ণসংখ্যা
userauth_gssapi(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ফাঁকা};
	Gssctxt *ctxt = ফাঁকা;
	পূর্ণসংখ্যা r, present;
	u_int mechs;
	OM_uint32 ms;
	আকার_t len;
	u_char *doid = ফাঁকা;

	যদি ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	যদি (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ফেরত (0);
	} অন্যথা যদি (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ফেরত (0);
	}

	করো {
		mechs--;

		মুক্ত(doid);

		present = 0;
		যদি ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		যদি (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.দৈর্ঘ্য   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} অন্যথা {
			logit_f("badly formed OID received");
		}
	} যখন (mechs > 0 && !present);

	যদি (!present) {
		মুক্ত(doid);
		authctxt->server_caused_failure = 1;
		ফেরত (0);
	}

	যদি (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		যদি (ctxt != ফাঁকা)
			ssh_gssapi_delete_ctx(&ctxt);
		মুক্ত(doid);
		authctxt->server_caused_failure = 1;
		ফেরত (0);
	}

	authctxt->methoddata = (শূন্য *)ctxt;

	/* Return the OID that we received */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	মুক্ত(doid);

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, &প্রবেশ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, &প্রবেশ_gssapi_errtok);
	authctxt->postponed = 1;

	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_token(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_বাফার_desc send_tok = GSS_C_EMPTY_বাফার;
	gss_বাফার_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.মান = p;
	recv_tok.দৈর্ঘ্য = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	মুক্ত(p);

	যদি (GSS_ERROR(maj_status)) {
		যদি (send_tok.দৈর্ঘ্য != 0) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.মান,
			    send_tok.দৈর্ঘ্য)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, ফাঁকা);
		ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, ফাঁকা);
		userauth_finish(ssh, 0, "gssapi-with-mic", ফাঁকা);
	} অন্যথা {
		যদি (send_tok.দৈর্ঘ্য != 0) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.মান,
			    send_tok.দৈর্ঘ্য)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		যদি (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, ফাঁকা);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			যদি (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_বার্তা_USERAUTH_GSSAPI_MIC,
				    &প্রবেশ_gssapi_mic);
			} অন্যথা {
				ssh_dispatch_set(ssh,
				    SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &প্রবেশ_gssapi_exchange_complete);
			}
		}
	}

	gss_release_বাফার(&min_status, &send_tok);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_errtok(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	যদি ((r = sshpkt_get_string_direct(ssh, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_MIC, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ফাঁকা);
	userauth_finish(ssh, 0, "gssapi-with-mic", ফাঁকা);
	ফেরত 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_exchange_complete(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	পূর্ণসংখ্যা r, authenticated;
	দ্বিগুণ tstart = monotime_double();

	যদি (authctxt == ফাঁকা)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	যদি (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_MIC, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ফাঁকা);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ফাঁকা);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_mic(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	পূর্ণসংখ্যা r, authenticated = 0;
	কাঠামো sshbuf *b;
	gss_বাফার_desc mic, gssbuf;
	u_char *p;
	আকার_t len;
	দ্বিগুণ tstart = monotime_double();

	যদি (authctxt == ফাঁকা)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	mic.মান = p;
	mic.দৈর্ঘ্য = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	যদি ((gssbuf.মান = sshbuf_mutable_ptr(b)) == ফাঁকা)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.দৈর্ঘ্য = sshbuf_len(b);

	যদি (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	অন্যথা
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	মুক্ত(mic.মান);

	যদি (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_MIC, ফাঁকা);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ফাঁকা);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ফাঁকা);
	ফেরত 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
