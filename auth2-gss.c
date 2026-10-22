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

#অন্তর্ভাৱ "includes.h"

#ifdef GSSAPI

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "ssh-gss.h"
#অন্তর্ভাৱ "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

বাহ্য ServerOptions options;
বাহ্য সংরচনা authmethod_cfg methodcfg_gssapi;

স্থির পূর্ণাঙ্ক প্ৰবেশ_gssapi_token(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh);
স্থির পূর্ণাঙ্ক প্ৰবেশ_gssapi_mic(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh);
স্থির পূর্ণাঙ্ক প্ৰবেশ_gssapi_exchange_complete(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh);
স্থির পূর্ণাঙ্ক প্ৰবেশ_gssapi_errtok(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
স্থির পূর্ণাঙ্ক
userauth_gssapi(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, রিক্ত};
	Gssctxt *ctxt = রিক্ত;
	পূর্ণাঙ্ক r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = রিক্ত;

	যদি ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	যদি (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		ঘূৰাই (0);
	} অন্যথা যদি (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		ঘূৰাই (0);
	}

	কৰা {
		mechs--;

		মুক্ত(doid);

		present = 0;
		যদি ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		যদি (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} অন্যথা {
			logit_f("badly formed OID received");
		}
	} যেতিয়ালৈ (mechs > 0 && !present);

	যদি (!present) {
		মুক্ত(doid);
		authctxt->server_caused_failure = 1;
		ঘূৰাই (0);
	}

	যদি (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		যদি (ctxt != রিক্ত)
			ssh_gssapi_delete_ctx(&ctxt);
		মুক্ত(doid);
		authctxt->server_caused_failure = 1;
		ঘূৰাই (0);
	}

	authctxt->methoddata = (শূন্য *)ctxt;

	/* Return the OID that we received */
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	মুক্ত(doid);

	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, &প্ৰবেশ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK, &প্ৰবেশ_gssapi_errtok);
	authctxt->postponed = 1;

	ঘূৰাই (0);
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_gssapi_token(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.মান = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	মুক্ত(p);

	যদি (GSS_ERROR(maj_status)) {
		যদি (send_tok.length != 0) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.মান,
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
		ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
		ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK, রিক্ত);
		userauth_finish(ssh, 0, "gssapi-with-mic", রিক্ত);
	} অন্যথা {
		যদি (send_tok.length != 0) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.মান,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		যদি (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			যদি (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_বাৰ্তা_USERAUTH_GSSAPI_MIC,
				    &প্ৰবেশ_gssapi_mic);
			} অন্যথা {
				ssh_dispatch_set(ssh,
				    SSH2_বাৰ্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &প্ৰবেশ_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_gssapi_errtok(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	যদি ((r = sshpkt_get_string_direct(ssh, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_MIC, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, রিক্ত);
	userauth_finish(ssh, 0, "gssapi-with-mic", রিক্ত);
	ঘূৰাই 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

স্থির পূর্ণাঙ্ক
প্ৰবেশ_gssapi_exchange_complete(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	পূর্ণাঙ্ক r, authenticated;
	দ্ৱিগুণ tstart = monotime_double();

	যদি (authctxt == রিক্ত)
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
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_MIC, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, রিক্ত);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", রিক্ত);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_gssapi_mic(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	পূর্ণাঙ্ক r, authenticated = 0;
	সংরচনা sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	দ্ৱিগুণ tstart = monotime_double();

	যদি (authctxt == রিক্ত)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	mic.মান = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	যদি ((gssbuf.মান = sshbuf_mutable_ptr(b)) == রিক্ত)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	যদি (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	অন্যথা
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	মুক্ত(mic.মান);

	যদি (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_TOKEN, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_ERRTOK, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_MIC, রিক্ত);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, রিক্ত);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", রিক্ত);
	ঘূৰাই 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
