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

#അന്തര്ഭാവ "includes.h"

#ifdef GSSAPI

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "ssh-gss.h"
#അന്തര്ഭാവ "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന authmethod_cfg methodcfg_gssapi;

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_token(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_mic(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_exchange_complete(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_errtok(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_gssapi(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, ശൂന്യ};
	Gssctxt *ctxt = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = ശൂന്യ;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	എങ്കിൽ (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		തിരികെ (0);
	} അല്ലെങ്കിൽ എങ്കിൽ (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		തിരികെ (0);
	}

	ചെയ്യുക {
		mechs--;

		സ്വതന്ത്രം(doid);

		present = 0;
		എങ്കിൽ ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		എങ്കിൽ (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} അല്ലെങ്കിൽ {
			logit_f("badly formed OID received");
		}
	} ആകുമ്പോൾ (mechs > 0 && !present);

	എങ്കിൽ (!present) {
		സ്വതന്ത്രം(doid);
		authctxt->server_caused_failure = 1;
		തിരികെ (0);
	}

	എങ്കിൽ (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		എങ്കിൽ (ctxt != ശൂന്യ)
			ssh_gssapi_delete_ctx(&ctxt);
		സ്വതന്ത്രം(doid);
		authctxt->server_caused_failure = 1;
		തിരികെ (0);
	}

	authctxt->methoddata = (ശൂന്യം *)ctxt;

	/* Return the OID that we received */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	സ്വതന്ത്രം(doid);

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, &നിവേശം_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, &നിവേശം_gssapi_errtok);
	authctxt->postponed = 1;

	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_token(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	എങ്കിൽ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.മൂല്യം = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	സ്വതന്ത്രം(p);

	എങ്കിൽ (GSS_ERROR(maj_status)) {
		എങ്കിൽ (send_tok.length != 0) {
			എങ്കിൽ ((r = sshpkt_start(ssh,
			    SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.മൂല്യം,
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
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, ശൂന്യ);
		userauth_finish(ssh, 0, "gssapi-with-mic", ശൂന്യ);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (send_tok.length != 0) {
			എങ്കിൽ ((r = sshpkt_start(ssh,
			    SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.മൂല്യം,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		എങ്കിൽ (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			എങ്കിൽ (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC,
				    &നിവേശം_gssapi_mic);
			} അല്ലെങ്കിൽ {
				ssh_dispatch_set(ssh,
				    SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &നിവേശം_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_errtok(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ശൂന്യ);
	userauth_finish(ssh, 0, "gssapi-with-mic", ശൂന്യ);
	തിരികെ 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_exchange_complete(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	പൂർണ്ണസംഖ്യ r, authenticated;
	ഇരട്ട tstart = monotime_double();

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	എങ്കിൽ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ശൂന്യ);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ശൂന്യ);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_mic(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	പൂർണ്ണസംഖ്യ r, authenticated = 0;
	ഘടന sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	ഇരട്ട tstart = monotime_double();

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	എങ്കിൽ ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	mic.മൂല്യം = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	എങ്കിൽ ((gssbuf.മൂല്യം = sshbuf_mutable_ptr(b)) == ശൂന്യ)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	എങ്കിൽ (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	അല്ലെങ്കിൽ
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	സ്വതന്ത്രം(mic.മൂല്യം);

	എങ്കിൽ (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC, ശൂന്യ);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, ശൂന്യ);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", ശൂന്യ);
	തിരികെ 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
