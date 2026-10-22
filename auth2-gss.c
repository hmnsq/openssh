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

#include "includes.h"

#ifdef GSSAPI

#include <sys/types.h>

#include <stdarg.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "misc.h"
#include "servconf.h"
#include "packet.h"
#include "kex.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"

#define SSH_GSSAPI_MAX_MECHS	2048

extern ServerOptions options;
extern struct authmethod_cfg methodcfg_gssapi;

static ціле input_gssapi_token(ціле type, uint32_t plen, struct ssh *ssh);
static ціле input_gssapi_mic(ціле type, uint32_t plen, struct ssh *ssh);
static ціле input_gssapi_exchange_complete(ціле type, uint32_t plen, struct ssh *ssh);
static ціле input_gssapi_errtok(ціле, uint32_t, struct ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
static ціле
userauth_gssapi(struct ssh *ssh, const char *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, NULL};
	Gssctxt *ctxt = NULL;
	ціле r, present;
	u_int mechs;
	OM_uint32 ms;
	size_t len;
	u_char *doid = NULL;

	якщо ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	якщо (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		повернути (0);
	} інакше якщо (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		повернути (0);
	}

	do {
		mechs--;

		free(doid);

		present = 0;
		якщо ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		якщо (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} інакше {
			logit_f("badly formed OID received");
		}
	} поки (mechs > 0 && !present);

	якщо (!present) {
		free(doid);
		authctxt->server_caused_failure = 1;
		повернути (0);
	}

	якщо (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		якщо (ctxt != NULL)
			ssh_gssapi_delete_ctx(&ctxt);
		free(doid);
		authctxt->server_caused_failure = 1;
		повернути (0);
	}

	authctxt->methoddata = (void *)ctxt;

	/* Return the OID that we received */
	якщо ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	free(doid);

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);
	authctxt->postponed = 1;

	повернути (0);
}

static ціле
input_gssapi_token(ціле type, uint32_t plen, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	size_t len;
	ціле r;

	якщо (authctxt == NULL)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	якщо ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.value = p;
	recv_tok.length = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	free(p);

	якщо (GSS_ERROR(maj_status)) {
		якщо (send_tok.length != 0) {
			якщо ((r = sshpkt_start(ssh,
			    SSH2_MSG_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value,
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
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
		userauth_finish(ssh, 0, "gssapi-with-mic", NULL);
	} інакше {
		якщо (send_tok.length != 0) {
			якщо ((r = sshpkt_start(ssh,
			    SSH2_MSG_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value,
			    send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		якщо (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			якщо (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_set(ssh,
				    SSH2_MSG_USERAUTH_GSSAPI_MIC,
				    &input_gssapi_mic);
			} інакше {
				ssh_dispatch_set(ssh,
				    SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &input_gssapi_exchange_complete);
			}
		}
	}

	gss_release_buffer(&min_status, &send_tok);
	повернути 0;
}

static ціле
input_gssapi_errtok(ціле type, uint32_t plen, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ціле r;

	якщо (authctxt == NULL)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	якщо ((r = sshpkt_get_string_direct(ssh, NULL, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(ssh, 0, "gssapi-with-mic", NULL);
	повернути 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

static ціле
input_gssapi_exchange_complete(ціле type, uint32_t plen, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ціле r, authenticated;
	double tstart = monotime_double();

	якщо (authctxt == NULL)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	якщо ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	якщо (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", NULL);
	повернути 0;
}

static ціле
input_gssapi_mic(ціле type, uint32_t plen, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ціле r, authenticated = 0;
	struct sshbuf *b;
	gss_buffer_desc mic, gssbuf;
	u_char *p;
	size_t len;
	double tstart = monotime_double();

	якщо (authctxt == NULL)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	якщо ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	якщо ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mic.value = p;
	mic.length = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	якщо ((gssbuf.value = sshbuf_mutable_ptr(b)) == NULL)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.length = sshbuf_len(b);

	якщо (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	інакше
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	free(mic.value);

	якщо (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", NULL);
	повернути 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#endif
