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

#समावेश "includes.h"

#अगर_घोषित GSSAPI

#समावेश <sys/types.h>

#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "ssh2.h"
#समावेश "log.h"
#समावेश "dispatch.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "packet.h"
#समावेश "kex.h"
#समावेश "ssh-gss.h"
#समावेश "monitor_wrap.h"

#घोषणा SSH_GSSAPI_MAX_MECHS	2048

बाह्य ServerOptions options;
बाह्य काष्ठा authmethod_cfg methodcfg_gssapi;

अटल पूर्णांक निवेश_gssapi_token(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh);
अटल पूर्णांक निवेश_gssapi_mic(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh);
अटल पूर्णांक निवेश_gssapi_exchange_complete(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh);
अटल पूर्णांक निवेश_gssapi_errtok(पूर्णांक, uint32_t, काष्ठा ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
अटल पूर्णांक
userauth_gssapi(काष्ठा ssh *ssh, स्थिर अक्षर *method)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, शून्य};
	Gssctxt *ctxt = शून्य;
	पूर्णांक r, present;
	u_int mechs;
	OM_uint32 ms;
	माप_प्रकार len;
	u_char *doid = शून्य;

	अगर ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	अगर (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		वापस (0);
	} अन्यथा अगर (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		वापस (0);
	}

	करो {
		mechs--;

		मुक्त(doid);

		present = 0;
		अगर ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		अगर (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.लंबाई   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} अन्यथा {
			logit_f("badly formed OID received");
		}
	} जबतक (mechs > 0 && !present);

	अगर (!present) {
		मुक्त(doid);
		authctxt->server_caused_failure = 1;
		वापस (0);
	}

	अगर (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		अगर (ctxt != शून्य)
			ssh_gssapi_delete_ctx(&ctxt);
		मुक्त(doid);
		authctxt->server_caused_failure = 1;
		वापस (0);
	}

	authctxt->methoddata = (व्योम *)ctxt;

	/* Return the OID that we received */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	मुक्त(doid);

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, &निवेश_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, &निवेश_gssapi_errtok);
	authctxt->postponed = 1;

	वापस (0);
}

अटल पूर्णांक
निवेश_gssapi_token(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_बफर_desc send_tok = GSS_C_EMPTY_बफर;
	gss_बफर_desc recv_tok;
	OM_uint32 maj_status, min_status, flags;
	u_char *p;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	अगर ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.मूल्य = p;
	recv_tok.लंबाई = len;
	maj_status = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	मुक्त(p);

	अगर (GSS_ERROR(maj_status)) {
		अगर (send_tok.लंबाई != 0) {
			अगर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
			    send_tok.लंबाई)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, शून्य);
		userauth_finish(ssh, 0, "gssapi-with-mic", शून्य);
	} अन्यथा {
		अगर (send_tok.लंबाई != 0) {
			अगर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
			    send_tok.लंबाई)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		अगर (maj_status == GSS_S_COMPLETE) {
			ssh_dispatch_set(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			अगर (flags & GSS_C_INTEG_FLAG) {
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

	gss_release_बफर(&min_status, &send_tok);
	वापस 0;
}

अटल पूर्णांक
निवेश_gssapi_errtok(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	अगर ((r = sshpkt_get_string_direct(ssh, शून्य, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, शून्य);
	userauth_finish(ssh, 0, "gssapi-with-mic", शून्य);
	वापस 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

अटल पूर्णांक
निवेश_gssapi_exchange_complete(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	पूर्णांक r, authenticated;
	द्विगुन tstart = monotime_double();

	अगर (authctxt == शून्य)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	अगर ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	अगर (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, शून्य);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", शून्य);
	वापस 0;
}

अटल पूर्णांक
निवेश_gssapi_mic(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	पूर्णांक r, authenticated = 0;
	काष्ठा sshbuf *b;
	gss_बफर_desc mic, gssbuf;
	u_char *p;
	माप_प्रकार len;
	द्विगुन tstart = monotime_double();

	अगर (authctxt == शून्य)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	अगर ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	mic.मूल्य = p;
	mic.लंबाई = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	अगर ((gssbuf.मूल्य = sshbuf_mutable_ptr(b)) == शून्य)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.लंबाई = sshbuf_len(b);

	अगर (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	अन्यथा
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	मुक्त(mic.मूल्य);

	अगर (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_MIC, शून्य);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, शून्य);
	userauth_finish(ssh, authenticated, "gssapi-with-mic", शून्य);
	वापस 0;
}

Authmethod method_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#पूर्ण_अगर
