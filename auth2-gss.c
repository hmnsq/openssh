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

#ضمن "includes.h"

#اگر_تعریف_شده GSSAPI

#ضمن <sys/types.h>

#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "ssh2.h"
#ضمن "log.h"
#ضمن "dispatch.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "packet.h"
#ضمن "kex.h"
#ضمن "ssh-gss.h"
#ضمن "monitor_wrap.h"

#تعریف_کن SSH_GSSAPI_MAX_MECHS	2048

خارجي ServerOptions options;
خارجي بنية authmethod_cfg methodcfg_gssapi;

ساكن صحيح درون_داد_gssapi_token(صحيح type, uint32_t plen, بنية ssh *ssh);
ساكن صحيح درون_داد_gssapi_mic(صحيح type, uint32_t plen, بنية ssh *ssh);
ساكن صحيح درون_داد_gssapi_exchange_complete(صحيح type, uint32_t plen, بنية ssh *ssh);
ساكن صحيح درون_داد_gssapi_errtok(صحيح, uint32_t, بنية ssh *);

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
ساكن صحيح
userauth_gssapi(بنية ssh *ssh, ثابت حرف *روش)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_OID_desc goid = {0, عدم};
	Gssctxt *ctxt = عدم;
	صحيح r, present;
	u_int mechs;
	OM_uint32 ms;
	اندازه_t len;
	u_char *doid = عدم;

	إذا ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
		fatal_fr(r, "parse packet");

	إذا (mechs == 0) {
		logit_f("mechanism negotiation is not supported");
		أرجع (0);
	} وإلا إذا (mechs > SSH_GSSAPI_MAX_MECHS) {
		logit_f("too many mechanisms requested %u > %u", mechs,
		    SSH_GSSAPI_MAX_MECHS);
		أرجع (0);
	}

	افعل {
		mechs--;

		حرر(doid);

		present = 0;
		إذا ((r = sshpkt_get_string(ssh, &doid, &len)) != 0)
			fatal_fr(r, "parse oid");

		إذا (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.درازی   = len - 2;
			ssh_gssapi_test_oid_supported(&ms, &goid, &present);
		} وإلا {
			logit_f("badly formed OID received");
		}
	} طالما (mechs > 0 && !present);

	إذا (!present) {
		حرر(doid);
		authctxt->server_caused_failure = 1;
		أرجع (0);
	}

	إذا (GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctxt, &goid))) {
		إذا (ctxt != عدم)
			ssh_gssapi_delete_ctx(&ctxt);
		حرر(doid);
		authctxt->server_caused_failure = 1;
		أرجع (0);
	}

	authctxt->methoddata = (فراغ *)ctxt;

	/* Return the OID that we received */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_USERAUTH_GSSAPI_RESPONSE)) != 0 ||
	    (r = sshpkt_put_string(ssh, doid, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	حرر(doid);

	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, &درون_داد_gssapi_token);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, &درون_داد_gssapi_errtok);
	authctxt->postponed = 1;

	أرجع (0);
}

ساكن صحيح
درون_داد_gssapi_token(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_میانگیر_desc send_tok = GSS_C_خالی_میانگیر;
	gss_میانگیر_desc recv_tok;
	OM_uint32 maj_وضعیت, min_وضعیت, flags;
	u_char *p;
	اندازه_t len;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_انتها(ssh)) != 0)
		fatal_fr(r, "parse packet");

	recv_tok.مقدار = p;
	recv_tok.درازی = len;
	maj_وضعیت = mm_ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags);

	حرر(p);

	إذا (GSS_ERROR(maj_وضعیت)) {
		إذا (send_tok.درازی != 0) {
			إذا ((r = sshpkt_شروع(ssh,
			    SSH2_پیام_USERAUTH_GSSAPI_ERRTOK)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.مقدار,
			    send_tok.درازی)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send ERRTOK packet");
		}
		logit("Failed gssapi-with-mic for %s%.100s "
		    "from %.200s port %d ssh2",
		    authctxt->valid ? "" : "invalid user ",
		    authctxt->user,
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
		authctxt->postponed = 0;
		ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, عدم);
		ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, عدم);
		userauth_پایان(ssh, 0, "gssapi-with-mic", عدم);
	} وإلا {
		إذا (send_tok.درازی != 0) {
			إذا ((r = sshpkt_شروع(ssh,
			    SSH2_پیام_USERAUTH_GSSAPI_TOKEN)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.مقدار,
			    send_tok.درازی)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send TOKEN packet");
		}
		إذا (maj_وضعیت == GSS_S_COMPLETE) {
			ssh_dispatch_مجموعه(ssh,
			    SSH2_پیام_USERAUTH_GSSAPI_TOKEN, عدم);
			/* note: keep ERRTOK handler as per RFC 4462 s3.4 */
			إذا (flags & GSS_C_INTEG_FLAG) {
				ssh_dispatch_مجموعه(ssh,
				    SSH2_پیام_USERAUTH_GSSAPI_MIC,
				    &درون_داد_gssapi_mic);
			} وإلا {
				ssh_dispatch_مجموعه(ssh,
				    SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
				    &درون_داد_gssapi_exchange_complete);
			}
		}
	}

	gss_release_میانگیر(&min_وضعیت, &send_tok);
	أرجع 0;
}

ساكن صحيح
درون_داد_gssapi_errtok(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("No authentication or GSSAPI context");

	/* Minimal error handling - just cancel auth and return FAILURE */
	إذا ((r = sshpkt_get_string_مستقیم(ssh, عدم, عدم)) != 0 ||
	    (r = sshpkt_get_انتها(ssh)) != 0)
		fatal_fr(r, "parse packet");

	logit("Failed gssapi-with-mic for %s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh));
	authctxt->postponed = 0;
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_MIC, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, عدم);
	userauth_پایان(ssh, 0, "gssapi-with-mic", عدم);
	أرجع 0;
}

/*
 * This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */

ساكن صحيح
درون_داد_gssapi_exchange_complete(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	صحيح r, authenticated;
	مزدوج tstart = monotime_double();

	إذا (authctxt == عدم)
		fatal("No authentication or GSSAPI context");

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	إذا ((r = sshpkt_get_انتها(ssh)) != 0)
		fatal_fr(r, "parse packet");

	authenticated = mm_ssh_gssapi_userok(authctxt->user);
	إذا (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_MIC, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, عدم);
	userauth_پایان(ssh, authenticated, "gssapi-with-mic", عدم);
	أرجع 0;
}

ساكن صحيح
درون_داد_gssapi_mic(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	صحيح r, authenticated = 0;
	بنية sshbuf *b;
	gss_میانگیر_desc mic, gssbuf;
	u_char *p;
	اندازه_t len;
	مزدوج tstart = monotime_double();

	إذا (authctxt == عدم)
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		fatal_fr(r, "parse packet");
	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	mic.مقدار = p;
	mic.درازی = len;
	ssh_gssapi_buildmic(b, authctxt->user, authctxt->service,
	    "gssapi-with-mic", ssh->kex->session_id);

	إذا ((gssbuf.مقدار = sshbuf_mutable_ptr(b)) == عدم)
		fatal_f("sshbuf_mutable_ptr failed");
	gssbuf.درازی = sshbuf_len(b);

	إذا (!GSS_ERROR(mm_ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic)))
		authenticated = mm_ssh_gssapi_userok(authctxt->user);
	وإلا
		logit("GSSAPI MIC check failed");

	sshbuf_free(b);
	حرر(mic.مقدار);

	إذا (!authenticated)
		auth_failure_delay(authctxt, tstart);

	authctxt->postponed = 0;
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_MIC, عدم);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, عدم);
	userauth_پایان(ssh, authenticated, "gssapi-with-mic", عدم);
	أرجع 0;
}

Authmethod روش_gssapi = {
	&methodcfg_gssapi,
	userauth_gssapi,
};
#پایان_اگر
