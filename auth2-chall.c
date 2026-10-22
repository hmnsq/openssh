/* $OpenBSD: auth2-chall.c,v 1.61 2026/07/06 07:44:48 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Per Allansson.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "ssh2.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "dispatch.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"

/* import */
خارجي ServerOptions options;

ساكن صحيح auth2_challenge_start(بنية ssh *);
ساكن صحيح send_userauth_info_request(بنية ssh *);
ساكن صحيح input_userauth_info_response(صحيح, uint32_t, بنية ssh *);

#ifdef BSD_AUTH
خارجي KbdintDevice mm_bsdauth_device;
#אחרת
#ifdef USE_PAM
خارجي KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#אחרת
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	عدم
};

تعريفنوع بنية KbdintAuthctxt KbdintAuthctxt;
بنية KbdintAuthctxt
{
	حرف *devices;
	فراغ *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
فراغ
remove_kbdint_device(ثابت حرف *devname)
{
	صحيح i, j;

	עבור (i = 0; devices[i] != عدم; i++)
		אם (strcmp(devices[i]->name, devname) == 0) {
			עבור (j = i; devices[j] != عدم; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

ساكن KbdintAuthctxt *
kbdint_alloc(ثابت حرف *devs)
{
	KbdintAuthctxt *kbdintctxt;
	بنية sshbuf *b;
	صحيح i, r;

#ifdef USE_PAM
	אם (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, حجم(KbdintAuthctxt));
	אם (strcmp(devs, "") == 0) {
		אם ((b = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		עבור (i = 0; devices[i]; i++) {
			אם ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		אם ((kbdintctxt->devices = sshbuf_dup_string(b)) == عدم)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} אחרת {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = عدم;
	kbdintctxt->device = عدم;
	kbdintctxt->nreq = 0;

	החזר kbdintctxt;
}
ساكن فراغ
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	אם (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = عدم;
	}
	kbdintctxt->device = عدم;
}
ساكن فراغ
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	אם (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	حرر(kbdintctxt->devices);
	freezero(kbdintctxt, حجم(*kbdintctxt));
}
/* get next device */
ساكن صحيح
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	حرف *t;
	size_t i;

	אם (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	עשה {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		אם (len == 0)
			اكسر;
		עבור (i = 0; devices[i]; i++) {
			אם (i >= حجم(kbdintctxt->devices_done) * 8 ||
			    i >= حجم(devices) / حجم(devices[0]))
				fatal_f("internal error: too many devices");
			אם ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				استمر;
			אם (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : عدم;
		حرر(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} כלעוד (kbdintctxt->devices && !kbdintctxt->device);

	החזר kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
صحيح
auth2_challenge(بنية ssh *ssh, حرف *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	אם (authctxt->user == عدم || !devs)
		החזר 0;
	אם (authctxt->kbdintctxt == عدم)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	החזר auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
فراغ
auth2_challenge_stop(بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE, عدم);
	אם (authctxt->kbdintctxt != عدم) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = عدم;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ساكن صحيح
auth2_challenge_start(بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	אם (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		החזר 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	אם ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == عدم) {
		auth2_challenge_stop(ssh);
		החזר 0;
	}
	אם (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		החזר 0;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response);

	authctxt->postponed = 1;
	החזר 0;
}

ساكن صحيح
send_userauth_info_request(بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	حرف *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	אם (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		החזר 0;

	אם ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	עבור (i = 0; i < kbdintctxt->nreq; i++) {
		אם ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	אם ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	עבור (i = 0; i < kbdintctxt->nreq; i++)
		حرر(prompts[i]);
	حرر(prompts);
	حرر(echo_on);
	حرر(name);
	حرر(instr);
	החזר 1;
}

ساكن صحيح
input_userauth_info_response(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	صحيح authenticated = 0, res;
	صحيح r;
	u_int i, nresp;
	ثابت حرف *devicename = عدم;
	حرف **response = عدم;
	مزدوج tstart = monotime_double();

	אם (authctxt == عدم)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	אם (kbdintctxt == عدم || kbdintctxt->ctxt == عدم)
		fatal_f("no kbdintctxt");
	אם (kbdintctxt->device == عدم)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	אם ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	אם (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	אם (nresp > 100)
		fatal_f("too many replies");
	אם (nresp > 0) {
		response = xcalloc(nresp, حجم(حرف *));
		עבור (i = 0; i < nresp; i++) {
			אם ((r = sshpkt_get_cstring(ssh, &response[i], عدم)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	אם ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	עבור (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		حرر(response[i]);
	}
	حرر(response);

	بدل (res) {
	حالة 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		اكسر;
	حالة 1:
		/* Authentication needs further interaction */
		אם (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		اكسر;
	افتراضي:
		/* Failure! */
		اكسر;
	}
	devicename = kbdintctxt->device->name;
	אם (!authctxt->postponed) {
		אם (authenticated) {
			auth2_challenge_stop(ssh);
		} אחרת {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	אם (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	החזר 0;
}
