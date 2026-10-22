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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "ssh2.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "dispatch.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"

/* import */
خارجی ServerOptions options;

ساکن صحیح auth2_challenge_آغاز(ساخت ssh *);
ساکن صحیح send_userauth_info_request(ساخت ssh *);
ساکن صحیح داخلہ_userauth_info_response(صحیح, uint32_t, ساخت ssh *);

#اگر_تعریف_شدہ BSD_AUTH
خارجی KbdintDevice mm_bsdauth_device;
#ورنہ
#اگر_تعریف_شدہ USE_PAM
خارجی KbdintDevice mm_sshpam_device;
#اگر_ختم
#اگر_ختم

KbdintDevice *devices[] = {
#اگر_تعریف_شدہ BSD_AUTH
	&mm_bsdauth_device,
#ورنہ
#اگر_تعریف_شدہ USE_PAM
	&mm_sshpam_device,
#اگر_ختم
#اگر_ختم
	تہی
};

قسمتعریف ساخت KbdintAuthctxt KbdintAuthctxt;
ساخت KbdintAuthctxt
{
	حرف *devices;
	خالی *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_مکمل;
};

#اگر_تعریف_شدہ USE_PAM
خالی
remove_kbdint_device(ثابت حرف *devname)
{
	صحیح i, j;

	برائے (i = 0; devices[i] != تہی; i++)
		اگر (strcmp(devices[i]->name, devname) == 0) {
			برائے (j = i; devices[j] != تہی; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#اگر_ختم

ساکن KbdintAuthctxt *
kbdint_alloc(ثابت حرف *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ساخت sshbuf *b;
	صحیح i, r;

#اگر_تعریف_شدہ USE_PAM
	اگر (!options.use_pam)
		remove_kbdint_device("pam");
#اگر_ختم

	kbdintctxt = xcalloc(1, حجم(KbdintAuthctxt));
	اگر (strcmp(devs, "") == 0) {
		اگر ((b = sshbuf_new()) == تہی)
			fatal_f("sshbuf_new failed");
		برائے (i = 0; devices[i]; i++) {
			اگر ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		اگر ((kbdintctxt->devices = sshbuf_dup_string(b)) == تہی)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ورنہ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = تہی;
	kbdintctxt->device = تہی;
	kbdintctxt->nreq = 0;

	واپس kbdintctxt;
}
ساکن خالی
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	اگر (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = تہی;
	}
	kbdintctxt->device = تہی;
}
ساکن خالی
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	اگر (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	آزاد(kbdintctxt->devices);
	freezero(kbdintctxt, حجم(*kbdintctxt));
}
/* get next device */
ساکن صحیح
kbdint_اگلا_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	سائز_t len;
	حرف *t;
	سائز_t i;

	اگر (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	کرو {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		اگر (len == 0)
			توڑو;
		برائے (i = 0; devices[i]; i++) {
			اگر (i >= حجم(kbdintctxt->devices_مکمل) * 8 ||
			    i >= حجم(devices) / حجم(devices[0]))
				fatal_f("internal error: too many devices");
			اگر ((kbdintctxt->devices_مکمل & (1 << i)) != 0 ||
			    !auth2_طریقہ_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				جاری;
			اگر (لڑی_لمبائی(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_مکمل |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : تہی;
		آزاد(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} جب (kbdintctxt->devices && !kbdintctxt->device);

	واپس kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
صحیح
auth2_challenge(ساخت ssh *ssh, حرف *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	اگر (authctxt->user == تہی || !devs)
		واپس 0;
	اگر (authctxt->kbdintctxt == تہی)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	واپس auth2_challenge_آغاز(ssh);
}

/* unregister kbd-int callbacks and context */
خالی
auth2_challenge_stop(ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_RESPONSE, تہی);
	اگر (authctxt->kbdintctxt != تہی) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = تہی;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ساکن صحیح
auth2_challenge_آغاز(ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	اگر (kbdint_اگلا_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		واپس 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	اگر ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == تہی) {
		auth2_challenge_stop(ssh);
		واپس 0;
	}
	اگر (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		واپس 0;
	}
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_RESPONSE,
	    &داخلہ_userauth_info_response);

	authctxt->postponed = 1;
	واپس 0;
}

ساکن صحیح
send_userauth_info_request(ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	حرف *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	اگر (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		واپس 0;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	برائے (i = 0; i < kbdintctxt->nreq; i++) {
		اگر ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	اگر ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	برائے (i = 0; i < kbdintctxt->nreq; i++)
		آزاد(prompts[i]);
	آزاد(prompts);
	آزاد(echo_on);
	آزاد(name);
	آزاد(instr);
	واپس 1;
}

ساکن صحیح
داخلہ_userauth_info_response(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	صحیح authenticated = 0, res;
	صحیح r;
	u_int i, nresp;
	ثابت حرف *devicename = تہی;
	حرف **response = تہی;
	دوہرا tstart = monotime_double();

	اگر (authctxt == تہی)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	اگر (kbdintctxt == تہی || kbdintctxt->ctxt == تہی)
		fatal_f("no kbdintctxt");
	اگر (kbdintctxt->device == تہی)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	اگر ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	اگر (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	اگر (nresp > 100)
		fatal_f("too many replies");
	اگر (nresp > 0) {
		response = xcalloc(nresp, حجم(حرف *));
		برائے (i = 0; i < nresp; i++) {
			اگر ((r = sshpkt_get_cstring(ssh, &response[i], تہی)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	برائے (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], لڑی_لمبائی(response[i]));
		آزاد(response[i]);
	}
	آزاد(response);

	انتخاب (res) {
	حالت 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		توڑو;
	حالت 1:
		/* Authentication needs further interaction */
		اگر (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		توڑو;
	طےشدہ:
		/* Failure! */
		توڑو;
	}
	devicename = kbdintctxt->device->name;
	اگر (!authctxt->postponed) {
		اگر (authenticated) {
			auth2_challenge_stop(ssh);
		} ورنہ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_آغاز(ssh);
		}
	}

	اگر (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_اختتام(ssh, authenticated, "keyboard-interactive",
	    devicename);
	واپس 0;
}
