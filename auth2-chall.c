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
بیرونی ServerOptions options;

ایستا صحیح auth2_challenge_start(ساختار ssh *);
ایستا صحیح send_userauth_info_request(ساختار ssh *);
ایستا صحیح درون_داد_userauth_info_response(صحیح, uint32_t, ساختار ssh *);

#ifdef BSD_AUTH
بیرونی KbdintDevice mm_bsdauth_device;
#وگرنه
#ifdef USE_PAM
بیرونی KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#وگرنه
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	پوچ
};

تعریفنوع ساختار KbdintAuthctxt KbdintAuthctxt;
ساختار KbdintAuthctxt
{
	نویسه *devices;
	تهی *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
تهی
remove_kbdint_device(ثابت نویسه *devname)
{
	صحیح i, j;

	برای (i = 0; devices[i] != پوچ; i++)
		اگر (strcmp(devices[i]->name, devname) == 0) {
			برای (j = i; devices[j] != پوچ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

ایستا KbdintAuthctxt *
kbdint_alloc(ثابت نویسه *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ساختار sshbuf *b;
	صحیح i, r;

#ifdef USE_PAM
	اگر (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, اندازه(KbdintAuthctxt));
	اگر (strcmp(devs, "") == 0) {
		اگر ((b = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new failed");
		برای (i = 0; devices[i]; i++) {
			اگر ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		اگر ((kbdintctxt->devices = sshbuf_dup_string(b)) == پوچ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} وگرنه {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = پوچ;
	kbdintctxt->device = پوچ;
	kbdintctxt->nreq = 0;

	بازگشت kbdintctxt;
}
ایستا تهی
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	اگر (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = پوچ;
	}
	kbdintctxt->device = پوچ;
}
ایستا تهی
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	اگر (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	آزاد(kbdintctxt->devices);
	freezero(kbdintctxt, اندازه(*kbdintctxt));
}
/* get next device */
ایستا صحیح
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	نویسه *t;
	size_t i;

	اگر (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	انجامبده {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		اگر (len == 0)
			بشکن;
		برای (i = 0; devices[i]; i++) {
			اگر (i >= اندازه(kbdintctxt->devices_done) * 8 ||
			    i >= اندازه(devices) / اندازه(devices[0]))
				fatal_f("internal error: too many devices");
			اگر ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ادامه;
			اگر (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : پوچ;
		آزاد(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} وقتی (kbdintctxt->devices && !kbdintctxt->device);

	بازگشت kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
صحیح
auth2_challenge(ساختار ssh *ssh, نویسه *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	اگر (authctxt->user == پوچ || !devs)
		بازگشت 0;
	اگر (authctxt->kbdintctxt == پوچ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	بازگشت auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
تهی
auth2_challenge_stop(ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_INFO_RESPONSE, پوچ);
	اگر (authctxt->kbdintctxt != پوچ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = پوچ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ایستا صحیح
auth2_challenge_start(ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	اگر (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		بازگشت 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	اگر ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == پوچ) {
		auth2_challenge_stop(ssh);
		بازگشت 0;
	}
	اگر (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		بازگشت 0;
	}
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_INFO_RESPONSE,
	    &درون_داد_userauth_info_response);

	authctxt->postponed = 1;
	بازگشت 0;
}

ایستا صحیح
send_userauth_info_request(ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	نویسه *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	اگر (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		بازگشت 0;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	برای (i = 0; i < kbdintctxt->nreq; i++) {
		اگر ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	اگر ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	برای (i = 0; i < kbdintctxt->nreq; i++)
		آزاد(prompts[i]);
	آزاد(prompts);
	آزاد(echo_on);
	آزاد(name);
	آزاد(instr);
	بازگشت 1;
}

ایستا صحیح
درون_داد_userauth_info_response(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	صحیح authenticated = 0, res;
	صحیح r;
	u_int i, nresp;
	ثابت نویسه *devicename = پوچ;
	نویسه **response = پوچ;
	دوگانه tstart = monotime_double();

	اگر (authctxt == پوچ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	اگر (kbdintctxt == پوچ || kbdintctxt->ctxt == پوچ)
		fatal_f("no kbdintctxt");
	اگر (kbdintctxt->device == پوچ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	اگر ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	اگر (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	اگر (nresp > 100)
		fatal_f("too many replies");
	اگر (nresp > 0) {
		response = xcalloc(nresp, اندازه(نویسه *));
		برای (i = 0; i < nresp; i++) {
			اگر ((r = sshpkt_get_cstring(ssh, &response[i], پوچ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	اگر ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	برای (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		آزاد(response[i]);
	}
	آزاد(response);

	انتخاب (res) {
	حالت 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		بشکن;
	حالت 1:
		/* Authentication needs further interaction */
		اگر (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		بشکن;
	پیشفرض:
		/* Failure! */
		بشکن;
	}
	devicename = kbdintctxt->device->name;
	اگر (!authctxt->postponed) {
		اگر (authenticated) {
			auth2_challenge_stop(ssh);
		} وگرنه {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	اگر (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	بازگشت 0;
}
