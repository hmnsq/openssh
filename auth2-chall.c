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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"

/* import */
ਬਾਹਰੀ ServerOptions options;

ਸਥਿਰ ਪੂਰਨ auth2_challenge_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ send_userauth_info_request(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_info_response(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
ਬਾਹਰੀ KbdintDevice mm_bsdauth_device;
#ਨਹੀਂਤਾਂ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਬਾਹਰੀ KbdintDevice mm_sshpam_device;
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

KbdintDevice *devices[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
	&mm_bsdauth_device,
#ਨਹੀਂਤਾਂ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	&mm_sshpam_device,
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ
	ਨਿਰਾ
};

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ KbdintAuthctxt KbdintAuthctxt;
ਬਣਤਰ KbdintAuthctxt
{
	ਅੱਖਰ *devices;
	ਖਾਲੀ *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_ਪੂਰਾ;
};

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
ਖਾਲੀ
remove_kbdint_device(ਅਚਲ ਅੱਖਰ *devname)
{
	ਪੂਰਨ i, j;

	ਲਈ (i = 0; devices[i] != ਨਿਰਾ; i++)
		ਜੇ (strcmp(devices[i]->name, devname) == 0) {
			ਲਈ (j = i; devices[j] != ਨਿਰਾ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ KbdintAuthctxt *
kbdint_alloc(ਅਚਲ ਅੱਖਰ *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ i, r;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (!options.use_pam)
		remove_kbdint_device("pam");
#ਜੇ_ਅੰਤ

	kbdintctxt = xcalloc(1, ਆਕਾਰ(KbdintAuthctxt));
	ਜੇ (strcmp(devs, "") == 0) {
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new failed");
		ਲਈ (i = 0; devices[i]; i++) {
			ਜੇ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ਜੇ ((kbdintctxt->devices = sshbuf_dup_string(b)) == ਨਿਰਾ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ਨਹੀਂਤਾਂ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ਨਿਰਾ;
	kbdintctxt->device = ਨਿਰਾ;
	kbdintctxt->nreq = 0;

	ਵਾਪਸ kbdintctxt;
}
ਸਥਿਰ ਖਾਲੀ
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ਜੇ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ਨਿਰਾ;
	}
	kbdintctxt->device = ਨਿਰਾ;
}
ਸਥਿਰ ਖਾਲੀ
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ਜੇ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ਮੁਕਤ(kbdintctxt->devices);
	freezero(kbdintctxt, ਆਕਾਰ(*kbdintctxt));
}
/* get next device */
ਸਥਿਰ ਪੂਰਨ
kbdint_ਅਗਲਾ_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	ਮਾਪ_t len;
	ਅੱਖਰ *t;
	ਮਾਪ_t i;

	ਜੇ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ਕਰੋ {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ਜੇ (len == 0)
			ਰੋਕੋ;
		ਲਈ (i = 0; devices[i]; i++) {
			ਜੇ (i >= ਆਕਾਰ(kbdintctxt->devices_ਪੂਰਾ) * 8 ||
			    i >= ਆਕਾਰ(devices) / ਆਕਾਰ(devices[0]))
				fatal_f("internal error: too many devices");
			ਜੇ ((kbdintctxt->devices_ਪੂਰਾ & (1 << i)) != 0 ||
			    !auth2_ਵਿਧੀ_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ਜਾਰੀ;
			ਜੇ (ਲੜੀ_ਲੰਬਾਈ(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_ਪੂਰਾ |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ਨਿਰਾ;
		ਮੁਕਤ(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ਜਦੋਂ (kbdintctxt->devices && !kbdintctxt->device);

	ਵਾਪਸ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
ਪੂਰਨ
auth2_challenge(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ਜੇ (authctxt->user == ਨਿਰਾ || !devs)
		ਵਾਪਸ 0;
	ਜੇ (authctxt->kbdintctxt == ਨਿਰਾ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ਵਾਪਸ auth2_challenge_ਸ਼ੁਰੂ(ssh);
}

/* unregister kbd-int callbacks and context */
ਖਾਲੀ
auth2_challenge_stop(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_RESPONSE, ਨਿਰਾ);
	ਜੇ (authctxt->kbdintctxt != ਨਿਰਾ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ਨਿਰਾ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ਸਥਿਰ ਪੂਰਨ
auth2_challenge_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ਜੇ (kbdint_ਅਗਲਾ_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ਵਾਪਸ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ਜੇ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ਨਿਰਾ) {
		auth2_challenge_stop(ssh);
		ਵਾਪਸ 0;
	}
	ਜੇ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ਵਾਪਸ 0;
	}
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_RESPONSE,
	    &ਨਿਵੇਸ਼_userauth_info_response);

	authctxt->postponed = 1;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
send_userauth_info_request(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ਅੱਖਰ *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ਜੇ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ਵਾਪਸ 0;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	ਲਈ (i = 0; i < kbdintctxt->nreq; i++) {
		ਜੇ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ਜੇ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	ਲਈ (i = 0; i < kbdintctxt->nreq; i++)
		ਮੁਕਤ(prompts[i]);
	ਮੁਕਤ(prompts);
	ਮੁਕਤ(echo_on);
	ਮੁਕਤ(name);
	ਮੁਕਤ(instr);
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_info_response(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ਪੂਰਨ authenticated = 0, res;
	ਪੂਰਨ r;
	u_int i, nresp;
	ਅਚਲ ਅੱਖਰ *devicename = ਨਿਰਾ;
	ਅੱਖਰ **response = ਨਿਰਾ;
	ਦੁੱਗਣਾ tstart = monotime_double();

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ਜੇ (kbdintctxt == ਨਿਰਾ || kbdintctxt->ctxt == ਨਿਰਾ)
		fatal_f("no kbdintctxt");
	ਜੇ (kbdintctxt->device == ਨਿਰਾ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ਜੇ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ਜੇ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ਜੇ (nresp > 100)
		fatal_f("too many replies");
	ਜੇ (nresp > 0) {
		response = xcalloc(nresp, ਆਕਾਰ(ਅੱਖਰ *));
		ਲਈ (i = 0; i < nresp; i++) {
			ਜੇ ((r = sshpkt_get_cstring(ssh, &response[i], ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	ਲਈ (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], ਲੜੀ_ਲੰਬਾਈ(response[i]));
		ਮੁਕਤ(response[i]);
	}
	ਮੁਕਤ(response);

	ਚੋਣ (res) {
	ਹਾਲਤ 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		ਰੋਕੋ;
	ਹਾਲਤ 1:
		/* Authentication needs further interaction */
		ਜੇ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		ਰੋਕੋ;
	ਮੂਲ:
		/* Failure! */
		ਰੋਕੋ;
	}
	devicename = kbdintctxt->device->name;
	ਜੇ (!authctxt->postponed) {
		ਜੇ (authenticated) {
			auth2_challenge_stop(ssh);
		} ਨਹੀਂਤਾਂ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_ਸ਼ੁਰੂ(ssh);
		}
	}

	ਜੇ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_ਅੰਤ(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ਵਾਪਸ 0;
}
