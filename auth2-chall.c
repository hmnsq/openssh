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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"

/* import */
வெளி ServerOptions options;

நிலையான முழு auth2_challenge_start(கட்டமைப்பு ssh *);
நிலையான முழு send_userauth_info_request(கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_info_response(முழு, uint32_t, கட்டமைப்பு ssh *);

#ifdef BSD_AUTH
வெளி KbdintDevice mm_bsdauth_device;
#இல்லையெனில்
#ifdef USE_PAM
வெளி KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#இல்லையெனில்
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	வெற்று
};

வகைவரை கட்டமைப்பு KbdintAuthctxt KbdintAuthctxt;
கட்டமைப்பு KbdintAuthctxt
{
	எழுத்து *devices;
	வெறுமை *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
வெறுமை
remove_kbdint_device(மாறிலி எழுத்து *devname)
{
	முழு i, j;

	க்கு (i = 0; devices[i] != வெற்று; i++)
		எனில் (strcmp(devices[i]->name, devname) == 0) {
			க்கு (j = i; devices[j] != வெற்று; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

நிலையான KbdintAuthctxt *
kbdint_alloc(மாறிலி எழுத்து *devs)
{
	KbdintAuthctxt *kbdintctxt;
	கட்டமைப்பு sshbuf *b;
	முழு i, r;

#ifdef USE_PAM
	எனில் (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, அளவு(KbdintAuthctxt));
	எனில் (strcmp(devs, "") == 0) {
		எனில் ((b = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new failed");
		க்கு (i = 0; devices[i]; i++) {
			எனில் ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		எனில் ((kbdintctxt->devices = sshbuf_dup_string(b)) == வெற்று)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} இல்லையெனில் {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = வெற்று;
	kbdintctxt->device = வெற்று;
	kbdintctxt->nreq = 0;

	திரும்பு kbdintctxt;
}
நிலையான வெறுமை
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	எனில் (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = வெற்று;
	}
	kbdintctxt->device = வெற்று;
}
நிலையான வெறுமை
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	எனில் (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	விடுவி(kbdintctxt->devices);
	freezero(kbdintctxt, அளவு(*kbdintctxt));
}
/* get next device */
நிலையான முழு
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	எழுத்து *t;
	size_t i;

	எனில் (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	செய் {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		எனில் (len == 0)
			நிறுத்து;
		க்கு (i = 0; devices[i]; i++) {
			எனில் (i >= அளவு(kbdintctxt->devices_done) * 8 ||
			    i >= அளவு(devices) / அளவு(devices[0]))
				fatal_f("internal error: too many devices");
			எனில் ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				தொடர்;
			எனில் (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : வெற்று;
		விடுவி(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} போது (kbdintctxt->devices && !kbdintctxt->device);

	திரும்பு kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
முழு
auth2_challenge(கட்டமைப்பு ssh *ssh, எழுத்து *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	எனில் (authctxt->user == வெற்று || !devs)
		திரும்பு 0;
	எனில் (authctxt->kbdintctxt == வெற்று)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	திரும்பு auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
வெறுமை
auth2_challenge_stop(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_INFO_RESPONSE, வெற்று);
	எனில் (authctxt->kbdintctxt != வெற்று) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = வெற்று;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
நிலையான முழு
auth2_challenge_start(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	எனில் (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		திரும்பு 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	எனில் ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == வெற்று) {
		auth2_challenge_stop(ssh);
		திரும்பு 0;
	}
	எனில் (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		திரும்பு 0;
	}
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_INFO_RESPONSE,
	    &உள்ளீடு_userauth_info_response);

	authctxt->postponed = 1;
	திரும்பு 0;
}

நிலையான முழு
send_userauth_info_request(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	எழுத்து *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	எனில் (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		திரும்பு 0;

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	க்கு (i = 0; i < kbdintctxt->nreq; i++) {
		எனில் ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	எனில் ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	க்கு (i = 0; i < kbdintctxt->nreq; i++)
		விடுவி(prompts[i]);
	விடுவி(prompts);
	விடுவி(echo_on);
	விடுவி(name);
	விடுவி(instr);
	திரும்பு 1;
}

நிலையான முழு
உள்ளீடு_userauth_info_response(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	முழு authenticated = 0, res;
	முழு r;
	u_int i, nresp;
	மாறிலி எழுத்து *devicename = வெற்று;
	எழுத்து **response = வெற்று;
	இரட்டை tstart = monotime_double();

	எனில் (authctxt == வெற்று)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	எனில் (kbdintctxt == வெற்று || kbdintctxt->ctxt == வெற்று)
		fatal_f("no kbdintctxt");
	எனில் (kbdintctxt->device == வெற்று)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	எனில் ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	எனில் (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	எனில் (nresp > 100)
		fatal_f("too many replies");
	எனில் (nresp > 0) {
		response = xcalloc(nresp, அளவு(எழுத்து *));
		க்கு (i = 0; i < nresp; i++) {
			எனில் ((r = sshpkt_get_cstring(ssh, &response[i], வெற்று)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	க்கு (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		விடுவி(response[i]);
	}
	விடுவி(response);

	தேர்வு (res) {
	நிலை 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		நிறுத்து;
	நிலை 1:
		/* Authentication needs further interaction */
		எனில் (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		நிறுத்து;
	இயல்பு:
		/* Failure! */
		நிறுத்து;
	}
	devicename = kbdintctxt->device->name;
	எனில் (!authctxt->postponed) {
		எனில் (authenticated) {
			auth2_challenge_stop(ssh);
		} இல்லையெனில் {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	எனில் (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	திரும்பு 0;
}
