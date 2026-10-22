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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ auth2_challenge_start(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ send_userauth_info_request(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_info_response(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

#ifdef BSD_AUTH
ಬಾಹ್ಯ KbdintDevice mm_bsdauth_device;
#ಅನ್ಯಥಾ
#ifdef USE_PAM
ಬಾಹ್ಯ KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#ಅನ್ಯಥಾ
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	ರಿಕ್ತ
};

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ KbdintAuthctxt KbdintAuthctxt;
ಸಂರಚನಾ KbdintAuthctxt
{
	ವರ್ಣ *devices;
	ಶೂನ್ಯ *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
ಶೂನ್ಯ
remove_kbdint_device(ಧ್ರುವ ವರ್ಣ *devname)
{
	ಪೂರ್ಣಾಙ್ಕ i, j;

	ಪ್ರತಿ (i = 0; devices[i] != ರಿಕ್ತ; i++)
		ಯದಿ (strcmp(devices[i]->name, devname) == 0) {
			ಪ್ರತಿ (j = i; devices[j] != ರಿಕ್ತ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

ಸ್ಥಿರ KbdintAuthctxt *
kbdint_alloc(ಧ್ರುವ ವರ್ಣ *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ i, r;

#ifdef USE_PAM
	ಯದಿ (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, ಪರಿಮಾಣ(KbdintAuthctxt));
	ಯದಿ (strcmp(devs, "") == 0) {
		ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new failed");
		ಪ್ರತಿ (i = 0; devices[i]; i++) {
			ಯದಿ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ಯದಿ ((kbdintctxt->devices = sshbuf_dup_string(b)) == ರಿಕ್ತ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ಅನ್ಯಥಾ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ರಿಕ್ತ;
	kbdintctxt->device = ರಿಕ್ತ;
	kbdintctxt->nreq = 0;

	ಪ್ರತ್ಯಾಗಮ kbdintctxt;
}
ಸ್ಥಿರ ಶೂನ್ಯ
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ಯದಿ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ರಿಕ್ತ;
	}
	kbdintctxt->device = ರಿಕ್ತ;
}
ಸ್ಥಿರ ಶೂನ್ಯ
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ಯದಿ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ಮುಕ್ತ(kbdintctxt->devices);
	freezero(kbdintctxt, ಪರಿಮಾಣ(*kbdintctxt));
}
/* get next device */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	ವರ್ಣ *t;
	size_t i;

	ಯದಿ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ಕುರು {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ಯದಿ (len == 0)
			ಭಙ್ಗ;
		ಪ್ರತಿ (i = 0; devices[i]; i++) {
			ಯದಿ (i >= ಪರಿಮಾಣ(kbdintctxt->devices_done) * 8 ||
			    i >= ಪರಿಮಾಣ(devices) / ಪರಿಮಾಣ(devices[0]))
				fatal_f("internal error: too many devices");
			ಯದಿ ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ಅನುವರ್ತ;
			ಯದಿ (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ರಿಕ್ತ;
		ಮುಕ್ತ(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ಯಾವತ್ (kbdintctxt->devices && !kbdintctxt->device);

	ಪ್ರತ್ಯಾಗಮ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
ಪೂರ್ಣಾಙ್ಕ
auth2_challenge(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ಯದಿ (authctxt->user == ರಿಕ್ತ || !devs)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (authctxt->kbdintctxt == ರಿಕ್ತ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ಪ್ರತ್ಯಾಗಮ auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
ಶೂನ್ಯ
auth2_challenge_stop(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE, ರಿಕ್ತ);
	ಯದಿ (authctxt->kbdintctxt != ರಿಕ್ತ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ರಿಕ್ತ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
auth2_challenge_start(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ಯದಿ (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ಯದಿ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ರಿಕ್ತ) {
		auth2_challenge_stop(ssh);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE,
	    &ಒಳಹರಿವು_userauth_info_response);

	authctxt->postponed = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
send_userauth_info_request(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ವರ್ಣ *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ಯದಿ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	ಪ್ರತಿ (i = 0; i < kbdintctxt->nreq; i++) {
		ಯದಿ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ಯದಿ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಪ್ರತಿ (i = 0; i < kbdintctxt->nreq; i++)
		ಮುಕ್ತ(prompts[i]);
	ಮುಕ್ತ(prompts);
	ಮುಕ್ತ(echo_on);
	ಮುಕ್ತ(name);
	ಮುಕ್ತ(instr);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_info_response(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ಪೂರ್ಣಾಙ್ಕ authenticated = 0, res;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, nresp;
	ಧ್ರುವ ವರ್ಣ *devicename = ರಿಕ್ತ;
	ವರ್ಣ **response = ರಿಕ್ತ;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ಯದಿ (kbdintctxt == ರಿಕ್ತ || kbdintctxt->ctxt == ರಿಕ್ತ)
		fatal_f("no kbdintctxt");
	ಯದಿ (kbdintctxt->device == ರಿಕ್ತ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ಯದಿ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ಯದಿ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ಯದಿ (nresp > 100)
		fatal_f("too many replies");
	ಯದಿ (nresp > 0) {
		response = xcalloc(nresp, ಪರಿಮಾಣ(ವರ್ಣ *));
		ಪ್ರತಿ (i = 0; i < nresp; i++) {
			ಯದಿ ((r = sshpkt_get_cstring(ssh, &response[i], ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	ಪ್ರತಿ (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		ಮುಕ್ತ(response[i]);
	}
	ಮುಕ್ತ(response);

	ವಿಕಲ್ಪ (res) {
	ಪಕ್ಷ 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		ಭಙ್ಗ;
	ಪಕ್ಷ 1:
		/* Authentication needs further interaction */
		ಯದಿ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		/* Failure! */
		ಭಙ್ಗ;
	}
	devicename = kbdintctxt->device->name;
	ಯದಿ (!authctxt->postponed) {
		ಯದಿ (authenticated) {
			auth2_challenge_stop(ssh);
		} ಅನ್ಯಥಾ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	ಯದಿ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ಪ್ರತ್ಯಾಗಮ 0;
}
