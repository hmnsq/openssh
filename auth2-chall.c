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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ auth2_challenge_ಆರಂಭ(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ send_userauth_info_request(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_info_response(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
ಬಾಹ್ಯ KbdintDevice mm_bsdauth_device;
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಬಾಹ್ಯ KbdintDevice mm_sshpam_device;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

KbdintDevice *devices[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
	&mm_bsdauth_device,
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	&mm_sshpam_device,
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ
	ಖಾಲಿ
};

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ KbdintAuthctxt KbdintAuthctxt;
ರಚನೆ KbdintAuthctxt
{
	ಅಕ್ಷರ *devices;
	ಶೂನ್ಯ *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_ಮುಗಿದ;
};

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
ಶೂನ್ಯ
remove_kbdint_device(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *devname)
{
	ಪೂರ್ಣಾಂಕ i, j;

	ಗಾಗಿ (i = 0; devices[i] != ಖಾಲಿ; i++)
		ಆದರೆ (strcmp(devices[i]->name, devname) == 0) {
			ಗಾಗಿ (j = i; devices[j] != ಖಾಲಿ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ KbdintAuthctxt *
kbdint_alloc(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ i, r;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (!options.use_pam)
		remove_kbdint_device("pam");
#ಆದರೆ_ಅಂತ್ಯ

	kbdintctxt = xcalloc(1, ಗಾತ್ರ(KbdintAuthctxt));
	ಆದರೆ (strcmp(devs, "") == 0) {
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new failed");
		ಗಾಗಿ (i = 0; devices[i]; i++) {
			ಆದರೆ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ಆದರೆ ((kbdintctxt->devices = sshbuf_dup_string(b)) == ಖಾಲಿ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ಇಲ್ಲದಿದ್ದರೆ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ಖಾಲಿ;
	kbdintctxt->device = ಖಾಲಿ;
	kbdintctxt->nreq = 0;

	ಹಿಂತಿರುಗಿ kbdintctxt;
}
ಸ್ಥಿರ ಶೂನ್ಯ
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ಆದರೆ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ಖಾಲಿ;
	}
	kbdintctxt->device = ಖಾಲಿ;
}
ಸ್ಥಿರ ಶೂನ್ಯ
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ಆದರೆ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ಬಿಡುಗಡೆ(kbdintctxt->devices);
	freezero(kbdintctxt, ಗಾತ್ರ(*kbdintctxt));
}
/* get next device */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kbdint_ಮುಂದಿನ_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *t;
	ಗಾತ್ರ_t i;

	ಆದರೆ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ಮಾಡು {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ಆದರೆ (len == 0)
			ನಿಲ್ಲಿಸು;
		ಗಾಗಿ (i = 0; devices[i]; i++) {
			ಆದರೆ (i >= ಗಾತ್ರ(kbdintctxt->devices_ಮುಗಿದ) * 8 ||
			    i >= ಗಾತ್ರ(devices) / ಗಾತ್ರ(devices[0]))
				fatal_f("internal error: too many devices");
			ಆದರೆ ((kbdintctxt->devices_ಮುಗಿದ & (1 << i)) != 0 ||
			    !auth2_ವಿಧಾನ_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ಮುಂದುವರಿ;
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_ಮುಗಿದ |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ಖಾಲಿ;
		ಬಿಡುಗಡೆ(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ಆಗ (kbdintctxt->devices && !kbdintctxt->device);

	ಹಿಂತಿರುಗಿ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
ಪೂರ್ಣಾಂಕ
auth2_challenge(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ಆದರೆ (authctxt->user == ಖಾಲಿ || !devs)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (authctxt->kbdintctxt == ಖಾಲಿ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ಹಿಂತಿರುಗಿ auth2_challenge_ಆರಂಭ(ssh);
}

/* unregister kbd-int callbacks and context */
ಶೂನ್ಯ
auth2_challenge_stop(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE, ಖಾಲಿ);
	ಆದರೆ (authctxt->kbdintctxt != ಖಾಲಿ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ಖಾಲಿ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
auth2_challenge_ಆರಂಭ(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ಆದರೆ (kbdint_ಮುಂದಿನ_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ಹಿಂತಿರುಗಿ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ಆದರೆ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ಖಾಲಿ) {
		auth2_challenge_stop(ssh);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ಹಿಂತಿರುಗಿ 0;
	}
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE,
	    &ಒಳಹರಿವು_userauth_info_response);

	authctxt->postponed = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
send_userauth_info_request(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ಅಕ್ಷರ *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ಆದರೆ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	ಗಾಗಿ (i = 0; i < kbdintctxt->nreq; i++) {
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ಆದರೆ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಗಾಗಿ (i = 0; i < kbdintctxt->nreq; i++)
		ಬಿಡುಗಡೆ(prompts[i]);
	ಬಿಡುಗಡೆ(prompts);
	ಬಿಡುಗಡೆ(echo_on);
	ಬಿಡುಗಡೆ(name);
	ಬಿಡುಗಡೆ(instr);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_info_response(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ಪೂರ್ಣಾಂಕ authenticated = 0, res;
	ಪೂರ್ಣಾಂಕ r;
	u_int i, nresp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *devicename = ಖಾಲಿ;
	ಅಕ್ಷರ **response = ಖಾಲಿ;
	ದ್ವಿಗುಣ tstart = monotime_double();

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ಆದರೆ (kbdintctxt == ಖಾಲಿ || kbdintctxt->ctxt == ಖಾಲಿ)
		fatal_f("no kbdintctxt");
	ಆದರೆ (kbdintctxt->device == ಖಾಲಿ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ಆದರೆ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ಆದರೆ (nresp > 100)
		fatal_f("too many replies");
	ಆದರೆ (nresp > 0) {
		response = xcalloc(nresp, ಗಾತ್ರ(ಅಕ್ಷರ *));
		ಗಾಗಿ (i = 0; i < nresp; i++) {
			ಆದರೆ ((r = sshpkt_get_cstring(ssh, &response[i], ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	ಗಾಗಿ (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(response[i]));
		ಬಿಡುಗಡೆ(response[i]);
	}
	ಬಿಡುಗಡೆ(response);

	ಆಯ್ಕೆ (res) {
	ಸ್ಥಿತಿ 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 1:
		/* Authentication needs further interaction */
		ಆದರೆ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* Failure! */
		ನಿಲ್ಲಿಸು;
	}
	devicename = kbdintctxt->device->name;
	ಆದರೆ (!authctxt->postponed) {
		ಆದರೆ (authenticated) {
			auth2_challenge_stop(ssh);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_ಆರಂಭ(ssh);
		}
	}

	ಆದರೆ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_ಮುಕ್ತಾಯ(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ಹಿಂತಿರುಗಿ 0;
}
