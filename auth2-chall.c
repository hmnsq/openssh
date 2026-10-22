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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"

/* import */
బాహ్య ServerOptions options;

స్థిర పూర్ణాంకం auth2_challenge_ప్రారంభం(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం send_userauth_info_request(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_info_response(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

#నిర్వచితమైతే BSD_AUTH
బాహ్య KbdintDevice mm_bsdauth_device;
#లేకపోతే
#నిర్వచితమైతే USE_PAM
బాహ్య KbdintDevice mm_sshpam_device;
#అయితే_ముగింపు
#అయితే_ముగింపు

KbdintDevice *devices[] = {
#నిర్వచితమైతే BSD_AUTH
	&mm_bsdauth_device,
#లేకపోతే
#నిర్వచితమైతే USE_PAM
	&mm_sshpam_device,
#అయితే_ముగింపు
#అయితే_ముగింపు
	ఖాళీ
};

రకనిర్వచనం నిర్మాణం KbdintAuthctxt KbdintAuthctxt;
నిర్మాణం KbdintAuthctxt
{
	అక్షరం *devices;
	శూన్య *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_పూర్తి;
};

#నిర్వచితమైతే USE_PAM
శూన్య
remove_kbdint_device(స్థిరరాశి అక్షరం *devname)
{
	పూర్ణాంకం i, j;

	కొరకు (i = 0; devices[i] != ఖాళీ; i++)
		ఒకవేళ (strcmp(devices[i]->name, devname) == 0) {
			కొరకు (j = i; devices[j] != ఖాళీ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#అయితే_ముగింపు

స్థిర KbdintAuthctxt *
kbdint_alloc(స్థిరరాశి అక్షరం *devs)
{
	KbdintAuthctxt *kbdintctxt;
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం i, r;

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (!options.use_pam)
		remove_kbdint_device("pam");
#అయితే_ముగింపు

	kbdintctxt = xcalloc(1, పరిమాణం(KbdintAuthctxt));
	ఒకవేళ (strcmp(devs, "") == 0) {
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new failed");
		కొరకు (i = 0; devices[i]; i++) {
			ఒకవేళ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ఒకవేళ ((kbdintctxt->devices = sshbuf_dup_string(b)) == ఖాళీ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} లేకపోతే {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ఖాళీ;
	kbdintctxt->device = ఖాళీ;
	kbdintctxt->nreq = 0;

	తిరిగి kbdintctxt;
}
స్థిర శూన్య
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ఒకవేళ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ఖాళీ;
	}
	kbdintctxt->device = ఖాళీ;
}
స్థిర శూన్య
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ఒకవేళ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	విడుదల(kbdintctxt->devices);
	freezero(kbdintctxt, పరిమాణం(*kbdintctxt));
}
/* get next device */
స్థిర పూర్ణాంకం
kbdint_తదుపరి_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	కొలత_t len;
	అక్షరం *t;
	కొలత_t i;

	ఒకవేళ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	చేయి {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ఒకవేళ (len == 0)
			ఆపు;
		కొరకు (i = 0; devices[i]; i++) {
			ఒకవేళ (i >= పరిమాణం(kbdintctxt->devices_పూర్తి) * 8 ||
			    i >= పరిమాణం(devices) / పరిమాణం(devices[0]))
				fatal_f("internal error: too many devices");
			ఒకవేళ ((kbdintctxt->devices_పూర్తి & (1 << i)) != 0 ||
			    !auth2_పద్ధతి_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				కొనసాగు;
			ఒకవేళ (అక్షరశ్రేణి_పొడవు(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_పూర్తి |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ఖాళీ;
		విడుదల(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} అయితే (kbdintctxt->devices && !kbdintctxt->device);

	తిరిగి kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
పూర్ణాంకం
auth2_challenge(నిర్మాణం ssh *ssh, అక్షరం *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ఒకవేళ (authctxt->user == ఖాళీ || !devs)
		తిరిగి 0;
	ఒకవేళ (authctxt->kbdintctxt == ఖాళీ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	తిరిగి auth2_challenge_ప్రారంభం(ssh);
}

/* unregister kbd-int callbacks and context */
శూన్య
auth2_challenge_stop(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_INFO_RESPONSE, ఖాళీ);
	ఒకవేళ (authctxt->kbdintctxt != ఖాళీ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ఖాళీ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
స్థిర పూర్ణాంకం
auth2_challenge_ప్రారంభం(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ఒకవేళ (kbdint_తదుపరి_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		తిరిగి 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ఒకవేళ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ఖాళీ) {
		auth2_challenge_stop(ssh);
		తిరిగి 0;
	}
	ఒకవేళ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		తిరిగి 0;
	}
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_INFO_RESPONSE,
	    &ఆదానం_userauth_info_response);

	authctxt->postponed = 1;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
send_userauth_info_request(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	అక్షరం *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ఒకవేళ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		తిరిగి 0;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	కొరకు (i = 0; i < kbdintctxt->nreq; i++) {
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ఒకవేళ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	కొరకు (i = 0; i < kbdintctxt->nreq; i++)
		విడుదల(prompts[i]);
	విడుదల(prompts);
	విడుదల(echo_on);
	విడుదల(name);
	విడుదల(instr);
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_info_response(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	పూర్ణాంకం authenticated = 0, res;
	పూర్ణాంకం r;
	u_int i, nresp;
	స్థిరరాశి అక్షరం *devicename = ఖాళీ;
	అక్షరం **response = ఖాళీ;
	ద్విగుణ tstart = monotime_double();

	ఒకవేళ (authctxt == ఖాళీ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ఒకవేళ (kbdintctxt == ఖాళీ || kbdintctxt->ctxt == ఖాళీ)
		fatal_f("no kbdintctxt");
	ఒకవేళ (kbdintctxt->device == ఖాళీ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ఒకవేళ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ఒకవేళ (nresp > 100)
		fatal_f("too many replies");
	ఒకవేళ (nresp > 0) {
		response = xcalloc(nresp, పరిమాణం(అక్షరం *));
		కొరకు (i = 0; i < nresp; i++) {
			ఒకవేళ ((r = sshpkt_get_cstring(ssh, &response[i], ఖాళీ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	కొరకు (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], అక్షరశ్రేణి_పొడవు(response[i]));
		విడుదల(response[i]);
	}
	విడుదల(response);

	ఎంపిక (res) {
	స్థితి 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		ఆపు;
	స్థితి 1:
		/* Authentication needs further interaction */
		ఒకవేళ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		ఆపు;
	అప్రమేయ:
		/* Failure! */
		ఆపు;
	}
	devicename = kbdintctxt->device->name;
	ఒకవేళ (!authctxt->postponed) {
		ఒకవేళ (authenticated) {
			auth2_challenge_stop(ssh);
		} లేకపోతే {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_ప్రారంభం(ssh);
		}
	}

	ఒకవేళ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_ముగింపు(ssh, authenticated, "keyboard-interactive",
	    devicename);
	తిరిగి 0;
}
