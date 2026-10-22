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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"

/* import */
ବାହ୍ୟ ServerOptions options;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth2_challenge_start(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା send_userauth_info_request(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_info_response(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

#ifdef BSD_AUTH
ବାହ୍ୟ KbdintDevice mm_bsdauth_device;
#ଅନ୍ୟଥା
#ifdef USE_PAM
ବାହ୍ୟ KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#ଅନ୍ୟଥା
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	ଖାଲି
};

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା KbdintAuthctxt KbdintAuthctxt;
ସଂରଚନା KbdintAuthctxt
{
	ଅକ୍ଷର *devices;
	ଶୂନ୍ୟ *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
ଶୂନ୍ୟ
remove_kbdint_device(ଅଚଳ ଅକ୍ଷର *devname)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;

	ପାଇଁ (i = 0; devices[i] != ଖାଲି; i++)
		ଯଦି (strcmp(devices[i]->name, devname) == 0) {
			ପାଇଁ (j = i; devices[j] != ଖାଲି; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

ସ୍ଥିର KbdintAuthctxt *
kbdint_alloc(ଅଚଳ ଅକ୍ଷର *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;

#ifdef USE_PAM
	ଯଦି (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, ଆକାର(KbdintAuthctxt));
	ଯଦି (strcmp(devs, "") == 0) {
		ଯଦି ((b = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new failed");
		ପାଇଁ (i = 0; devices[i]; i++) {
			ଯଦି ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ଯଦି ((kbdintctxt->devices = sshbuf_dup_string(b)) == ଖାଲି)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ଅନ୍ୟଥା {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ଖାଲି;
	kbdintctxt->device = ଖାଲି;
	kbdintctxt->nreq = 0;

	ଫେରନ୍ତୁ kbdintctxt;
}
ସ୍ଥିର ଶୂନ୍ୟ
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ଯଦି (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ଖାଲି;
	}
	kbdintctxt->device = ଖାଲି;
}
ସ୍ଥିର ଶୂନ୍ୟ
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ଯଦି (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ମୁକ୍ତ(kbdintctxt->devices);
	freezero(kbdintctxt, ଆକାର(*kbdintctxt));
}
/* get next device */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	ଅକ୍ଷର *t;
	size_t i;

	ଯଦି (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	କର {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ଯଦି (len == 0)
			ଭାଙ୍ଗ;
		ପାଇଁ (i = 0; devices[i]; i++) {
			ଯଦି (i >= ଆକାର(kbdintctxt->devices_done) * 8 ||
			    i >= ଆକାର(devices) / ଆକାର(devices[0]))
				fatal_f("internal error: too many devices");
			ଯଦି ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ଜାରି;
			ଯଦି (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ଖାଲି;
		ମୁକ୍ତ(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ଯେତେବେଳେ (kbdintctxt->devices && !kbdintctxt->device);

	ଫେରନ୍ତୁ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_challenge(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ଯଦି (authctxt->user == ଖାଲି || !devs)
		ଫେରନ୍ତୁ 0;
	ଯଦି (authctxt->kbdintctxt == ଖାଲି)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ଫେରନ୍ତୁ auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
ଶୂନ୍ୟ
auth2_challenge_stop(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_RESPONSE, ଖାଲି);
	ଯଦି (authctxt->kbdintctxt != ଖାଲି) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ଖାଲି;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_challenge_start(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ଯଦି (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ଫେରନ୍ତୁ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ଯଦି ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ଖାଲି) {
		auth2_challenge_stop(ssh);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ଫେରନ୍ତୁ 0;
	}
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_RESPONSE,
	    &ନିବେଶ_userauth_info_response);

	authctxt->postponed = 1;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
send_userauth_info_request(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ଅକ୍ଷର *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ଯଦି (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ଫେରନ୍ତୁ 0;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	ପାଇଁ (i = 0; i < kbdintctxt->nreq; i++) {
		ଯଦି ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ଯଦି ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	ପାଇଁ (i = 0; i < kbdintctxt->nreq; i++)
		ମୁକ୍ତ(prompts[i]);
	ମୁକ୍ତ(prompts);
	ମୁକ୍ତ(echo_on);
	ମୁକ୍ତ(name);
	ମୁକ୍ତ(instr);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_info_response(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା authenticated = 0, res;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, nresp;
	ଅଚଳ ଅକ୍ଷର *devicename = ଖାଲି;
	ଅକ୍ଷର **response = ଖାଲି;
	ଦ୍ୱିଗୁଣ tstart = monotime_double();

	ଯଦି (authctxt == ଖାଲି)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ଯଦି (kbdintctxt == ଖାଲି || kbdintctxt->ctxt == ଖାଲି)
		fatal_f("no kbdintctxt");
	ଯଦି (kbdintctxt->device == ଖାଲି)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ଯଦି ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ଯଦି (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ଯଦି (nresp > 100)
		fatal_f("too many replies");
	ଯଦି (nresp > 0) {
		response = xcalloc(nresp, ଆକାର(ଅକ୍ଷର *));
		ପାଇଁ (i = 0; i < nresp; i++) {
			ଯଦି ((r = sshpkt_get_cstring(ssh, &response[i], ଖାଲି)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	ପାଇଁ (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		ମୁକ୍ତ(response[i]);
	}
	ମୁକ୍ତ(response);

	ବାଛ (res) {
	ସ୍ଥିତି 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 1:
		/* Authentication needs further interaction */
		ଯଦି (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		/* Failure! */
		ଭାଙ୍ଗ;
	}
	devicename = kbdintctxt->device->name;
	ଯଦି (!authctxt->postponed) {
		ଯଦି (authenticated) {
			auth2_challenge_stop(ssh);
		} ଅନ୍ୟଥା {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	ଯଦି (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ଫେରନ୍ତୁ 0;
}
