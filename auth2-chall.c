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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"

/* import */
બાહ્ય ServerOptions options;

સ્થિર પૂર્ણાંક auth2_challenge_start(સંરચના ssh *);
સ્થિર પૂર્ણાંક send_userauth_info_request(સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_info_response(પૂર્ણાંક, uint32_t, સંરચના ssh *);

#ifdef BSD_AUTH
બાહ્ય KbdintDevice mm_bsdauth_device;
#નહીંતર
#ifdef USE_PAM
બાહ્ય KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#નહીંતર
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	ખાલી
};

પ્રકારવ્યાખ્યા સંરચના KbdintAuthctxt KbdintAuthctxt;
સંરચના KbdintAuthctxt
{
	અક્ષર *devices;
	શૂન્ય *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
શૂન્ય
remove_kbdint_device(અચલ અક્ષર *devname)
{
	પૂર્ણાંક i, j;

	માટે (i = 0; devices[i] != ખાલી; i++)
		જો (strcmp(devices[i]->name, devname) == 0) {
			માટે (j = i; devices[j] != ખાલી; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

સ્થિર KbdintAuthctxt *
kbdint_alloc(અચલ અક્ષર *devs)
{
	KbdintAuthctxt *kbdintctxt;
	સંરચના sshbuf *b;
	પૂર્ણાંક i, r;

#ifdef USE_PAM
	જો (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, કદ(KbdintAuthctxt));
	જો (strcmp(devs, "") == 0) {
		જો ((b = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new failed");
		માટે (i = 0; devices[i]; i++) {
			જો ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		જો ((kbdintctxt->devices = sshbuf_dup_string(b)) == ખાલી)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} નહીંતર {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ખાલી;
	kbdintctxt->device = ખાલી;
	kbdintctxt->nreq = 0;

	પાછા kbdintctxt;
}
સ્થિર શૂન્ય
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	જો (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ખાલી;
	}
	kbdintctxt->device = ખાલી;
}
સ્થિર શૂન્ય
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	જો (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	મુક્ત(kbdintctxt->devices);
	freezero(kbdintctxt, કદ(*kbdintctxt));
}
/* get next device */
સ્થિર પૂર્ણાંક
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	અક્ષર *t;
	size_t i;

	જો (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	કરો {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		જો (len == 0)
			તોડો;
		માટે (i = 0; devices[i]; i++) {
			જો (i >= કદ(kbdintctxt->devices_done) * 8 ||
			    i >= કદ(devices) / કદ(devices[0]))
				fatal_f("internal error: too many devices");
			જો ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				ચાલુ;
			જો (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ખાલી;
		મુક્ત(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} જ્યારે (kbdintctxt->devices && !kbdintctxt->device);

	પાછા kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
પૂર્ણાંક
auth2_challenge(સંરચના ssh *ssh, અક્ષર *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	જો (authctxt->user == ખાલી || !devs)
		પાછા 0;
	જો (authctxt->kbdintctxt == ખાલી)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	પાછા auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
શૂન્ય
auth2_challenge_stop(સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_INFO_RESPONSE, ખાલી);
	જો (authctxt->kbdintctxt != ખાલી) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ખાલી;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
સ્થિર પૂર્ણાંક
auth2_challenge_start(સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	જો (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		પાછા 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	જો ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ખાલી) {
		auth2_challenge_stop(ssh);
		પાછા 0;
	}
	જો (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		પાછા 0;
	}
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_INFO_RESPONSE,
	    &આગત_userauth_info_response);

	authctxt->postponed = 1;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
send_userauth_info_request(સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	અક્ષર *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	જો (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		પાછા 0;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	માટે (i = 0; i < kbdintctxt->nreq; i++) {
		જો ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	જો ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	માટે (i = 0; i < kbdintctxt->nreq; i++)
		મુક્ત(prompts[i]);
	મુક્ત(prompts);
	મુક્ત(echo_on);
	મુક્ત(name);
	મુક્ત(instr);
	પાછા 1;
}

સ્થિર પૂર્ણાંક
આગત_userauth_info_response(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	પૂર્ણાંક authenticated = 0, res;
	પૂર્ણાંક r;
	u_int i, nresp;
	અચલ અક્ષર *devicename = ખાલી;
	અક્ષર **response = ખાલી;
	દ્વિગુણ tstart = monotime_double();

	જો (authctxt == ખાલી)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	જો (kbdintctxt == ખાલી || kbdintctxt->ctxt == ખાલી)
		fatal_f("no kbdintctxt");
	જો (kbdintctxt->device == ખાલી)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	જો ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	જો (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	જો (nresp > 100)
		fatal_f("too many replies");
	જો (nresp > 0) {
		response = xcalloc(nresp, કદ(અક્ષર *));
		માટે (i = 0; i < nresp; i++) {
			જો ((r = sshpkt_get_cstring(ssh, &response[i], ખાલી)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	જો ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	માટે (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		મુક્ત(response[i]);
	}
	મુક્ત(response);

	પસંદગી (res) {
	સ્થિતિ 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		તોડો;
	સ્થિતિ 1:
		/* Authentication needs further interaction */
		જો (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		તોડો;
	મૂળભૂત:
		/* Failure! */
		તોડો;
	}
	devicename = kbdintctxt->device->name;
	જો (!authctxt->postponed) {
		જો (authenticated) {
			auth2_challenge_stop(ssh);
		} નહીંતર {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	જો (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	પાછા 0;
}
