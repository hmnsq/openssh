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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"

/* import */
বাহ্যিক ServerOptions options;

স্থির পূর্ণসংখ্যা auth2_challenge_start(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা send_userauth_info_request(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_info_response(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

#ifdef BSD_AUTH
বাহ্যিক KbdintDevice mm_bsdauth_device;
#অন্যথা
#ifdef USE_PAM
বাহ্যিক KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#অন্যথা
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	ফাঁকা
};

প্রকারলেখ কাঠামো KbdintAuthctxt KbdintAuthctxt;
কাঠামো KbdintAuthctxt
{
	অক্ষর *devices;
	শূন্য *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
শূন্য
remove_kbdint_device(ধ্রুবক অক্ষর *devname)
{
	পূর্ণসংখ্যা i, j;

	জন্য (i = 0; devices[i] != ফাঁকা; i++)
		যদি (strcmp(devices[i]->name, devname) == 0) {
			জন্য (j = i; devices[j] != ফাঁকা; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

স্থির KbdintAuthctxt *
kbdint_alloc(ধ্রুবক অক্ষর *devs)
{
	KbdintAuthctxt *kbdintctxt;
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা i, r;

#ifdef USE_PAM
	যদি (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, আকার(KbdintAuthctxt));
	যদি (strcmp(devs, "") == 0) {
		যদি ((b = sshbuf_new()) == ফাঁকা)
			fatal_f("sshbuf_new failed");
		জন্য (i = 0; devices[i]; i++) {
			যদি ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		যদি ((kbdintctxt->devices = sshbuf_dup_string(b)) == ফাঁকা)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} অন্যথা {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ফাঁকা;
	kbdintctxt->device = ফাঁকা;
	kbdintctxt->nreq = 0;

	ফেরত kbdintctxt;
}
স্থির শূন্য
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	যদি (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ফাঁকা;
	}
	kbdintctxt->device = ফাঁকা;
}
স্থির শূন্য
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	যদি (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	মুক্ত(kbdintctxt->devices);
	freezero(kbdintctxt, আকার(*kbdintctxt));
}
/* get next device */
স্থির পূর্ণসংখ্যা
kbdint_পরবর্তী_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	আকার_t len;
	অক্ষর *t;
	আকার_t i;

	যদি (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	করো {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		যদি (len == 0)
			বিরতি;
		জন্য (i = 0; devices[i]; i++) {
			যদি (i >= আকার(kbdintctxt->devices_done) * 8 ||
			    i >= আকার(devices) / আকার(devices[0]))
				fatal_f("internal error: too many devices");
			যদি ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				চালু;
			যদি (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ফাঁকা;
		মুক্ত(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} যখন (kbdintctxt->devices && !kbdintctxt->device);

	ফেরত kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
পূর্ণসংখ্যা
auth2_challenge(কাঠামো ssh *ssh, অক্ষর *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	যদি (authctxt->user == ফাঁকা || !devs)
		ফেরত 0;
	যদি (authctxt->kbdintctxt == ফাঁকা)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ফেরত auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
শূন্য
auth2_challenge_stop(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_RESPONSE, ফাঁকা);
	যদি (authctxt->kbdintctxt != ফাঁকা) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ফাঁকা;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
স্থির পূর্ণসংখ্যা
auth2_challenge_start(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	যদি (kbdint_পরবর্তী_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ফেরত 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	যদি ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ফাঁকা) {
		auth2_challenge_stop(ssh);
		ফেরত 0;
	}
	যদি (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ফেরত 0;
	}
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_RESPONSE,
	    &প্রবেশ_userauth_info_response);

	authctxt->postponed = 1;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
send_userauth_info_request(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	অক্ষর *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	যদি (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ফেরত 0;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	জন্য (i = 0; i < kbdintctxt->nreq; i++) {
		যদি ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	যদি ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	জন্য (i = 0; i < kbdintctxt->nreq; i++)
		মুক্ত(prompts[i]);
	মুক্ত(prompts);
	মুক্ত(echo_on);
	মুক্ত(name);
	মুক্ত(instr);
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_info_response(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	পূর্ণসংখ্যা authenticated = 0, res;
	পূর্ণসংখ্যা r;
	u_int i, nresp;
	ধ্রুবক অক্ষর *devicename = ফাঁকা;
	অক্ষর **response = ফাঁকা;
	দ্বিগুণ tstart = monotime_double();

	যদি (authctxt == ফাঁকা)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	যদি (kbdintctxt == ফাঁকা || kbdintctxt->ctxt == ফাঁকা)
		fatal_f("no kbdintctxt");
	যদি (kbdintctxt->device == ফাঁকা)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	যদি ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	যদি (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	যদি (nresp > 100)
		fatal_f("too many replies");
	যদি (nresp > 0) {
		response = xcalloc(nresp, আকার(অক্ষর *));
		জন্য (i = 0; i < nresp; i++) {
			যদি ((r = sshpkt_get_cstring(ssh, &response[i], ফাঁকা)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	জন্য (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		মুক্ত(response[i]);
	}
	মুক্ত(response);

	নির্বাচন (res) {
	ক্ষেত্র 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		বিরতি;
	ক্ষেত্র 1:
		/* Authentication needs further interaction */
		যদি (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		বিরতি;
	পূর্বনির্ধারিত:
		/* Failure! */
		বিরতি;
	}
	devicename = kbdintctxt->device->name;
	যদি (!authctxt->postponed) {
		যদি (authenticated) {
			auth2_challenge_stop(ssh);
		} অন্যথা {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	যদি (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ফেরত 0;
}
