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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"

/* import */
बाह्य ServerOptions options;

स्थिर पूर्णाङ्क auth2_challenge_start(संरचना ssh *);
स्थिर पूर्णाङ्क send_userauth_info_request(संरचना ssh *);
स्थिर पूर्णाङ्क आदान_userauth_info_response(पूर्णाङ्क, uint32_t, संरचना ssh *);

#ifdef BSD_AUTH
बाह्य KbdintDevice mm_bsdauth_device;
#अन्यथा
#ifdef USE_PAM
बाह्य KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#अन्यथा
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	रिक्त
};

प्रकारनिर्देश संरचना KbdintAuthctxt KbdintAuthctxt;
संरचना KbdintAuthctxt
{
	वर्ण *devices;
	शून्य *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
शून्य
remove_kbdint_device(ध्रुव वर्ण *devname)
{
	पूर्णाङ्क i, j;

	प्रति (i = 0; devices[i] != रिक्त; i++)
		यदि (strcmp(devices[i]->name, devname) == 0) {
			प्रति (j = i; devices[j] != रिक्त; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

स्थिर KbdintAuthctxt *
kbdint_alloc(ध्रुव वर्ण *devs)
{
	KbdintAuthctxt *kbdintctxt;
	संरचना sshbuf *b;
	पूर्णाङ्क i, r;

#ifdef USE_PAM
	यदि (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, परिमाण(KbdintAuthctxt));
	यदि (strcmp(devs, "") == 0) {
		यदि ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		प्रति (i = 0; devices[i]; i++) {
			यदि ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		यदि ((kbdintctxt->devices = sshbuf_dup_string(b)) == रिक्त)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} अन्यथा {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = रिक्त;
	kbdintctxt->device = रिक्त;
	kbdintctxt->nreq = 0;

	प्रत्यागम kbdintctxt;
}
स्थिर शून्य
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	यदि (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = रिक्त;
	}
	kbdintctxt->device = रिक्त;
}
स्थिर शून्य
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	यदि (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	मुक्त(kbdintctxt->devices);
	freezero(kbdintctxt, परिमाण(*kbdintctxt));
}
/* get next device */
स्थिर पूर्णाङ्क
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	वर्ण *t;
	size_t i;

	यदि (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	कुरु {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		यदि (len == 0)
			भङ्ग;
		प्रति (i = 0; devices[i]; i++) {
			यदि (i >= परिमाण(kbdintctxt->devices_done) * 8 ||
			    i >= परिमाण(devices) / परिमाण(devices[0]))
				fatal_f("internal error: too many devices");
			यदि ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				अनुवर्त;
			यदि (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : रिक्त;
		मुक्त(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} यावत् (kbdintctxt->devices && !kbdintctxt->device);

	प्रत्यागम kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
पूर्णाङ्क
auth2_challenge(संरचना ssh *ssh, वर्ण *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	यदि (authctxt->user == रिक्त || !devs)
		प्रत्यागम 0;
	यदि (authctxt->kbdintctxt == रिक्त)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	प्रत्यागम auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
शून्य
auth2_challenge_stop(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE, रिक्त);
	यदि (authctxt->kbdintctxt != रिक्त) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = रिक्त;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
स्थिर पूर्णाङ्क
auth2_challenge_start(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	यदि (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		प्रत्यागम 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	यदि ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == रिक्त) {
		auth2_challenge_stop(ssh);
		प्रत्यागम 0;
	}
	यदि (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		प्रत्यागम 0;
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE,
	    &आदान_userauth_info_response);

	authctxt->postponed = 1;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
send_userauth_info_request(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	वर्ण *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	यदि (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		प्रत्यागम 0;

	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	प्रति (i = 0; i < kbdintctxt->nreq; i++) {
		यदि ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	यदि ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	प्रति (i = 0; i < kbdintctxt->nreq; i++)
		मुक्त(prompts[i]);
	मुक्त(prompts);
	मुक्त(echo_on);
	मुक्त(name);
	मुक्त(instr);
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
आदान_userauth_info_response(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	पूर्णाङ्क authenticated = 0, res;
	पूर्णाङ्क r;
	u_int i, nresp;
	ध्रुव वर्ण *devicename = रिक्त;
	वर्ण **response = रिक्त;
	द्विगुण tstart = monotime_double();

	यदि (authctxt == रिक्त)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	यदि (kbdintctxt == रिक्त || kbdintctxt->ctxt == रिक्त)
		fatal_f("no kbdintctxt");
	यदि (kbdintctxt->device == रिक्त)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	यदि ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	यदि (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	यदि (nresp > 100)
		fatal_f("too many replies");
	यदि (nresp > 0) {
		response = xcalloc(nresp, परिमाण(वर्ण *));
		प्रति (i = 0; i < nresp; i++) {
			यदि ((r = sshpkt_get_cstring(ssh, &response[i], रिक्त)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	यदि ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	प्रति (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		मुक्त(response[i]);
	}
	मुक्त(response);

	विकल्प (res) {
	पक्ष 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		भङ्ग;
	पक्ष 1:
		/* Authentication needs further interaction */
		यदि (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		भङ्ग;
	स्वभाव:
		/* Failure! */
		भङ्ग;
	}
	devicename = kbdintctxt->device->name;
	यदि (!authctxt->postponed) {
		यदि (authenticated) {
			auth2_challenge_stop(ssh);
		} अन्यथा {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	यदि (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	प्रत्यागम 0;
}
