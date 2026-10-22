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

स्थिर पूर्णांक auth2_challenge_start(संरचना ssh *);
स्थिर पूर्णांक send_userauth_info_request(संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_info_response(पूर्णांक, uint32_t, संरचना ssh *);

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

प्रकारव्याख्या संरचना KbdintAuthctxt KbdintAuthctxt;
संरचना KbdintAuthctxt
{
	अक्षर *devices;
	शून्य *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
शून्य
remove_kbdint_device(स्थिरांक अक्षर *devname)
{
	पूर्णांक i, j;

	साठी (i = 0; devices[i] != रिक्त; i++)
		जर (म_भेद(devices[i]->name, devname) == 0) {
			साठी (j = i; devices[j] != रिक्त; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

स्थिर KbdintAuthctxt *
kbdint_alloc(स्थिरांक अक्षर *devs)
{
	KbdintAuthctxt *kbdintctxt;
	संरचना sshbuf *b;
	पूर्णांक i, r;

#ifdef USE_PAM
	जर (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, आकार(KbdintAuthctxt));
	जर (म_भेद(devs, "") == 0) {
		जर ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		साठी (i = 0; devices[i]; i++) {
			जर ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		जर ((kbdintctxt->devices = sshbuf_dup_string(b)) == रिक्त)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} अन्यथा {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = रिक्त;
	kbdintctxt->device = रिक्त;
	kbdintctxt->nreq = 0;

	परत kbdintctxt;
}
स्थिर शून्य
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	जर (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = रिक्त;
	}
	kbdintctxt->device = रिक्त;
}
स्थिर शून्य
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	जर (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	मुक्त(kbdintctxt->devices);
	freezero(kbdintctxt, आकार(*kbdintctxt));
}
/* get next device */
स्थिर पूर्णांक
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	माप_प्रकार len;
	अक्षर *t;
	माप_प्रकार i;

	जर (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	करा {
		len = kbdintctxt->devices ?
		    म_खोज(kbdintctxt->devices, ",") : 0;

		जर (len == 0)
			थांबा;
		साठी (i = 0; devices[i]; i++) {
			जर (i >= आकार(kbdintctxt->devices_done) * 8 ||
			    i >= आकार(devices) / आकार(devices[0]))
				fatal_f("internal error: too many devices");
			जर ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				सुरूठेवा;
			जर (म_माप(devices[i]->name) == len &&
			    स_भेद(kbdintctxt->devices, devices[i]->name,
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
	} पर्यंत (kbdintctxt->devices && !kbdintctxt->device);

	परत kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
पूर्णांक
auth2_challenge(संरचना ssh *ssh, अक्षर *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	जर (authctxt->user == रिक्त || !devs)
		परत 0;
	जर (authctxt->kbdintctxt == रिक्त)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	परत auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
शून्य
auth2_challenge_stop(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE, रिक्त);
	जर (authctxt->kbdintctxt != रिक्त) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = रिक्त;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
स्थिर पूर्णांक
auth2_challenge_start(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	जर (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		परत 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	जर ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == रिक्त) {
		auth2_challenge_stop(ssh);
		परत 0;
	}
	जर (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		परत 0;
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE,
	    &आदान_userauth_info_response);

	authctxt->postponed = 1;
	परत 0;
}

स्थिर पूर्णांक
send_userauth_info_request(संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	अक्षर *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	जर (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		परत 0;

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	साठी (i = 0; i < kbdintctxt->nreq; i++) {
		जर ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	जर ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	साठी (i = 0; i < kbdintctxt->nreq; i++)
		मुक्त(prompts[i]);
	मुक्त(prompts);
	मुक्त(echo_on);
	मुक्त(name);
	मुक्त(instr);
	परत 1;
}

स्थिर पूर्णांक
आदान_userauth_info_response(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	पूर्णांक authenticated = 0, res;
	पूर्णांक r;
	u_int i, nresp;
	स्थिरांक अक्षर *devicename = रिक्त;
	अक्षर **response = रिक्त;
	द्विगुण tstart = monotime_double();

	जर (authctxt == रिक्त)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	जर (kbdintctxt == रिक्त || kbdintctxt->ctxt == रिक्त)
		fatal_f("no kbdintctxt");
	जर (kbdintctxt->device == रिक्त)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	जर ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	जर (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	जर (nresp > 100)
		fatal_f("too many replies");
	जर (nresp > 0) {
		response = xcalloc(nresp, आकार(अक्षर *));
		साठी (i = 0; i < nresp; i++) {
			जर ((r = sshpkt_get_cstring(ssh, &response[i], रिक्त)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	जर ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	साठी (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], म_माप(response[i]));
		मुक्त(response[i]);
	}
	मुक्त(response);

	निवड (res) {
	स्थिती 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		थांबा;
	स्थिती 1:
		/* Authentication needs further interaction */
		जर (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		थांबा;
	पूर्वनिर्धारित:
		/* Failure! */
		थांबा;
	}
	devicename = kbdintctxt->device->name;
	जर (!authctxt->postponed) {
		जर (authenticated) {
			auth2_challenge_stop(ssh);
		} अन्यथा {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	जर (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	परत 0;
}
