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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "ssh2.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "dispatch.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"

/* import */
बाह्य ServerOptions options;

अटल पूर्णांक auth2_challenge_start(काष्ठा ssh *);
अटल पूर्णांक send_userauth_info_request(काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_info_response(पूर्णांक, uint32_t, काष्ठा ssh *);

#अगर_घोषित BSD_AUTH
बाह्य KbdintDevice mm_bsdauth_device;
#अन्यथा
#अगर_घोषित USE_PAM
बाह्य KbdintDevice mm_sshpam_device;
#पूर्ण_अगर
#पूर्ण_अगर

KbdintDevice *devices[] = {
#अगर_घोषित BSD_AUTH
	&mm_bsdauth_device,
#अन्यथा
#अगर_घोषित USE_PAM
	&mm_sshpam_device,
#पूर्ण_अगर
#पूर्ण_अगर
	शून्य
};

प्रकार काष्ठा KbdintAuthctxt KbdintAuthctxt;
काष्ठा KbdintAuthctxt
{
	अक्षर *devices;
	व्योम *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#अगर_घोषित USE_PAM
व्योम
remove_kbdint_device(स्थिर अक्षर *devname)
{
	पूर्णांक i, j;

	क्रम (i = 0; devices[i] != शून्य; i++)
		अगर (म_भेद(devices[i]->name, devname) == 0) {
			क्रम (j = i; devices[j] != शून्य; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#पूर्ण_अगर

अटल KbdintAuthctxt *
kbdint_alloc(स्थिर अक्षर *devs)
{
	KbdintAuthctxt *kbdintctxt;
	काष्ठा sshbuf *b;
	पूर्णांक i, r;

#अगर_घोषित USE_PAM
	अगर (!options.use_pam)
		remove_kbdint_device("pam");
#पूर्ण_अगर

	kbdintctxt = xcalloc(1, माप(KbdintAuthctxt));
	अगर (म_भेद(devs, "") == 0) {
		अगर ((b = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new failed");
		क्रम (i = 0; devices[i]; i++) {
			अगर ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		अगर ((kbdintctxt->devices = sshbuf_dup_string(b)) == शून्य)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} अन्यथा {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = शून्य;
	kbdintctxt->device = शून्य;
	kbdintctxt->nreq = 0;

	वापस kbdintctxt;
}
अटल व्योम
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	अगर (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = शून्य;
	}
	kbdintctxt->device = शून्य;
}
अटल व्योम
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	अगर (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	मुक्त(kbdintctxt->devices);
	freezero(kbdintctxt, माप(*kbdintctxt));
}
/* get next device */
अटल पूर्णांक
kbdint_अग्र_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	माप_प्रकार len;
	अक्षर *t;
	माप_प्रकार i;

	अगर (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	करो {
		len = kbdintctxt->devices ?
		    म_खोज(kbdintctxt->devices, ",") : 0;

		अगर (len == 0)
			अवरोध;
		क्रम (i = 0; devices[i]; i++) {
			अगर (i >= माप(kbdintctxt->devices_done) * 8 ||
			    i >= माप(devices) / माप(devices[0]))
				fatal_f("internal error: too many devices");
			अगर ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				जारी;
			अगर (म_माप(devices[i]->name) == len &&
			    स_भेद(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : शून्य;
		मुक्त(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} जबतक (kbdintctxt->devices && !kbdintctxt->device);

	वापस kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
पूर्णांक
auth2_challenge(काष्ठा ssh *ssh, अक्षर *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	अगर (authctxt->user == शून्य || !devs)
		वापस 0;
	अगर (authctxt->kbdintctxt == शून्य)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	वापस auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
व्योम
auth2_challenge_stop(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE, शून्य);
	अगर (authctxt->kbdintctxt != शून्य) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = शून्य;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
अटल पूर्णांक
auth2_challenge_start(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	अगर (kbdint_अग्र_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		वापस 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	अगर ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == शून्य) {
		auth2_challenge_stop(ssh);
		वापस 0;
	}
	अगर (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		वापस 0;
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE,
	    &निवेश_userauth_info_response);

	authctxt->postponed = 1;
	वापस 0;
}

अटल पूर्णांक
send_userauth_info_request(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	अक्षर *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	अगर (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		वापस 0;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	क्रम (i = 0; i < kbdintctxt->nreq; i++) {
		अगर ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	अगर ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	क्रम (i = 0; i < kbdintctxt->nreq; i++)
		मुक्त(prompts[i]);
	मुक्त(prompts);
	मुक्त(echo_on);
	मुक्त(name);
	मुक्त(instr);
	वापस 1;
}

अटल पूर्णांक
निवेश_userauth_info_response(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	पूर्णांक authenticated = 0, res;
	पूर्णांक r;
	u_int i, nresp;
	स्थिर अक्षर *devicename = शून्य;
	अक्षर **response = शून्य;
	द्विगुन tstart = monotime_double();

	अगर (authctxt == शून्य)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	अगर (kbdintctxt == शून्य || kbdintctxt->ctxt == शून्य)
		fatal_f("no kbdintctxt");
	अगर (kbdintctxt->device == शून्य)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	अगर ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	अगर (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	अगर (nresp > 100)
		fatal_f("too many replies");
	अगर (nresp > 0) {
		response = xcalloc(nresp, माप(अक्षर *));
		क्रम (i = 0; i < nresp; i++) {
			अगर ((r = sshpkt_get_cstring(ssh, &response[i], शून्य)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	अगर ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	क्रम (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], म_माप(response[i]));
		मुक्त(response[i]);
	}
	मुक्त(response);

	चयन (res) {
	हाल 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		अवरोध;
	हाल 1:
		/* Authentication needs further interaction */
		अगर (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		अवरोध;
	शेष:
		/* Failure! */
		अवरोध;
	}
	devicename = kbdintctxt->device->name;
	अगर (!authctxt->postponed) {
		अगर (authenticated) {
			auth2_challenge_stop(ssh);
		} अन्यथा {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	अगर (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	वापस 0;
}
