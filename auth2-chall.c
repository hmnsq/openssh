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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"

/* import */
ബാഹ്യ ServerOptions options;

സ്ഥിതം പൂർണ്ണസംഖ്യ auth2_challenge_start(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ send_userauth_info_request(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_info_response(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

#ifdef BSD_AUTH
ബാഹ്യ KbdintDevice mm_bsdauth_device;
#അല്ലെങ്കിൽ
#ifdef USE_PAM
ബാഹ്യ KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#അല്ലെങ്കിൽ
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	ശൂന്യ
};

തരനിർവചനം ഘടന KbdintAuthctxt KbdintAuthctxt;
ഘടന KbdintAuthctxt
{
	അക്ഷരം *devices;
	ശൂന്യം *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
ശൂന്യം
remove_kbdint_device(സ്ഥിരം അക്ഷരം *devname)
{
	പൂർണ്ണസംഖ്യ i, j;

	വേണ്ടി (i = 0; devices[i] != ശൂന്യ; i++)
		എങ്കിൽ (strcmp(devices[i]->name, devname) == 0) {
			വേണ്ടി (j = i; devices[j] != ശൂന്യ; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

സ്ഥിതം KbdintAuthctxt *
kbdint_alloc(സ്ഥിരം അക്ഷരം *devs)
{
	KbdintAuthctxt *kbdintctxt;
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ i, r;

#ifdef USE_PAM
	എങ്കിൽ (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, വലുപ്പം(KbdintAuthctxt));
	എങ്കിൽ (strcmp(devs, "") == 0) {
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new failed");
		വേണ്ടി (i = 0; devices[i]; i++) {
			എങ്കിൽ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		എങ്കിൽ ((kbdintctxt->devices = sshbuf_dup_string(b)) == ശൂന്യ)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} അല്ലെങ്കിൽ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = ശൂന്യ;
	kbdintctxt->device = ശൂന്യ;
	kbdintctxt->nreq = 0;

	തിരികെ kbdintctxt;
}
സ്ഥിതം ശൂന്യം
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	എങ്കിൽ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = ശൂന്യ;
	}
	kbdintctxt->device = ശൂന്യ;
}
സ്ഥിതം ശൂന്യം
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	എങ്കിൽ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	സ്വതന്ത്രം(kbdintctxt->devices);
	freezero(kbdintctxt, വലുപ്പം(*kbdintctxt));
}
/* get next device */
സ്ഥിതം പൂർണ്ണസംഖ്യ
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	അക്ഷരം *t;
	size_t i;

	എങ്കിൽ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	ചെയ്യുക {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		എങ്കിൽ (len == 0)
			നിർത്തുക;
		വേണ്ടി (i = 0; devices[i]; i++) {
			എങ്കിൽ (i >= വലുപ്പം(kbdintctxt->devices_done) * 8 ||
			    i >= വലുപ്പം(devices) / വലുപ്പം(devices[0]))
				fatal_f("internal error: too many devices");
			എങ്കിൽ ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				തുടരുക;
			എങ്കിൽ (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : ശൂന്യ;
		സ്വതന്ത്രം(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ആകുമ്പോൾ (kbdintctxt->devices && !kbdintctxt->device);

	തിരികെ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
പൂർണ്ണസംഖ്യ
auth2_challenge(ഘടന ssh *ssh, അക്ഷരം *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	എങ്കിൽ (authctxt->user == ശൂന്യ || !devs)
		തിരികെ 0;
	എങ്കിൽ (authctxt->kbdintctxt == ശൂന്യ)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	തിരികെ auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
ശൂന്യം
auth2_challenge_stop(ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_RESPONSE, ശൂന്യ);
	എങ്കിൽ (authctxt->kbdintctxt != ശൂന്യ) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = ശൂന്യ;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
സ്ഥിതം പൂർണ്ണസംഖ്യ
auth2_challenge_start(ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	എങ്കിൽ (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		തിരികെ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	എങ്കിൽ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == ശൂന്യ) {
		auth2_challenge_stop(ssh);
		തിരികെ 0;
	}
	എങ്കിൽ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		തിരികെ 0;
	}
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_RESPONSE,
	    &നിവേശം_userauth_info_response);

	authctxt->postponed = 1;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
send_userauth_info_request(ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	അക്ഷരം *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	എങ്കിൽ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		തിരികെ 0;

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	വേണ്ടി (i = 0; i < kbdintctxt->nreq; i++) {
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	എങ്കിൽ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	വേണ്ടി (i = 0; i < kbdintctxt->nreq; i++)
		സ്വതന്ത്രം(prompts[i]);
	സ്വതന്ത്രം(prompts);
	സ്വതന്ത്രം(echo_on);
	സ്വതന്ത്രം(name);
	സ്വതന്ത്രം(instr);
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_info_response(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	പൂർണ്ണസംഖ്യ authenticated = 0, res;
	പൂർണ്ണസംഖ്യ r;
	u_int i, nresp;
	സ്ഥിരം അക്ഷരം *devicename = ശൂന്യ;
	അക്ഷരം **response = ശൂന്യ;
	ഇരട്ട tstart = monotime_double();

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	എങ്കിൽ (kbdintctxt == ശൂന്യ || kbdintctxt->ctxt == ശൂന്യ)
		fatal_f("no kbdintctxt");
	എങ്കിൽ (kbdintctxt->device == ശൂന്യ)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	എങ്കിൽ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	എങ്കിൽ (nresp > 100)
		fatal_f("too many replies");
	എങ്കിൽ (nresp > 0) {
		response = xcalloc(nresp, വലുപ്പം(അക്ഷരം *));
		വേണ്ടി (i = 0; i < nresp; i++) {
			എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &response[i], ശൂന്യ)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	വേണ്ടി (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		സ്വതന്ത്രം(response[i]);
	}
	സ്വതന്ത്രം(response);

	തിരഞ്ഞെടുപ്പ് (res) {
	അവസ്ഥ 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		നിർത്തുക;
	അവസ്ഥ 1:
		/* Authentication needs further interaction */
		എങ്കിൽ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		/* Failure! */
		നിർത്തുക;
	}
	devicename = kbdintctxt->device->name;
	എങ്കിൽ (!authctxt->postponed) {
		എങ്കിൽ (authenticated) {
			auth2_challenge_stop(ssh);
		} അല്ലെങ്കിൽ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	എങ്കിൽ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	തിരികെ 0;
}
