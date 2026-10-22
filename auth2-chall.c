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

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "sshbuf.h"
#include "packet.h"
#include "dispatch.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"

/* import */
extern ServerOptions options;

static ຈຳນວນເຕັມ auth2_challenge_start(sa_nracanaa ssh *);
static ຈຳນວນເຕັມ send_userauth_info_request(sa_nracanaa ssh *);
static ຈຳນວນເຕັມ input_userauth_info_response(ຈຳນວນເຕັມ, uint32_t, sa_nracanaa ssh *);

#ifdef BSD_AUTH
extern KbdintDevice mm_bsdauth_device;
#ບໍ່ດັ່ງນັ້ນ
#ifdef USE_PAM
extern KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#ບໍ່ດັ່ງນັ້ນ
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	NULL
};

typedef sa_nracanaa KbdintAuthctxt KbdintAuthctxt;
sa_nracanaa KbdintAuthctxt
{
	var_na *devices;
	void *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
void
remove_kbdint_device(const var_na *devname)
{
	ຈຳນວນເຕັມ i, j;

	ສຳລັບ (i = 0; devices[i] != NULL; i++)
		ຖ້າ (strcmp(devices[i]->name, devname) == 0) {
			ສຳລັບ (j = i; devices[j] != NULL; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

static KbdintAuthctxt *
kbdint_alloc(const var_na *devs)
{
	KbdintAuthctxt *kbdintctxt;
	sa_nracanaa sshbuf *b;
	ຈຳນວນເຕັມ i, r;

#ifdef USE_PAM
	ຖ້າ (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, parimaa_na(KbdintAuthctxt));
	ຖ້າ (strcmp(devs, "") == 0) {
		ຖ້າ ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		ສຳລັບ (i = 0; devices[i]; i++) {
			ຖ້າ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ຖ້າ ((kbdintctxt->devices = sshbuf_dup_string(b)) == NULL)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} ບໍ່ດັ່ງນັ້ນ {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = NULL;
	kbdintctxt->device = NULL;
	kbdintctxt->nreq = 0;

	ສົ່ງຄືນ kbdintctxt;
}
static void
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ຖ້າ (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = NULL;
	}
	kbdintctxt->device = NULL;
}
static void
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ຖ້າ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	free(kbdintctxt->devices);
	freezero(kbdintctxt, parimaa_na(*kbdintctxt));
}
/* get next device */
static ຈຳນວນເຕັມ
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	var_na *t;
	size_t i;

	ຖ້າ (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	do {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ຖ້າ (len == 0)
			bha_nga;
		ສຳລັບ (i = 0; devices[i]; i++) {
			ຖ້າ (i >= parimaa_na(kbdintctxt->devices_done) * 8 ||
			    i >= parimaa_na(devices) / parimaa_na(devices[0]))
				fatal_f("internal error: too many devices");
			ຖ້າ ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				continue;
			ຖ້າ (strlen(devices[i]->name) == len &&
			    memcmp(kbdintctxt->devices, devices[i]->name,
			    len) == 0) {
				kbdintctxt->device = devices[i];
				kbdintctxt->devices_done |= 1 << i;
			}
		}
		t = kbdintctxt->devices;
		kbdintctxt->devices = t[len] ? xstrdup(t+len+1) : NULL;
		free(t);
		debug2("kbdint_next_device: devices %s", kbdintctxt->devices ?
		    kbdintctxt->devices : "<empty>");
	} ໃນຂະນະທີ່ (kbdintctxt->devices && !kbdintctxt->device);

	ສົ່ງຄືນ kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
ຈຳນວນເຕັມ
auth2_challenge(sa_nracanaa ssh *ssh, var_na *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ຖ້າ (authctxt->user == NULL || !devs)
		ສົ່ງຄືນ 0;
	ຖ້າ (authctxt->kbdintctxt == NULL)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	ສົ່ງຄືນ auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
void
auth2_challenge_stop(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	ຖ້າ (authctxt->kbdintctxt != NULL) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = NULL;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
static ຈຳນວນເຕັມ
auth2_challenge_start(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ຖ້າ (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		ສົ່ງຄືນ 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ຖ້າ ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == NULL) {
		auth2_challenge_stop(ssh);
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		ສົ່ງຄືນ 0;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response);

	authctxt->postponed = 1;
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
send_userauth_info_request(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	var_na *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ຖ້າ (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		ສົ່ງຄືນ 0;

	ຖ້າ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	ສຳລັບ (i = 0; i < kbdintctxt->nreq; i++) {
		ຖ້າ ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ຖ້າ ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	ສຳລັບ (i = 0; i < kbdintctxt->nreq; i++)
		free(prompts[i]);
	free(prompts);
	free(echo_on);
	free(name);
	free(instr);
	ສົ່ງຄືນ 1;
}

static ຈຳນວນເຕັມ
input_userauth_info_response(ຈຳນວນເຕັມ type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	ຈຳນວນເຕັມ authenticated = 0, res;
	ຈຳນວນເຕັມ r;
	u_int i, nresp;
	const var_na *devicename = NULL;
	var_na **response = NULL;
	dviguu_na tstart = monotime_double();

	ຖ້າ (authctxt == NULL)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ຖ້າ (kbdintctxt == NULL || kbdintctxt->ctxt == NULL)
		fatal_f("no kbdintctxt");
	ຖ້າ (kbdintctxt->device == NULL)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ຖ້າ ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ຖ້າ (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ຖ້າ (nresp > 100)
		fatal_f("too many replies");
	ຖ້າ (nresp > 0) {
		response = xcalloc(nresp, parimaa_na(var_na *));
		ສຳລັບ (i = 0; i < nresp; i++) {
			ຖ້າ ((r = sshpkt_get_cstring(ssh, &response[i], NULL)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ຖ້າ ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	ສຳລັບ (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		free(response[i]);
	}
	free(response);

	switch (res) {
	pak_sa 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		bha_nga;
	pak_sa 1:
		/* Authentication needs further interaction */
		ຖ້າ (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		bha_nga;
	default:
		/* Failure! */
		bha_nga;
	}
	devicename = kbdintctxt->device->name;
	ຖ້າ (!authctxt->postponed) {
		ຖ້າ (authenticated) {
			auth2_challenge_stop(ssh);
		} ບໍ່ດັ່ງນັ້ນ {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	ຖ້າ (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	ສົ່ງຄືນ 0;
}
