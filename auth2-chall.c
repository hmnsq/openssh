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

static số_nguyên auth2_challenge_start(struct ssh *);
static số_nguyên send_userauth_info_request(struct ssh *);
static số_nguyên input_userauth_info_response(số_nguyên, uint32_t, struct ssh *);

#ifdef BSD_AUTH
extern KbdintDevice mm_bsdauth_device;
#không_thì
#ifdef USE_PAM
extern KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#không_thì
#ifdef USE_PAM
	&mm_sshpam_device,
#endif
#endif
	NULL
};

typedef struct KbdintAuthctxt KbdintAuthctxt;
struct KbdintAuthctxt
{
	char *devices;
	void *ctxt;
	KbdintDevice *device;
	u_int nreq;
	u_int devices_done;
};

#ifdef USE_PAM
void
remove_kbdint_device(const char *devname)
{
	số_nguyên i, j;

	cho (i = 0; devices[i] != NULL; i++)
		nếu (strcmp(devices[i]->name, devname) == 0) {
			cho (j = i; devices[j] != NULL; j++)
				devices[j] = devices[j+1];
			i--;
		}
}
#endif

static KbdintAuthctxt *
kbdint_alloc(const char *devs)
{
	KbdintAuthctxt *kbdintctxt;
	struct sshbuf *b;
	số_nguyên i, r;

#ifdef USE_PAM
	nếu (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, sizeof(KbdintAuthctxt));
	nếu (strcmp(devs, "") == 0) {
		nếu ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		cho (i = 0; devices[i]; i++) {
			nếu ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		nếu ((kbdintctxt->devices = sshbuf_dup_string(b)) == NULL)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} không_thì {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = NULL;
	kbdintctxt->device = NULL;
	kbdintctxt->nreq = 0;

	trả_về kbdintctxt;
}
static void
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	nếu (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = NULL;
	}
	kbdintctxt->device = NULL;
}
static void
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	nếu (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	free(kbdintctxt->devices);
	freezero(kbdintctxt, sizeof(*kbdintctxt));
}
/* get next device */
static số_nguyên
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	char *t;
	size_t i;

	nếu (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	do {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		nếu (len == 0)
			break;
		cho (i = 0; devices[i]; i++) {
			nếu (i >= sizeof(kbdintctxt->devices_done) * 8 ||
			    i >= sizeof(devices) / sizeof(devices[0]))
				fatal_f("internal error: too many devices");
			nếu ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				continue;
			nếu (strlen(devices[i]->name) == len &&
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
	} trong_khi (kbdintctxt->devices && !kbdintctxt->device);

	trả_về kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
số_nguyên
auth2_challenge(struct ssh *ssh, char *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	nếu (authctxt->user == NULL || !devs)
		trả_về 0;
	nếu (authctxt->kbdintctxt == NULL)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	trả_về auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
void
auth2_challenge_stop(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	nếu (authctxt->kbdintctxt != NULL) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = NULL;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
static số_nguyên
auth2_challenge_start(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	nếu (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		trả_về 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	nếu ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == NULL) {
		auth2_challenge_stop(ssh);
		trả_về 0;
	}
	nếu (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		trả_về 0;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response);

	authctxt->postponed = 1;
	trả_về 0;
}

static số_nguyên
send_userauth_info_request(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	char *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	nếu (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		trả_về 0;

	nếu ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	cho (i = 0; i < kbdintctxt->nreq; i++) {
		nếu ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	nếu ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	cho (i = 0; i < kbdintctxt->nreq; i++)
		free(prompts[i]);
	free(prompts);
	free(echo_on);
	free(name);
	free(instr);
	trả_về 1;
}

static số_nguyên
input_userauth_info_response(số_nguyên type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	số_nguyên authenticated = 0, res;
	số_nguyên r;
	u_int i, nresp;
	const char *devicename = NULL;
	char **response = NULL;
	double tstart = monotime_double();

	nếu (authctxt == NULL)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	nếu (kbdintctxt == NULL || kbdintctxt->ctxt == NULL)
		fatal_f("no kbdintctxt");
	nếu (kbdintctxt->device == NULL)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	nếu ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	nếu (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	nếu (nresp > 100)
		fatal_f("too many replies");
	nếu (nresp > 0) {
		response = xcalloc(nresp, sizeof(char *));
		cho (i = 0; i < nresp; i++) {
			nếu ((r = sshpkt_get_cstring(ssh, &response[i], NULL)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	nếu ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	cho (i = 0; i < nresp; i++) {
		explicit_bzero(response[i], strlen(response[i]));
		free(response[i]);
	}
	free(response);

	switch (res) {
	case 0:
		/* Success! */
		authenticated = authctxt->valid ? 1 : 0;
		break;
	case 1:
		/* Authentication needs further interaction */
		nếu (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		break;
	default:
		/* Failure! */
		break;
	}
	devicename = kbdintctxt->device->name;
	nếu (!authctxt->postponed) {
		nếu (authenticated) {
			auth2_challenge_stop(ssh);
		} không_thì {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	nếu (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	trả_về 0;
}
