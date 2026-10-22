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

static цео auth2_challenge_start(struct ssh *);
static цео send_userauth_info_request(struct ssh *);
static цео input_userauth_info_response(цео, uint32_t, struct ssh *);

#ifdef BSD_AUTH
extern KbdintDevice mm_bsdauth_device;
#инако
#ifdef USE_PAM
extern KbdintDevice mm_sshpam_device;
#endif
#endif

KbdintDevice *devices[] = {
#ifdef BSD_AUTH
	&mm_bsdauth_device,
#инако
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
	цео i, j;

	за (i = 0; devices[i] != NULL; i++)
		ако (strcmp(devices[i]->name, devname) == 0) {
			за (j = i; devices[j] != NULL; j++)
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
	цео i, r;

#ifdef USE_PAM
	ако (!options.use_pam)
		remove_kbdint_device("pam");
#endif

	kbdintctxt = xcalloc(1, sizeof(KbdintAuthctxt));
	ако (strcmp(devs, "") == 0) {
		ако ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		за (i = 0; devices[i]; i++) {
			ако ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", devices[i]->name)) != 0)
				fatal_fr(r, "buffer error");
		}
		ако ((kbdintctxt->devices = sshbuf_dup_string(b)) == NULL)
			fatal_f("sshbuf_dup_string failed");
		sshbuf_free(b);
	} инако {
		kbdintctxt->devices = xstrdup(devs);
	}
	debug("kbdint_alloc: devices '%s'", kbdintctxt->devices);
	kbdintctxt->ctxt = NULL;
	kbdintctxt->device = NULL;
	kbdintctxt->nreq = 0;

	врати kbdintctxt;
}
static void
kbdint_reset_device(KbdintAuthctxt *kbdintctxt)
{
	ако (kbdintctxt->ctxt) {
		kbdintctxt->device->free_ctx(kbdintctxt->ctxt);
		kbdintctxt->ctxt = NULL;
	}
	kbdintctxt->device = NULL;
}
static void
kbdint_free(KbdintAuthctxt *kbdintctxt)
{
	ако (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	free(kbdintctxt->devices);
	freezero(kbdintctxt, sizeof(*kbdintctxt));
}
/* get next device */
static цео
kbdint_next_device(Authctxt *authctxt, KbdintAuthctxt *kbdintctxt)
{
	size_t len;
	char *t;
	size_t i;

	ако (kbdintctxt->device)
		kbdint_reset_device(kbdintctxt);
	do {
		len = kbdintctxt->devices ?
		    strcspn(kbdintctxt->devices, ",") : 0;

		ако (len == 0)
			break;
		за (i = 0; devices[i]; i++) {
			ако (i >= sizeof(kbdintctxt->devices_done) * 8 ||
			    i >= sizeof(devices) / sizeof(devices[0]))
				fatal_f("internal error: too many devices");
			ако ((kbdintctxt->devices_done & (1 << i)) != 0 ||
			    !auth2_method_allowed(authctxt,
			    "keyboard-interactive", devices[i]->name))
				continue;
			ако (strlen(devices[i]->name) == len &&
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
	} док (kbdintctxt->devices && !kbdintctxt->device);

	врати kbdintctxt->device ? 1 : 0;
}

/*
 * try challenge-response, set authctxt->postponed if we have to
 * wait for the response.
 */
цео
auth2_challenge(struct ssh *ssh, char *devs)
{
	Authctxt *authctxt = ssh->authctxt;
	debug("auth2_challenge: user=%s devs=%s",
	    authctxt->user ? authctxt->user : "<nouser>",
	    devs ? devs : "<no devs>");

	ако (authctxt->user == NULL || !devs)
		врати 0;
	ако (authctxt->kbdintctxt == NULL)
		authctxt->kbdintctxt = kbdint_alloc(devs);
	врати auth2_challenge_start(ssh);
}

/* unregister kbd-int callbacks and context */
void
auth2_challenge_stop(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	/* unregister callback */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
	ако (authctxt->kbdintctxt != NULL) {
		kbdint_free(authctxt->kbdintctxt);
		authctxt->kbdintctxt = NULL;
	}
}

/* side effect: sets authctxt->postponed if a reply was sent*/
static цео
auth2_challenge_start(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt = authctxt->kbdintctxt;

	debug2("auth2_challenge_start: devices %s",
	    kbdintctxt->devices ?  kbdintctxt->devices : "<empty>");

	ако (kbdint_next_device(authctxt, kbdintctxt) == 0) {
		auth2_challenge_stop(ssh);
		врати 0;
	}
	debug("auth2_challenge_start: trying authentication method '%s'",
	    kbdintctxt->device->name);

	ако ((kbdintctxt->ctxt = kbdintctxt->device->init_ctx(authctxt)) == NULL) {
		auth2_challenge_stop(ssh);
		врати 0;
	}
	ако (send_userauth_info_request(ssh) == 0) {
		auth2_challenge_stop(ssh);
		врати 0;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response);

	authctxt->postponed = 1;
	врати 0;
}

static цео
send_userauth_info_request(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	char *name, *instr, **prompts;
	u_int r, i, *echo_on;

	kbdintctxt = authctxt->kbdintctxt;
	ако (kbdintctxt->device->query(kbdintctxt->ctxt,
	    &name, &instr, &kbdintctxt->nreq, &prompts, &echo_on))
		врати 0;

	ако ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, instr)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language not used */
	    (r = sshpkt_put_u32(ssh, kbdintctxt->nreq)) != 0)
		fatal_fr(r, "start packet");
	за (i = 0; i < kbdintctxt->nreq; i++) {
		ако ((r = sshpkt_put_cstring(ssh, prompts[i])) != 0 ||
		    (r = sshpkt_put_u8(ssh, echo_on[i])) != 0)
			fatal_fr(r, "assemble packet");
	}
	ако ((r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");

	за (i = 0; i < kbdintctxt->nreq; i++)
		free(prompts[i]);
	free(prompts);
	free(echo_on);
	free(name);
	free(instr);
	врати 1;
}

static цео
input_userauth_info_response(цео type, uint32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	KbdintAuthctxt *kbdintctxt;
	цео authenticated = 0, res;
	цео r;
	u_int i, nresp;
	const char *devicename = NULL;
	char **response = NULL;
	double tstart = monotime_double();

	ако (authctxt == NULL)
		fatal_f("no authctxt");
	kbdintctxt = authctxt->kbdintctxt;
	ако (kbdintctxt == NULL || kbdintctxt->ctxt == NULL)
		fatal_f("no kbdintctxt");
	ако (kbdintctxt->device == NULL)
		fatal_f("no device");

	authctxt->postponed = 0;	/* reset */
	ако ((r = sshpkt_get_u32(ssh, &nresp)) != 0)
		fatal_fr(r, "parse packet");
	ако (nresp != kbdintctxt->nreq)
		fatal_f("wrong number of replies");
	ако (nresp > 100)
		fatal_f("too many replies");
	ако (nresp > 0) {
		response = xcalloc(nresp, sizeof(char *));
		за (i = 0; i < nresp; i++) {
			ако ((r = sshpkt_get_cstring(ssh, &response[i], NULL)) != 0)
				fatal_fr(r, "parse response");
		}
	}
	ако ((r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	res = kbdintctxt->device->respond(kbdintctxt->ctxt, nresp, response);

	за (i = 0; i < nresp; i++) {
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
		ако (send_userauth_info_request(ssh) == 1)
			authctxt->postponed = 1;
		break;
	default:
		/* Failure! */
		break;
	}
	devicename = kbdintctxt->device->name;
	ако (!authctxt->postponed) {
		ако (authenticated) {
			auth2_challenge_stop(ssh);
		} инако {
			/* start next device */
			/* may set authctxt->postponed */
			auth2_challenge_start(ssh);
		}
	}

	ако (!authenticated)
		auth_failure_delay(authctxt, tstart);
	userauth_finish(ssh, authenticated, "keyboard-interactive",
	    devicename);
	врати 0;
}
