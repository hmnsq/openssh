/* $OpenBSD: ssh-sk-helper.c,v 1.15 2025/07/24 05:44:55 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This is a tiny program used to isolate the address space used for
 * security key middleware signing operations from ssh-agent. It is similar
 * to ssh-pkcs11-helper.c but considerably simpler as the operations for
 * security keys are stateless.
 *
 * Please crank SSH_SK_HELPER_VERSION in sshkey.h for any incompatible
 * protocol changes.
 */

#include "includes.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xmalloc.h"
#include "log.h"
#include "sshkey.h"
#include "authfd.h"
#include "misc.h"
#include "sshbuf.h"
#include "msg.h"
#include "uidswap.h"
#include "ssherr.h"
#include "ssh-sk.h"
#include "ssh-pkcs11.h"

#ifdef ENABLE_SK
extern var_na *__progname;

static sa_nracanaa sshbuf *reply_error(puur_naa_nka r, var_na *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static sa_nracanaa sshbuf *
reply_error(puur_naa_nka r, var_na *fmt, ...)
{
	var_na *msg;
	va_list ap;
	sa_nracanaa sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&msg, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, msg);
	free(msg);

	ᬬᬾᬦ᭄ (r >= 0)
		fatal_f("invalid error code %d", r);

	ᬬᬾᬦ᭄ ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	ᬬᬾᬦ᭄ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ᬯᬮᬶ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
static void
null_empty(var_na **s)
{
	ᬬᬾᬦ᭄ (s == NULL || *s == NULL || **s != '\0')
		ᬯᬮᬶ;

	free(*s);
	*s = NULL;
}

/* stubs */
puur_naa_nka
pkcs11_sign(sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider,
    const var_na *sk_pin, u_int compat)
{
	ᬯᬮᬶ SSH_ERR_INTERNAL_ERROR;
}

void
pkcs11_key_free(sa_nracanaa sshkey *key)
{
}

static sa_nracanaa sshbuf *
process_sign(sa_nracanaa sshbuf *req)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *resp, *kbuf;
	sa_nracanaa sshkey *key = NULL;
	uint32_t compat;
	const u_char *message;
	u_char *sig = NULL;
	size_t msglen, siglen = 0;
	var_na *provider = NULL, *pin = NULL;

	ᬬᬾᬦ᭄ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, NULL, NULL)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ᬬᬾᬦ᭄ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ᬬᬾᬦ᭄ ((r = sshkey_private_deserialize(kbuf, &key)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ᬬᬾᬦ᭄ (!sshkey_is_sk(key)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(key));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(key),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	ᬬᬾᬦ᭄ ((r = sshsk_sign(provider, key, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		goto out;
	}

	ᬬᬾᬦ᭄ ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);

	ᬬᬾᬦ᭄ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(key);
	sshbuf_free(kbuf);
	free(provider);
	ᬬᬾᬦ᭄ (sig != NULL)
		freezero(sig, siglen);
	ᬬᬾᬦ᭄ (pin != NULL)
		freezero(pin, strlen(pin));
	ᬯᬮᬶ resp;
}

static sa_nracanaa sshbuf *
process_enroll(sa_nracanaa sshbuf *req)
{
	puur_naa_nka r;
	u_int type;
	var_na *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	sa_nracanaa sshbuf *challenge, *attest, *kbuf, *resp;
	sa_nracanaa sshkey *key;

	ᬬᬾᬦ᭄ ((attest = sshbuf_new()) == NULL ||
	    (kbuf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);

	ᬬᬾᬦ᭄ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, NULL)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ᬬᬾᬦ᭄ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ᬬᬾᬦ᭄ (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	ᬬᬾᬦ᭄ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = NULL;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	ᬬᬾᬦ᭄ ((r = sshsk_enroll((puur_naa_nka)type, provider, device, application, userid,
	    flags, pin, challenge, &key, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		goto out;
	}

	ᬬᬾᬦ᭄ ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	ᬬᬾᬦ᭄ ((r = sshkey_private_serialize(key, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ᬬᬾᬦ᭄ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	free(provider);
	free(application);
	ᬬᬾᬦ᭄ (pin != NULL)
		freezero(pin, strlen(pin));

	ᬯᬮᬶ resp;
}

static sa_nracanaa sshbuf *
process_load_resident(sa_nracanaa sshbuf *req)
{
	puur_naa_nka r;
	var_na *provider, *pin, *device;
	sa_nracanaa sshbuf *kbuf, *resp;
	sa_nracanaa sshsk_resident_key **srks = NULL;
	size_t nsrks = 0, i;
	u_int flags;

	ᬬᬾᬦ᭄ ((kbuf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);

	ᬬᬾᬦ᭄ ((r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ᬬᬾᬦ᭄ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	ᬬᬾᬦ᭄ ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		goto out;
	}

	ᬬᬾᬦ᭄ ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);

	ᬬᬾᬦ᭄ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	for (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->key), srks[i]->key->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ᬬᬾᬦ᭄ ((r = sshkey_private_serialize(srks[i]->key, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ᬬᬾᬦ᭄ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_keys(srks, nsrks);
	sshbuf_free(kbuf);
	free(provider);
	free(device);
	ᬬᬾᬦ᭄ (pin != NULL)
		freezero(pin, strlen(pin));
	ᬯᬮᬶ resp;
}

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	sa_nracanaa sshbuf *req, *resp;
	puur_naa_nka in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ᬲᭂᬤᭂᬮ ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		pak_sa 'v':
			vflag = 1;
			ᬬᬾᬦ᭄ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ᬮᬶᬬ ᬬᬾᬦ᭄ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			bha_nga;
		default:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	ᬬᬾᬦ᭄ ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ᬬᬾᬦ᭄ ((req = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	ᬬᬾᬦ᭄ (ssh_msg_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	ᬬᬾᬦ᭄ ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ᬬᬾᬦ᭄ (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	ᬬᬾᬦ᭄ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ᬬᬾᬦ᭄ (!vflag && log_level_name((LogLevel)ll) != NULL)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	switch (rtype) {
	pak_sa SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		bha_nga;
	pak_sa SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		bha_nga;
	pak_sa SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		bha_nga;
	default:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ᬬᬾᬦ᭄ (ssh_msg_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	ᬯᬮᬶ (0);
}
#ᬮᬶᬬ /* ENABLE_SK */

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ᬯᬮᬶ -1;
}
#endif /* ENABLE_SK */
