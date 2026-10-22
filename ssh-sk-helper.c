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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <errno.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "ssh-pkcs11.h"

#ifdef ENABLE_SK
வெளி எழுத்து *__progname;

நிலையான கட்டமைப்பு sshbuf *reply_error(முழு r, எழுத்து *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

நிலையான கட்டமைப்பு sshbuf *
reply_error(முழு r, எழுத்து *fmt, ...)
{
	எழுத்து *செய்தி;
	va_list ap;
	கட்டமைப்பு sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&செய்தி, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, செய்தி);
	விடுவி(செய்தி);

	எனில் (r >= 0)
		fatal_f("invalid error code %d", r);

	எனில் ((resp = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);
	எனில் (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	திரும்பு resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
நிலையான வெறுமை
null_empty(எழுத்து **s)
{
	எனில் (s == வெற்று || *s == வெற்று || **s != '\0')
		திரும்பு;

	விடுவி(*s);
	*s = வெற்று;
}

/* stubs */
முழு
pkcs11_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	திரும்பு SSH_ERR_INTERNAL_ERROR;
}

வெறுமை
pkcs11_சாவி_free(கட்டமைப்பு sshkey *சாவி)
{
}

நிலையான கட்டமைப்பு sshbuf *
process_sign(கட்டமைப்பு sshbuf *req)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *resp, *kbuf;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	uint32_t compat;
	மாறிலி u_char *message;
	u_char *sig = வெற்று;
	size_t msglen, siglen = 0;
	எழுத்து *provider = வெற்று, *pin = வெற்று;

	எனில் ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, வெற்று, வெற்று)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, வெற்று)) != 0)
		fatal_r(r, "%s: parse", __progname);
	எனில் (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	எனில் ((r = sshkey_private_deserialize(kbuf, &சாவி)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	எனில் (!sshkey_is_sk(சாவி)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(சாவி));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(சாவி),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	எனில் ((r = sshsk_sign(provider, சாவி, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		செல் out;
	}

	எனில் ((resp = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);

	எனில் ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(சாவி);
	sshbuf_free(kbuf);
	விடுவி(provider);
	எனில் (sig != வெற்று)
		freezero(sig, siglen);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
	திரும்பு resp;
}

நிலையான கட்டமைப்பு sshbuf *
process_enroll(கட்டமைப்பு sshbuf *req)
{
	முழு r;
	u_int type;
	எழுத்து *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	கட்டமைப்பு sshbuf *challenge, *attest, *kbuf, *resp;
	கட்டமைப்பு sshkey *சாவி;

	எனில் ((attest = sshbuf_new()) == வெற்று ||
	    (kbuf = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);

	எனில் ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, வெற்று)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, வெற்று)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	எனில் (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	எனில் (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	எனில் (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = வெற்று;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	எனில் ((r = sshsk_enroll((முழு)type, provider, device, application, userid,
	    flags, pin, challenge, &சாவி, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		செல் out;
	}

	எனில் ((resp = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);
	எனில் ((r = sshkey_private_serialize(சாவி, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	எனில் ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(சாவி);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	விடுவி(provider);
	விடுவி(application);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));

	திரும்பு resp;
}

நிலையான கட்டமைப்பு sshbuf *
process_load_resident(கட்டமைப்பு sshbuf *req)
{
	முழு r;
	எழுத்து *provider, *pin, *device;
	கட்டமைப்பு sshbuf *kbuf, *resp;
	கட்டமைப்பு sshsk_resident_சாவி **srks = வெற்று;
	size_t nsrks = 0, i;
	u_int flags;

	எனில் ((kbuf = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);

	எனில் ((r = sshbuf_get_cstring(req, &provider, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	எனில் (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	எனில் ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		செல் out;
	}

	எனில் ((resp = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);

	எனில் ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	க்கு (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->சாவி), srks[i]->சாவி->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		எனில் ((r = sshkey_private_serialize(srks[i]->சாவி, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		எனில் ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_சாவிகள்(srks, nsrks);
	sshbuf_free(kbuf);
	விடுவி(provider);
	விடுவி(device);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
	திரும்பு resp;
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	கட்டமைப்பு sshbuf *req, *resp;
	முழு in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	போது ((ch = getopt(argc, argv, "v")) != -1) {
		தேர்வு (ch) {
		நிலை 'v':
			vflag = 1;
			எனில் (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			நிறுத்து;
		இயல்பு:
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
	எனில் ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	எனில் ((req = sshbuf_new()) == வெற்று)
		fatal("%s: sshbuf_new failed", __progname);
	எனில் (ssh_செய்தி_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	எனில் ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	எனில் (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	எனில் ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	எனில் (!vflag && log_level_name((LogLevel)ll) != வெற்று)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	தேர்வு (rtype) {
	நிலை SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		நிறுத்து;
	நிலை SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		நிறுத்து;
	நிலை SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		நிறுத்து;
	இயல்பு:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	எனில் (ssh_செய்தி_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	திரும்பு (0);
}
#இல்லையெனில் /* ENABLE_SK */

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	திரும்பு -1;
}
#endif /* ENABLE_SK */
