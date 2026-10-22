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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
ਬਾਹਰੀ ਅੱਖਰ *__progname;

ਸਥਿਰ ਬਣਤਰ sshbuf *ਜਵਾਬ_error(ਪੂਰਨ r, ਅੱਖਰ *fmt, ...)
    __attribute__((__format__ (ਲਿਖੋ, 2, 3)));

ਸਥਿਰ ਬਣਤਰ sshbuf *
ਜਵਾਬ_error(ਪੂਰਨ r, ਅੱਖਰ *fmt, ...)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	va_list ap;
	ਬਣਤਰ sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&ਸੁਨੇਹਾ, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, ਸੁਨੇਹਾ);
	ਮੁਕਤ(ਸੁਨੇਹਾ);

	ਜੇ (r >= 0)
		fatal_f("invalid error code %d", r);

	ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);
	ਜੇ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ਵਾਪਸ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ਸਥਿਰ ਖਾਲੀ
null_ਖਾਲੀ_ਥਾਵਾਂ(ਅੱਖਰ **s)
{
	ਜੇ (s == ਨਿਰਾ || *s == ਨਿਰਾ || **s != '\0')
		ਵਾਪਸ;

	ਮੁਕਤ(*s);
	*s = ਨਿਰਾ;
}

/* stubs */
ਪੂਰਨ
pkcs11_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}

ਖਾਲੀ
pkcs11_ਕੁੰਜੀ_free(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
}

ਸਥਿਰ ਬਣਤਰ sshbuf *
process_sign(ਬਣਤਰ sshbuf *req)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *resp, *kbuf;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	uint32_t compat;
	ਅਚਲ u_char *ਸੁਨੇਹਾ_2;
	u_char *sig = ਨਿਰਾ;
	ਮਾਪ_t msglen, siglen = 0;
	ਅੱਖਰ *provider = ਨਿਰਾ, *pin = ਨਿਰਾ;

	ਜੇ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(req, &ਸੁਨੇਹਾ_2, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ਨਿਰਾ, ਨਿਰਾ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ਨਿਰਾ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ਜੇ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(kbuf, &ਕੁੰਜੀ)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ਜੇ (!sshkey_is_sk(ਕੁੰਜੀ)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(ਕੁੰਜੀ));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(ਕੁੰਜੀ),
	    provider, msglen, (u_long)compat);

	null_ਖਾਲੀ_ਥਾਵਾਂ(&pin);

	ਜੇ ((r = sshsk_sign(provider, ਕੁੰਜੀ, &sig, &siglen,
	    ਸੁਨੇਹਾ_2, msglen, compat, pin)) != 0) {
		resp = ਜਵਾਬ_error(r, "Signing failed: %s", ssh_err(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);

	ਜੇ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(kbuf);
	ਮੁਕਤ(provider);
	ਜੇ (sig != ਨਿਰਾ)
		freezero(sig, siglen);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
	ਵਾਪਸ resp;
}

ਸਥਿਰ ਬਣਤਰ sshbuf *
process_enroll(ਬਣਤਰ sshbuf *req)
{
	ਪੂਰਨ r;
	u_int type;
	ਅੱਖਰ *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ਬਣਤਰ sshbuf *challenge, *attest, *kbuf, *resp;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;

	ਜੇ ((attest = sshbuf_new()) == ਨਿਰਾ ||
	    (kbuf = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);

	ਜੇ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ਜੇ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ਜੇ (type > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal("%s: bad type %u", __progname, type);
	ਜੇ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ਨਿਰਾ;
	}
	null_ਖਾਲੀ_ਥਾਵਾਂ(&device);
	null_ਖਾਲੀ_ਥਾਵਾਂ(&userid);
	null_ਖਾਲੀ_ਥਾਵਾਂ(&pin);

	ਜੇ ((r = sshsk_enroll((ਪੂਰਨ)type, provider, device, application, userid,
	    flags, pin, challenge, &ਕੁੰਜੀ, attest)) != 0) {
		resp = ਜਵਾਬ_error(r, "Enrollment failed: %s", ssh_err(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(ਕੁੰਜੀ, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ਜੇ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	ਮੁਕਤ(provider);
	ਮੁਕਤ(application);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));

	ਵਾਪਸ resp;
}

ਸਥਿਰ ਬਣਤਰ sshbuf *
process_ਲੱਦੋ_resident(ਬਣਤਰ sshbuf *req)
{
	ਪੂਰਨ r;
	ਅੱਖਰ *provider, *pin, *device;
	ਬਣਤਰ sshbuf *kbuf, *resp;
	ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks = ਨਿਰਾ;
	ਮਾਪ_t nsrks = 0, i;
	u_int flags;

	ਜੇ ((kbuf = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);

	ਜੇ ((r = sshbuf_get_cstring(req, &provider, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ਜੇ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_ਖਾਲੀ_ਥਾਵਾਂ(&device);
	null_ਖਾਲੀ_ਥਾਵਾਂ(&pin);

	ਜੇ ((r = sshsk_ਲੱਦੋ_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = ਜਵਾਬ_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((resp = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);

	ਜੇ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ਲੱਦੋ_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	ਲਈ (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->ਕੁੰਜੀ), srks[i]->ਕੁੰਜੀ->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(srks[i]->ਕੁੰਜੀ, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ਜੇ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 ਬਾਹਰਲਾ:
	sshsk_free_resident_ਕੁੰਜੀਆਂ(srks, nsrks);
	sshbuf_free(kbuf);
	ਮੁਕਤ(provider);
	ਮੁਕਤ(device);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
	ਵਾਪਸ resp;
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ਬਣਤਰ sshbuf *req, *resp;
	ਪੂਰਨ ਵਿੱਚ, ਬਾਹਰਲਾ, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t ਸੰਸਕਰਣ, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ਜਦੋਂ ((ch = getopt(argc, argv, "v")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'v':
			vflag = 1;
			ਜੇ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ਰੋਕੋ;
		ਮੂਲ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	ਜੇ ((ਵਿੱਚ = dup(STDIN_FILENO)) == -1 || (ਬਾਹਰਲਾ = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ਜੇ ((req = sshbuf_new()) == ਨਿਰਾ)
		fatal("%s: sshbuf_new failed", __progname);
	ਜੇ (ssh_ਸੁਨੇਹਾ_recv(ਵਿੱਚ, req) < 0)
		fatal("ssh_msg_recv failed");
	close(ਵਿੱਚ);
	debug_f("received message len %zu", sshbuf_len(req));

	ਜੇ ((r = sshbuf_get_u8(req, &ਸੰਸਕਰਣ)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ਜੇ (ਸੰਸਕਰਣ != SSH_SK_HELPER_ਸੰਸਕਰਣ) {
		fatal("unsupported version: received %d, expected %d",
		    ਸੰਸਕਰਣ, SSH_SK_HELPER_ਸੰਸਕਰਣ);
	}

	ਜੇ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ਜੇ (!vflag && log_level_name((LogLevel)ll) != ਨਿਰਾ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	ਚੋਣ (rtype) {
	ਹਾਲਤ SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SK_HELPER_ਲੱਦੋ_RESIDENT:
		resp = process_ਲੱਦੋ_resident(req);
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ਜੇ (ssh_ਸੁਨੇਹਾ_send(ਬਾਹਰਲਾ, SSH_SK_HELPER_ਸੰਸਕਰਣ, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(ਬਾਹਰਲਾ);

	ਵਾਪਸ (0);
}
#ਨਹੀਂਤਾਂ /* ENABLE_SK */

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ /* ENABLE_SK */
