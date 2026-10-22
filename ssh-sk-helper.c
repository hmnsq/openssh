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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"

#ifdef ENABLE_SK
ಬಾಹ್ಯ ವರ್ಣ *__progname;

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *reply_error(ಪೂರ್ಣಾಙ್ಕ r, ವರ್ಣ *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
reply_error(ಪೂರ್ಣಾಙ್ಕ r, ವರ್ಣ *fmt, ...)
{
	ವರ್ಣ *ಸಂದೇಶ;
	va_list ap;
	ಸಂರಚನಾ sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&ಸಂದೇಶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, ಸಂದೇಶ);
	ಮುಕ್ತ(ಸಂದೇಶ);

	ಯದಿ (r >= 0)
		fatal_f("invalid error code %d", r);

	ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);
	ಯದಿ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ಪ್ರತ್ಯಾಗಮ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ಸ್ಥಿರ ಶೂನ್ಯ
null_empty(ವರ್ಣ **s)
{
	ಯದಿ (s == ರಿಕ್ತ || *s == ರಿಕ್ತ || **s != '\0')
		ಪ್ರತ್ಯಾಗಮ;

	ಮುಕ್ತ(*s);
	*s = ರಿಕ್ತ;
}

/* stubs */
ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
}

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
process_sign(ಸಂರಚನಾ sshbuf *req)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *resp, *kbuf;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	uint32_t compat;
	ಧ್ರುವ u_char *message;
	u_char *sig = ರಿಕ್ತ;
	size_t msglen, siglen = 0;
	ವರ್ಣ *provider = ರಿಕ್ತ, *pin = ರಿಕ್ತ;

	ಯದಿ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ರಿಕ್ತ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಯದಿ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ಯದಿ ((r = sshkey_private_deserialize(kbuf, &ಕೀಲಿ)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ಯದಿ (!sshkey_is_sk(ಕೀಲಿ)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(ಕೀಲಿ));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(ಕೀಲಿ),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	ಯದಿ ((r = sshsk_sign(provider, ಕೀಲಿ, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		ಗಚ್ಛ out;
	}

	ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);

	ಯದಿ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	ಮುಕ್ತ(provider);
	ಯದಿ (sig != ರಿಕ್ತ)
		freezero(sig, siglen);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
	ಪ್ರತ್ಯಾಗಮ resp;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
process_enroll(ಸಂರಚನಾ sshbuf *req)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int type;
	ವರ್ಣ *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ಸಂರಚನಾ sshbuf *challenge, *attest, *kbuf, *resp;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;

	ಯದಿ ((attest = sshbuf_new()) == ರಿಕ್ತ ||
	    (kbuf = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);

	ಯದಿ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಯದಿ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ಯದಿ (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	ಯದಿ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ರಿಕ್ತ;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	ಯದಿ ((r = sshsk_enroll((ಪೂರ್ಣಾಙ್ಕ)type, provider, device, application, userid,
	    flags, pin, challenge, &ಕೀಲಿ, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		ಗಚ್ಛ out;
	}

	ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);
	ಯದಿ ((r = sshkey_private_serialize(ಕೀಲಿ, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ಯದಿ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	ಮುಕ್ತ(provider);
	ಮುಕ್ತ(application);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));

	ಪ್ರತ್ಯಾಗಮ resp;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
process_load_resident(ಸಂರಚನಾ sshbuf *req)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *provider, *pin, *device;
	ಸಂರಚನಾ sshbuf *kbuf, *resp;
	ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ **srks = ರಿಕ್ತ;
	size_t nsrks = 0, i;
	u_int flags;

	ಯದಿ ((kbuf = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);

	ಯದಿ ((r = sshbuf_get_cstring(req, &provider, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಯದಿ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	ಯದಿ ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		ಗಚ್ಛ out;
	}

	ಯದಿ ((resp = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);

	ಯದಿ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	ಪ್ರತಿ (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->ಕೀಲಿ), srks[i]->ಕೀಲಿ->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ಯದಿ ((r = sshkey_private_serialize(srks[i]->ಕೀಲಿ, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ಯದಿ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	sshbuf_free(kbuf);
	ಮುಕ್ತ(provider);
	ಮುಕ್ತ(device);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
	ಪ್ರತ್ಯಾಗಮ resp;
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ಸಂರಚನಾ sshbuf *req, *resp;
	ಪೂರ್ಣಾಙ್ಕ in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ಯಾವತ್ ((ch = getopt(argc, argv, "v")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'v':
			vflag = 1;
			ಯದಿ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
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
	ಯದಿ ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ಯದಿ ((req = sshbuf_new()) == ರಿಕ್ತ)
		fatal("%s: sshbuf_new failed", __progname);
	ಯದಿ (ssh_ಸಂದೇಶ_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	ಯದಿ ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ಯದಿ (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	ಯದಿ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ಯದಿ (!vflag && log_level_name((LogLevel)ll) != ರಿಕ್ತ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	ವಿಕಲ್ಪ (rtype) {
	ಪಕ್ಷ SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ಯದಿ (ssh_ಸಂದೇಶ_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	ಪ್ರತ್ಯಾಗಮ (0);
}
#ಅನ್ಯಥಾ /* ENABLE_SK */

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif /* ENABLE_SK */
