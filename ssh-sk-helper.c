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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

ಸ್ಥಿರ ರಚನೆ sshbuf *ಉತ್ತರ_error(ಪೂರ್ಣಾಂಕ r, ಅಕ್ಷರ *fmt, ...)
    __attribute__((__format__ (ಬರೆ, 2, 3)));

ಸ್ಥಿರ ರಚನೆ sshbuf *
ಉತ್ತರ_error(ಪೂರ್ಣಾಂಕ r, ಅಕ್ಷರ *fmt, ...)
{
	ಅಕ್ಷರ *ಸಂದೇಶ;
	va_list ap;
	ರಚನೆ sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&ಸಂದೇಶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);

	ಆದರೆ (r >= 0)
		fatal_f("invalid error code %d", r);

	ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);
	ಆದರೆ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ಹಿಂತಿರುಗಿ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ಸ್ಥಿರ ಶೂನ್ಯ
null_ಖಾಲಿಗಳು(ಅಕ್ಷರ **s)
{
	ಆದರೆ (s == ಖಾಲಿ || *s == ಖಾಲಿ || **s != '\0')
		ಹಿಂತಿರುಗಿ;

	ಬಿಡುಗಡೆ(*s);
	*s = ಖಾಲಿ;
}

/* stubs */
ಪೂರ್ಣಾಂಕ
pkcs11_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ರಚನೆ sshkey *ಕೀಲಿ)
{
}

ಸ್ಥಿರ ರಚನೆ sshbuf *
process_sign(ರಚನೆ sshbuf *req)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *resp, *kbuf;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	uint32_t compat;
	ಸ್ಥಿರಾಂಕ u_char *ಸಂದೇಶ_2;
	u_char *sig = ಖಾಲಿ;
	ಗಾತ್ರ_t msglen, siglen = 0;
	ಅಕ್ಷರ *provider = ಖಾಲಿ, *pin = ಖಾಲಿ;

	ಆದರೆ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(req, &ಸಂದೇಶ_2, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ಖಾಲಿ, ಖಾಲಿ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ಖಾಲಿ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಆದರೆ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(kbuf, &ಕೀಲಿ)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ಆದರೆ (!sshkey_is_sk(ಕೀಲಿ)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(ಕೀಲಿ));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(ಕೀಲಿ),
	    provider, msglen, (u_long)compat);

	null_ಖಾಲಿಗಳು(&pin);

	ಆದರೆ ((r = sshsk_sign(provider, ಕೀಲಿ, &sig, &siglen,
	    ಸಂದೇಶ_2, msglen, compat, pin)) != 0) {
		resp = ಉತ್ತರ_error(r, "Signing failed: %s", ssh_err(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);

	ಆದರೆ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	ಬಿಡುಗಡೆ(provider);
	ಆದರೆ (sig != ಖಾಲಿ)
		freezero(sig, siglen);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
	ಹಿಂತಿರುಗಿ resp;
}

ಸ್ಥಿರ ರಚನೆ sshbuf *
process_enroll(ರಚನೆ sshbuf *req)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int type;
	ಅಕ್ಷರ *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ರಚನೆ sshbuf *challenge, *attest, *kbuf, *resp;
	ರಚನೆ sshkey *ಕೀಲಿ;

	ಆದರೆ ((attest = sshbuf_new()) == ಖಾಲಿ ||
	    (kbuf = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);

	ಆದರೆ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಆದರೆ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ಆದರೆ (type > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal("%s: bad type %u", __progname, type);
	ಆದರೆ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ಖಾಲಿ;
	}
	null_ಖಾಲಿಗಳು(&device);
	null_ಖಾಲಿಗಳು(&userid);
	null_ಖಾಲಿಗಳು(&pin);

	ಆದರೆ ((r = sshsk_enroll((ಪೂರ್ಣಾಂಕ)type, provider, device, application, userid,
	    flags, pin, challenge, &ಕೀಲಿ, attest)) != 0) {
		resp = ಉತ್ತರ_error(r, "Enrollment failed: %s", ssh_err(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(ಕೀಲಿ, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ಆದರೆ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	ಬಿಡುಗಡೆ(provider);
	ಬಿಡುಗಡೆ(application);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));

	ಹಿಂತಿರುಗಿ resp;
}

ಸ್ಥಿರ ರಚನೆ sshbuf *
process_ತುಂಬು_resident(ರಚನೆ sshbuf *req)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *provider, *pin, *device;
	ರಚನೆ sshbuf *kbuf, *resp;
	ರಚನೆ sshsk_resident_ಕೀಲಿ **srks = ಖಾಲಿ;
	ಗಾತ್ರ_t nsrks = 0, i;
	u_int flags;

	ಆದರೆ ((kbuf = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);

	ಆದರೆ ((r = sshbuf_get_cstring(req, &provider, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ಆದರೆ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_ಖಾಲಿಗಳು(&device);
	null_ಖಾಲಿಗಳು(&pin);

	ಆದರೆ ((r = sshsk_ತುಂಬು_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = ಉತ್ತರ_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((resp = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);

	ಆದರೆ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ತುಂಬು_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	ಗಾಗಿ (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->ಕೀಲಿ), srks[i]->ಕೀಲಿ->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(srks[i]->ಕೀಲಿ, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ಆದರೆ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 ಹೊರಹೋಗು:
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	sshbuf_free(kbuf);
	ಬಿಡುಗಡೆ(provider);
	ಬಿಡುಗಡೆ(device);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
	ಹಿಂತಿರುಗಿ resp;
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ರಚನೆ sshbuf *req, *resp;
	ಪೂರ್ಣಾಂಕ ಒಳ, ಹೊರಹೋಗು, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t ಆವೃತ್ತಿ, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ಆಗ ((ch = getopt(argc, argv, "v")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'v':
			vflag = 1;
			ಆದರೆ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			ನಿರ್ಗಮಿಸು(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	ಆದರೆ ((ಒಳ = dup(STDIN_FILENO)) == -1 || (ಹೊರಹೋಗು = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ಆದರೆ ((req = sshbuf_new()) == ಖಾಲಿ)
		fatal("%s: sshbuf_new failed", __progname);
	ಆದರೆ (ssh_ಸಂದೇಶ_recv(ಒಳ, req) < 0)
		fatal("ssh_msg_recv failed");
	close(ಒಳ);
	debug_f("received message len %zu", sshbuf_len(req));

	ಆದರೆ ((r = sshbuf_get_u8(req, &ಆವೃತ್ತಿ)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ಆದರೆ (ಆವೃತ್ತಿ != SSH_SK_HELPER_ಆವೃತ್ತಿ) {
		fatal("unsupported version: received %d, expected %d",
		    ಆವೃತ್ತಿ, SSH_SK_HELPER_ಆವೃತ್ತಿ);
	}

	ಆದರೆ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ಆದರೆ (!vflag && log_level_name((LogLevel)ll) != ಖಾಲಿ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	ಆಯ್ಕೆ (rtype) {
	ಸ್ಥಿತಿ SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SK_HELPER_ತುಂಬು_RESIDENT:
		resp = process_ತುಂಬು_resident(req);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ಆದರೆ (ssh_ಸಂದೇಶ_send(ಹೊರಹೋಗು, SSH_SK_HELPER_ಆವೃತ್ತಿ, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(ಹೊರಹೋಗು);

	ಹಿಂತಿರುಗಿ (0);
}
#ಇಲ್ಲದಿದ್ದರೆ /* ENABLE_SK */

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_SK */
