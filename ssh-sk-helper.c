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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "ssh-pkcs11.h"

#यदि_परिभाषितम् ENABLE_SK
बाह्य वर्ण *__progname;

स्थिर संरचना sshbuf *प्रत्युत्तरम्_error(पूर्णाङ्क r, वर्ण *fmt, ...)
    __attribute__((__format__ (प्रारूप_लिख, 2, 3)));

स्थिर संरचना sshbuf *
प्रत्युत्तरम्_error(पूर्णाङ्क r, वर्ण *fmt, ...)
{
	वर्ण *सन्देशः;
	va_list ap;
	संरचना sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&सन्देशः, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, सन्देशः);
	मुक्त(सन्देशः);

	यदि (r >= 0)
		fatal_f("invalid error code %d", r);

	यदि ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	यदि (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	प्रत्यागम resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
स्थिर शून्य
null_रिक्तानि(वर्ण **s)
{
	यदि (s == रिक्त || *s == रिक्त || **s != '\0')
		प्रत्यागम;

	मुक्त(*s);
	*s = रिक्त;
}

/* stubs */
पूर्णाङ्क
pkcs11_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}

शून्य
pkcs11_कुञ्चिका_free(संरचना sshkey *कुञ्चिका)
{
}

स्थिर संरचना sshbuf *
process_sign(संरचना sshbuf *req)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *resp, *kbuf;
	संरचना sshkey *कुञ्चिका = रिक्त;
	uint32_t compat;
	ध्रुव u_char *सन्देशः_2;
	u_char *sig = रिक्त;
	आकार_t msglen, siglen = 0;
	वर्ण *provider = रिक्त, *pin = रिक्त;

	यदि ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(req, &सन्देशः_2, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, रिक्त, रिक्त)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0)
		fatal_r(r, "%s: parse", __progname);
	यदि (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	यदि ((r = sshkey_वैयक्तिकम्_deserialize(kbuf, &कुञ्चिका)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	यदि (!sshkey_is_sk(कुञ्चिका)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(कुञ्चिका));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(कुञ्चिका),
	    provider, msglen, (u_long)compat);

	null_रिक्तानि(&pin);

	यदि ((r = sshsk_sign(provider, कुञ्चिका, &sig, &siglen,
	    सन्देशः_2, msglen, compat, pin)) != 0) {
		resp = प्रत्युत्तरम्_error(r, "Signing failed: %s", ssh_err(r));
		गच्छ बहिर्गमनम्;
	}

	यदि ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	यदि ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	sshbuf_free(kbuf);
	मुक्त(provider);
	यदि (sig != रिक्त)
		freezero(sig, siglen);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));
	प्रत्यागम resp;
}

स्थिर संरचना sshbuf *
process_enroll(संरचना sshbuf *req)
{
	पूर्णाङ्क r;
	u_int type;
	वर्ण *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	संरचना sshbuf *challenge, *attest, *kbuf, *resp;
	संरचना sshkey *कुञ्चिका;

	यदि ((attest = sshbuf_new()) == रिक्त ||
	    (kbuf = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	यदि ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	यदि (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	यदि (type > अधिकतम_पूर्णाङ्कः)
		fatal("%s: bad type %u", __progname, type);
	यदि (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = रिक्त;
	}
	null_रिक्तानि(&device);
	null_रिक्तानि(&userid);
	null_रिक्तानि(&pin);

	यदि ((r = sshsk_enroll((पूर्णाङ्क)type, provider, device, application, userid,
	    flags, pin, challenge, &कुञ्चिका, attest)) != 0) {
		resp = प्रत्युत्तरम्_error(r, "Enrollment failed: %s", ssh_err(r));
		गच्छ बहिर्गमनम्;
	}

	यदि ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	यदि ((r = sshkey_वैयक्तिकम्_serialize(कुञ्चिका, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	यदि ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	मुक्त(provider);
	मुक्त(application);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));

	प्रत्यागम resp;
}

स्थिर संरचना sshbuf *
process_आरोपय_resident(संरचना sshbuf *req)
{
	पूर्णाङ्क r;
	वर्ण *provider, *pin, *device;
	संरचना sshbuf *kbuf, *resp;
	संरचना sshsk_resident_कुञ्चिका **srks = रिक्त;
	आकार_t nsrks = 0, i;
	u_int flags;

	यदि ((kbuf = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	यदि ((r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	यदि (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_रिक्तानि(&device);
	null_रिक्तानि(&pin);

	यदि ((r = sshsk_आरोपय_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = प्रत्युत्तरम्_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		गच्छ बहिर्गमनम्;
	}

	यदि ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	यदि ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_आरोपय_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	प्रति (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->कुञ्चिका), srks[i]->कुञ्चिका->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		यदि ((r = sshkey_वैयक्तिकम्_serialize(srks[i]->कुञ्चिका, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		यदि ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 बहिर्गमनम्:
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	sshbuf_free(kbuf);
	मुक्त(provider);
	मुक्त(device);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));
	प्रत्यागम resp;
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	संरचना sshbuf *req, *resp;
	पूर्णाङ्क अन्तर्, बहिर्गमनम्, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t संस्करणम्, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	यावत् ((ch = getopt(argc, argv, "v")) != -1) {
		विकल्प (ch) {
		पक्ष 'v':
			vflag = 1;
			यदि (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			भङ्ग;
		स्वभाव:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			निर्गच्छ(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	यदि ((अन्तर् = dup(STDIN_FILENO)) == -1 || (बहिर्गमनम् = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	यदि ((req = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	यदि (ssh_सन्देशः_recv(अन्तर्, req) < 0)
		fatal("ssh_msg_recv failed");
	close(अन्तर्);
	debug_f("received message len %zu", sshbuf_len(req));

	यदि ((r = sshbuf_get_u8(req, &संस्करणम्)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	यदि (संस्करणम् != SSH_SK_HELPER_संस्करणम्) {
		fatal("unsupported version: received %d, expected %d",
		    संस्करणम्, SSH_SK_HELPER_संस्करणम्);
	}

	यदि ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	यदि (!vflag && log_level_name((LogLevel)ll) != रिक्त)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	विकल्प (rtype) {
	पक्ष SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		भङ्ग;
	पक्ष SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		भङ्ग;
	पक्ष SSH_SK_HELPER_आरोपय_RESIDENT:
		resp = process_आरोपय_resident(req);
		भङ्ग;
	स्वभाव:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	यदि (ssh_सन्देशः_send(बहिर्गमनम्, SSH_SK_HELPER_संस्करणम्, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(बहिर्गमनम्);

	प्रत्यागम (0);
}
#अन्यथा /* ENABLE_SK */

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	प्रत्यागम -1;
}
#यदि_अन्तः /* ENABLE_SK */
