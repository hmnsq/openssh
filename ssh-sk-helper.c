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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <errno.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "ssh-pkcs11.h"

#ifdef ENABLE_SK
বাহ্যিক অক্ষর *__progname;

স্থির কাঠামো sshbuf *reply_error(পূর্ণসংখ্যা r, অক্ষর *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

স্থির কাঠামো sshbuf *
reply_error(পূর্ণসংখ্যা r, অক্ষর *fmt, ...)
{
	অক্ষর *বার্তা;
	va_list ap;
	কাঠামো sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&বার্তা, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, বার্তা);
	মুক্ত(বার্তা);

	যদি (r >= 0)
		fatal_f("invalid error code %d", r);

	যদি ((resp = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);
	যদি (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ফেরত resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
স্থির শূন্য
null_empty(অক্ষর **s)
{
	যদি (s == ফাঁকা || *s == ফাঁকা || **s != '\0')
		ফেরত;

	মুক্ত(*s);
	*s = ফাঁকা;
}

/* stubs */
পূর্ণসংখ্যা
pkcs11_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	ফেরত SSH_ERR_INTERNAL_ERROR;
}

শূন্য
pkcs11_চাবি_free(কাঠামো sshkey *চাবি)
{
}

স্থির কাঠামো sshbuf *
process_sign(কাঠামো sshbuf *req)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *resp, *kbuf;
	কাঠামো sshkey *চাবি = ফাঁকা;
	uint32_t compat;
	ধ্রুবক u_char *message;
	u_char *sig = ফাঁকা;
	আকার_t msglen, siglen = 0;
	অক্ষর *provider = ফাঁকা, *pin = ফাঁকা;

	যদি ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ফাঁকা, ফাঁকা)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ফাঁকা)) != 0)
		fatal_r(r, "%s: parse", __progname);
	যদি (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	যদি ((r = sshkey_private_deserialize(kbuf, &চাবি)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	যদি (!sshkey_is_sk(চাবি)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(চাবি));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(চাবি),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	যদি ((r = sshsk_sign(provider, চাবি, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		যাও out;
	}

	যদি ((resp = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);

	যদি ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	মুক্ত(provider);
	যদি (sig != ফাঁকা)
		freezero(sig, siglen);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
	ফেরত resp;
}

স্থির কাঠামো sshbuf *
process_enroll(কাঠামো sshbuf *req)
{
	পূর্ণসংখ্যা r;
	u_int type;
	অক্ষর *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	কাঠামো sshbuf *challenge, *attest, *kbuf, *resp;
	কাঠামো sshkey *চাবি;

	যদি ((attest = sshbuf_new()) == ফাঁকা ||
	    (kbuf = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);

	যদি ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ফাঁকা)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	যদি (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	যদি (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	যদি (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ফাঁকা;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	যদি ((r = sshsk_enroll((পূর্ণসংখ্যা)type, provider, device, application, userid,
	    flags, pin, challenge, &চাবি, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		যাও out;
	}

	যদি ((resp = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);
	যদি ((r = sshkey_private_serialize(চাবি, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	যদি ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	মুক্ত(provider);
	মুক্ত(application);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));

	ফেরত resp;
}

স্থির কাঠামো sshbuf *
process_load_resident(কাঠামো sshbuf *req)
{
	পূর্ণসংখ্যা r;
	অক্ষর *provider, *pin, *device;
	কাঠামো sshbuf *kbuf, *resp;
	কাঠামো sshsk_resident_চাবি **srks = ফাঁকা;
	আকার_t nsrks = 0, i;
	u_int flags;

	যদি ((kbuf = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);

	যদি ((r = sshbuf_get_cstring(req, &provider, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	যদি (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	যদি ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		যাও out;
	}

	যদি ((resp = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);

	যদি ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	জন্য (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->চাবি), srks[i]->চাবি->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		যদি ((r = sshkey_private_serialize(srks[i]->চাবি, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		যদি ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	sshbuf_free(kbuf);
	মুক্ত(provider);
	মুক্ত(device);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
	ফেরত resp;
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	কাঠামো sshbuf *req, *resp;
	পূর্ণসংখ্যা in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	যখন ((ch = getopt(argc, argv, "v")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'v':
			vflag = 1;
			যদি (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			বিরতি;
		পূর্বনির্ধারিত:
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
	যদি ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	যদি ((req = sshbuf_new()) == ফাঁকা)
		fatal("%s: sshbuf_new failed", __progname);
	যদি (ssh_বার্তা_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	যদি ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	যদি (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	যদি ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	যদি (!vflag && log_level_name((LogLevel)ll) != ফাঁকা)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	নির্বাচন (rtype) {
	ক্ষেত্র SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		বিরতি;
	ক্ষেত্র SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		বিরতি;
	ক্ষেত্র SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		বিরতি;
	পূর্বনির্ধারিত:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	যদি (ssh_বার্তা_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	ফেরত (0);
}
#অন্যথা /* ENABLE_SK */

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ফেরত -1;
}
#endif /* ENABLE_SK */
