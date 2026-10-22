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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"

#ifdef ENABLE_SK
ବାହ୍ୟ ଅକ୍ଷର *__progname;

ସ୍ଥିର ସଂରଚନା sshbuf *reply_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅକ୍ଷର *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ସ୍ଥିର ସଂରଚନା sshbuf *
reply_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅକ୍ଷର *fmt, ...)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	va_list ap;
	ସଂରଚନା sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&ସନ୍ଦେଶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, ସନ୍ଦେଶ);
	ମୁକ୍ତ(ସନ୍ଦେଶ);

	ଯଦି (r >= 0)
		fatal_f("invalid error code %d", r);

	ଯଦି ((resp = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);
	ଯଦି (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	ଫେରନ୍ତୁ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ସ୍ଥିର ଶୂନ୍ୟ
null_empty(ଅକ୍ଷର **s)
{
	ଯଦି (s == ଖାଲି || *s == ଖାଲି || **s != '\0')
		ଫେରନ୍ତୁ;

	ମୁକ୍ତ(*s);
	*s = ଖାଲି;
}

/* stubs */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}

ଶୂନ୍ୟ
pkcs11_ଚାବି_free(ସଂରଚନା sshkey *ଚାବି)
{
}

ସ୍ଥିର ସଂରଚନା sshbuf *
process_sign(ସଂରଚନା sshbuf *req)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *resp, *kbuf;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	uint32_t compat;
	ଅଚଳ u_char *message;
	u_char *sig = ଖାଲି;
	size_t msglen, siglen = 0;
	ଅକ୍ଷର *provider = ଖାଲି, *pin = ଖାଲି;

	ଯଦି ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ଖାଲି, ଖାଲି)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ଖାଲି)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ଯଦି (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ଯଦି ((r = sshkey_private_deserialize(kbuf, &ଚାବି)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ଯଦି (!sshkey_is_sk(ଚାବି)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(ଚାବି));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(ଚାବି),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	ଯଦି ((r = sshsk_sign(provider, ଚାବି, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		ଯାଅ out;
	}

	ଯଦି ((resp = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);

	ଯଦି ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(ଚାବି);
	sshbuf_free(kbuf);
	ମୁକ୍ତ(provider);
	ଯଦି (sig != ଖାଲି)
		freezero(sig, siglen);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
	ଫେରନ୍ତୁ resp;
}

ସ୍ଥିର ସଂରଚନା sshbuf *
process_enroll(ସଂରଚନା sshbuf *req)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int type;
	ଅକ୍ଷର *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ସଂରଚନା sshbuf *challenge, *attest, *kbuf, *resp;
	ସଂରଚନା sshkey *ଚାବି;

	ଯଦି ((attest = sshbuf_new()) == ଖାଲି ||
	    (kbuf = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);

	ଯଦି ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ଖାଲି)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ଯଦି (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ଯଦି (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	ଯଦି (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ଖାଲି;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	ଯଦି ((r = sshsk_enroll((ପୂର୍ଣ୍ଣସଂଖ୍ୟା)type, provider, device, application, userid,
	    flags, pin, challenge, &ଚାବି, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		ଯାଅ out;
	}

	ଯଦି ((resp = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);
	ଯଦି ((r = sshkey_private_serialize(ଚାବି, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ଯଦି ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(ଚାବି);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	ମୁକ୍ତ(provider);
	ମୁକ୍ତ(application);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));

	ଫେରନ୍ତୁ resp;
}

ସ୍ଥିର ସଂରଚନା sshbuf *
process_load_resident(ସଂରଚନା sshbuf *req)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *provider, *pin, *device;
	ସଂରଚନା sshbuf *kbuf, *resp;
	ସଂରଚନା sshsk_resident_ଚାବି **srks = ଖାଲି;
	size_t nsrks = 0, i;
	u_int flags;

	ଯଦି ((kbuf = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);

	ଯଦି ((r = sshbuf_get_cstring(req, &provider, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ଯଦି (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	ଯଦି ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		ଯାଅ out;
	}

	ଯଦି ((resp = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);

	ଯଦି ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	ପାଇଁ (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->ଚାବି), srks[i]->ଚାବି->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ଯଦି ((r = sshkey_private_serialize(srks[i]->ଚାବି, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ଯଦି ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(srks, nsrks);
	sshbuf_free(kbuf);
	ମୁକ୍ତ(provider);
	ମୁକ୍ତ(device);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
	ଫେରନ୍ତୁ resp;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ସଂରଚନା sshbuf *req, *resp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "v")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'v':
			vflag = 1;
			ଯଦି (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
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
	ଯଦି ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ଯଦି ((req = sshbuf_new()) == ଖାଲି)
		fatal("%s: sshbuf_new failed", __progname);
	ଯଦି (ssh_ସନ୍ଦେଶ_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	ଯଦି ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ଯଦି (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	ଯଦି ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ଯଦି (!vflag && log_level_name((LogLevel)ll) != ଖାଲି)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	ବାଛ (rtype) {
	ସ୍ଥିତି SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ଯଦି (ssh_ସନ୍ଦେଶ_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	ଫେରନ୍ତୁ (0);
}
#ଅନ୍ୟଥା /* ENABLE_SK */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	ଫେରନ୍ତୁ -1;
}
#endif /* ENABLE_SK */
