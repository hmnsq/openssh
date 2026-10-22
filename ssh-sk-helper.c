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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <errno.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "ssh-pkcs11.h"

#ifdef ENABLE_SK
બાહ્ય અક્ષર *__progname;

સ્થિર સંરચના sshbuf *reply_error(પૂર્ણાંક r, અક્ષર *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

સ્થિર સંરચના sshbuf *
reply_error(પૂર્ણાંક r, અક્ષર *fmt, ...)
{
	અક્ષર *સંદેશ;
	va_list ap;
	સંરચના sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&સંદેશ, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, સંદેશ);
	મુક્ત(સંદેશ);

	જો (r >= 0)
		fatal_f("invalid error code %d", r);

	જો ((resp = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);
	જો (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	પાછા resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
સ્થિર શૂન્ય
null_empty(અક્ષર **s)
{
	જો (s == ખાલી || *s == ખાલી || **s != '\0')
		પાછા;

	મુક્ત(*s);
	*s = ખાલી;
}

/* stubs */
પૂર્ણાંક
pkcs11_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	પાછા SSH_ERR_INTERNAL_ERROR;
}

શૂન્ય
pkcs11_ચાવી_free(સંરચના sshkey *ચાવી)
{
}

સ્થિર સંરચના sshbuf *
process_sign(સંરચના sshbuf *req)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *resp, *kbuf;
	સંરચના sshkey *ચાવી = ખાલી;
	uint32_t compat;
	અચલ u_char *message;
	u_char *sig = ખાલી;
	size_t msglen, siglen = 0;
	અક્ષર *provider = ખાલી, *pin = ખાલી;

	જો ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ખાલી, ખાલી)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ખાલી)) != 0)
		fatal_r(r, "%s: parse", __progname);
	જો (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	જો ((r = sshkey_private_deserialize(kbuf, &ચાવી)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	જો (!sshkey_is_sk(ચાવી)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(ચાવી));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(ચાવી),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	જો ((r = sshsk_sign(provider, ચાવી, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		જાઓ out;
	}

	જો ((resp = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);

	જો ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(ચાવી);
	sshbuf_free(kbuf);
	મુક્ત(provider);
	જો (sig != ખાલી)
		freezero(sig, siglen);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
	પાછા resp;
}

સ્થિર સંરચના sshbuf *
process_enroll(સંરચના sshbuf *req)
{
	પૂર્ણાંક r;
	u_int type;
	અક્ષર *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	સંરચના sshbuf *challenge, *attest, *kbuf, *resp;
	સંરચના sshkey *ચાવી;

	જો ((attest = sshbuf_new()) == ખાલી ||
	    (kbuf = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);

	જો ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ખાલી)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ખાલી)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	જો (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	જો (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	જો (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ખાલી;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	જો ((r = sshsk_enroll((પૂર્ણાંક)type, provider, device, application, userid,
	    flags, pin, challenge, &ચાવી, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		જાઓ out;
	}

	જો ((resp = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);
	જો ((r = sshkey_private_serialize(ચાવી, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	જો ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(ચાવી);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	મુક્ત(provider);
	મુક્ત(application);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));

	પાછા resp;
}

સ્થિર સંરચના sshbuf *
process_load_resident(સંરચના sshbuf *req)
{
	પૂર્ણાંક r;
	અક્ષર *provider, *pin, *device;
	સંરચના sshbuf *kbuf, *resp;
	સંરચના sshsk_resident_ચાવી **srks = ખાલી;
	size_t nsrks = 0, i;
	u_int flags;

	જો ((kbuf = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);

	જો ((r = sshbuf_get_cstring(req, &provider, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	જો (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	જો ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		જાઓ out;
	}

	જો ((resp = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);

	જો ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	માટે (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->ચાવી), srks[i]->ચાવી->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		જો ((r = sshkey_private_serialize(srks[i]->ચાવી, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		જો ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_ચાવીઓ(srks, nsrks);
	sshbuf_free(kbuf);
	મુક્ત(provider);
	મુક્ત(device);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
	પાછા resp;
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	સંરચના sshbuf *req, *resp;
	પૂર્ણાંક in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	જ્યારે ((ch = getopt(argc, argv, "v")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'v':
			vflag = 1;
			જો (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			તોડો;
		મૂળભૂત:
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
	જો ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	જો ((req = sshbuf_new()) == ખાલી)
		fatal("%s: sshbuf_new failed", __progname);
	જો (ssh_સંદેશ_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	જો ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	જો (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	જો ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	જો (!vflag && log_level_name((LogLevel)ll) != ખાલી)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	પસંદગી (rtype) {
	સ્થિતિ SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		તોડો;
	સ્થિતિ SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		તોડો;
	સ્થિતિ SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		તોડો;
	મૂળભૂત:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	જો (ssh_સંદેશ_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	પાછા (0);
}
#નહીંતર /* ENABLE_SK */

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	પાછા -1;
}
#endif /* ENABLE_SK */
