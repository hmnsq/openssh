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

#شامل "includes.h"

#شامل <limits.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <errno.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "msg.h"
#شامل "uidswap.h"
#شامل "ssherr.h"
#شامل "ssh-sk.h"
#شامل "ssh-pkcs11.h"

#ifdef ENABLE_SK
بیرونی نویسه *__progname;

ایستا ساختار sshbuf *reply_error(صحیح r, نویسه *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ایستا ساختار sshbuf *
reply_error(صحیح r, نویسه *fmt, ...)
{
	نویسه *پیام;
	va_list ap;
	ساختار sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&پیام, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, پیام);
	آزاد(پیام);

	اگر (r >= 0)
		fatal_f("invalid error code %d", r);

	اگر ((resp = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);
	اگر (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	بازگشت resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ایستا تهی
null_empty(نویسه **s)
{
	اگر (s == پوچ || *s == پوچ || **s != '\0')
		بازگشت;

	آزاد(*s);
	*s = پوچ;
}

/* stubs */
صحیح
pkcs11_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	بازگشت SSH_ERR_INTERNAL_ERROR;
}

تهی
pkcs11_کلید_free(ساختار sshkey *کلید)
{
}

ایستا ساختار sshbuf *
process_sign(ساختار sshbuf *req)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *resp, *kbuf;
	ساختار sshkey *کلید = پوچ;
	uint32_t compat;
	ثابت u_char *message;
	u_char *sig = پوچ;
	size_t msglen, siglen = 0;
	نویسه *provider = پوچ, *pin = پوچ;

	اگر ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, پوچ, پوچ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, پوچ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	اگر (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	اگر ((r = sshkey_private_deserialize(kbuf, &کلید)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	اگر (!sshkey_is_sk(کلید)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(کلید));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(کلید),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	اگر ((r = sshsk_sign(provider, کلید, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		برو out;
	}

	اگر ((resp = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);

	اگر ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	آزاد(provider);
	اگر (sig != پوچ)
		freezero(sig, siglen);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
	بازگشت resp;
}

ایستا ساختار sshbuf *
process_enroll(ساختار sshbuf *req)
{
	صحیح r;
	u_int type;
	نویسه *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ساختار sshbuf *challenge, *attest, *kbuf, *resp;
	ساختار sshkey *کلید;

	اگر ((attest = sshbuf_new()) == پوچ ||
	    (kbuf = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);

	اگر ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, پوچ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, پوچ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	اگر (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	اگر (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	اگر (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = پوچ;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	اگر ((r = sshsk_enroll((صحیح)type, provider, device, application, userid,
	    flags, pin, challenge, &کلید, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		برو out;
	}

	اگر ((resp = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);
	اگر ((r = sshkey_private_serialize(کلید, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	اگر ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	آزاد(provider);
	آزاد(application);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));

	بازگشت resp;
}

ایستا ساختار sshbuf *
process_load_resident(ساختار sshbuf *req)
{
	صحیح r;
	نویسه *provider, *pin, *device;
	ساختار sshbuf *kbuf, *resp;
	ساختار sshsk_resident_کلید **srks = پوچ;
	size_t nsrks = 0, i;
	u_int flags;

	اگر ((kbuf = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);

	اگر ((r = sshbuf_get_cstring(req, &provider, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	اگر (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	اگر ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		برو out;
	}

	اگر ((resp = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);

	اگر ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	برای (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->کلید), srks[i]->کلید->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		اگر ((r = sshkey_private_serialize(srks[i]->کلید, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		اگر ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_کلیدها(srks, nsrks);
	sshbuf_free(kbuf);
	آزاد(provider);
	آزاد(device);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
	بازگشت resp;
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ساختار sshbuf *req, *resp;
	صحیح in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	وقتی ((ch = getopt(argc, argv, "v")) != -1) {
		انتخاب (ch) {
		حالت 'v':
			vflag = 1;
			اگر (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			بشکن;
		پیشفرض:
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
	اگر ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	اگر ((req = sshbuf_new()) == پوچ)
		fatal("%s: sshbuf_new failed", __progname);
	اگر (ssh_پیام_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	اگر ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	اگر (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	اگر ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	اگر (!vflag && log_level_name((LogLevel)ll) != پوچ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	انتخاب (rtype) {
	حالت SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		بشکن;
	حالت SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		بشکن;
	حالت SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		بشکن;
	پیشفرض:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	اگر (ssh_پیام_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	بازگشت (0);
}
#وگرنه /* ENABLE_SK */

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	بازگشت -1;
}
#endif /* ENABLE_SK */
