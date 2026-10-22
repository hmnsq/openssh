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

#ضمن "includes.h"

#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <errno.h>

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "msg.h"
#ضمن "uidswap.h"
#ضمن "ssherr.h"
#ضمن "ssh-sk.h"
#ضمن "ssh-pkcs11.h"

#که_تعریف_شوی ENABLE_SK
خارجي حرف *__progname;

ساكن بنية sshbuf *ځواب_error(صحيح r, حرف *fmt, ...)
    __attribute__((__format__ (چاپ_کړه, 2, 3)));

ساكن بنية sshbuf *
ځواب_error(صحيح r, حرف *fmt, ...)
{
	حرف *پیغام;
	va_list ap;
	بنية sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&پیغام, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, پیغام);
	حرر(پیغام);

	إذا (r >= 0)
		fatal_f("invalid error code %d", r);

	إذا ((resp = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);
	إذا (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	أرجع resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
ساكن فراغ
null_تشه(حرف **s)
{
	إذا (s == عدم || *s == عدم || **s != '\0')
		أرجع;

	حرر(*s);
	*s = عدم;
}

/* stubs */
صحيح
pkcs11_sign(بنية sshkey *کلی,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	أرجع SSH_ERR_دننی_ERROR;
}

فراغ
pkcs11_کلی_free(بنية sshkey *کلی)
{
}

ساكن بنية sshbuf *
process_sign(بنية sshbuf *req)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *resp, *kbuf;
	بنية sshkey *کلی = عدم;
	uint32_t compat;
	ثابت u_char *پیغام_2;
	u_char *sig = عدم;
	اندازه_t msglen, siglen = 0;
	حرف *provider = عدم, *pin = عدم;

	إذا ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(req, &پیغام_2, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, عدم, عدم)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, عدم)) != 0)
		fatal_r(r, "%s: parse", __progname);
	إذا (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	إذا ((r = sshkey_شخصي_deserialize(kbuf, &کلی)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	إذا (!sshkey_is_sk(کلی)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(کلی));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(کلی),
	    provider, msglen, (u_long)compat);

	null_تشه(&pin);

	إذا ((r = sshsk_sign(provider, کلی, &sig, &siglen,
	    پیغام_2, msglen, compat, pin)) != 0) {
		resp = ځواب_error(r, "Signing failed: %s", ssh_err(r));
		اذهب بهر;
	}

	إذا ((resp = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);

	إذا ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 بهر:
	sshkey_free(کلی);
	sshbuf_free(kbuf);
	حرر(provider);
	إذا (sig != عدم)
		freezero(sig, siglen);
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));
	أرجع resp;
}

ساكن بنية sshbuf *
process_enroll(بنية sshbuf *req)
{
	صحيح r;
	u_int type;
	حرف *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	بنية sshbuf *challenge, *attest, *kbuf, *resp;
	بنية sshkey *کلی;

	إذا ((attest = sshbuf_new()) == عدم ||
	    (kbuf = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);

	إذا ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, عدم)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, عدم)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	إذا (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	إذا (type > لوی_عدد)
		fatal("%s: bad type %u", __progname, type);
	إذا (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = عدم;
	}
	null_تشه(&device);
	null_تشه(&userid);
	null_تشه(&pin);

	إذا ((r = sshsk_enroll((صحيح)type, provider, device, application, userid,
	    flags, pin, challenge, &کلی, attest)) != 0) {
		resp = ځواب_error(r, "Enrollment failed: %s", ssh_err(r));
		اذهب بهر;
	}

	إذا ((resp = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);
	إذا ((r = sshkey_شخصي_serialize(کلی, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	إذا ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 بهر:
	sshkey_free(کلی);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	حرر(provider);
	حرر(application);
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));

	أرجع resp;
}

ساكن بنية sshbuf *
process_بارول_resident(بنية sshbuf *req)
{
	صحيح r;
	حرف *provider, *pin, *device;
	بنية sshbuf *kbuf, *resp;
	بنية sshsk_resident_کلی **srks = عدم;
	اندازه_t nsrks = 0, i;
	u_int flags;

	إذا ((kbuf = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);

	إذا ((r = sshbuf_get_cstring(req, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, عدم)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	إذا (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_تشه(&device);
	null_تشه(&pin);

	إذا ((r = sshsk_بارول_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = ځواب_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		اذهب بهر;
	}

	إذا ((resp = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);

	إذا ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_بارول_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	لكل (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->کلی), srks[i]->کلی->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		إذا ((r = sshkey_شخصي_serialize(srks[i]->کلی, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		إذا ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 بهر:
	sshsk_free_resident_کلیګانې(srks, nsrks);
	sshbuf_free(kbuf);
	حرر(provider);
	حرر(device);
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));
	أرجع resp;
}

صحيح
اصلي(صحيح argc, حرف **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	بنية sshbuf *req, *resp;
	صحيح دننه, بهر, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t نسخه, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	طالما ((ch = getopt(argc, argv, "v")) != -1) {
		بدل (ch) {
		حالة 'v':
			vflag = 1;
			إذا (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			اكسر;
		افتراضي:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			وتل(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	إذا ((دننه = dup(STDIN_FILENO)) == -1 || (بهر = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	إذا ((req = sshbuf_new()) == عدم)
		fatal("%s: sshbuf_new failed", __progname);
	إذا (ssh_پیغام_recv(دننه, req) < 0)
		fatal("ssh_msg_recv failed");
	close(دننه);
	debug_f("received message len %zu", sshbuf_len(req));

	إذا ((r = sshbuf_get_u8(req, &نسخه)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	إذا (نسخه != SSH_SK_HELPER_نسخه) {
		fatal("unsupported version: received %d, expected %d",
		    نسخه, SSH_SK_HELPER_نسخه);
	}

	إذا ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	إذا (!vflag && log_level_name((LogLevel)ll) != عدم)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	بدل (rtype) {
	حالة SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		اكسر;
	حالة SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		اكسر;
	حالة SSH_SK_HELPER_بارول_RESIDENT:
		resp = process_بارول_resident(req);
		اكسر;
	افتراضي:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	إذا (ssh_پیغام_send(بهر, SSH_SK_HELPER_نسخه, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(بهر);

	أرجع (0);
}
#وإلا /* ENABLE_SK */

صحيح
اصلي(صحيح argc, حرف **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	أرجع -1;
}
#د_که_پای /* ENABLE_SK */
