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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <errno.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "ssh-pkcs11.h"

#నిర్వచితమైతే ENABLE_SK
బాహ్య అక్షరం *__progname;

స్థిర నిర్మాణం sshbuf *జవాబు_error(పూర్ణాంకం r, అక్షరం *fmt, ...)
    __attribute__((__format__ (రాయి, 2, 3)));

స్థిర నిర్మాణం sshbuf *
జవాబు_error(పూర్ణాంకం r, అక్షరం *fmt, ...)
{
	అక్షరం *సందేశం;
	va_list ap;
	నిర్మాణం sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&సందేశం, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, సందేశం);
	విడుదల(సందేశం);

	ఒకవేళ (r >= 0)
		fatal_f("invalid error code %d", r);

	ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);
	ఒకవేళ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	తిరిగి resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
స్థిర శూన్య
null_ఖాళీలు(అక్షరం **s)
{
	ఒకవేళ (s == ఖాళీ || *s == ఖాళీ || **s != '\0')
		తిరిగి;

	విడుదల(*s);
	*s = ఖాళీ;
}

/* stubs */
పూర్ణాంకం
pkcs11_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}

శూన్య
pkcs11_కీలకం_free(నిర్మాణం sshkey *కీలకం)
{
}

స్థిర నిర్మాణం sshbuf *
process_sign(నిర్మాణం sshbuf *req)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *resp, *kbuf;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	uint32_t compat;
	స్థిరరాశి u_char *సందేశం_2;
	u_char *sig = ఖాళీ;
	కొలత_t msglen, siglen = 0;
	అక్షరం *provider = ఖాళీ, *pin = ఖాళీ;

	ఒకవేళ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(req, &సందేశం_2, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ఖాళీ, ఖాళీ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ఖాళీ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ఒకవేళ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(kbuf, &కీలకం)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	ఒకవేళ (!sshkey_is_sk(కీలకం)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(కీలకం));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(కీలకం),
	    provider, msglen, (u_long)compat);

	null_ఖాళీలు(&pin);

	ఒకవేళ ((r = sshsk_sign(provider, కీలకం, &sig, &siglen,
	    సందేశం_2, msglen, compat, pin)) != 0) {
		resp = జవాబు_error(r, "Signing failed: %s", ssh_err(r));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);

	ఒకవేళ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 బహిర్గతం:
	sshkey_free(కీలకం);
	sshbuf_free(kbuf);
	విడుదల(provider);
	ఒకవేళ (sig != ఖాళీ)
		freezero(sig, siglen);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
	తిరిగి resp;
}

స్థిర నిర్మాణం sshbuf *
process_enroll(నిర్మాణం sshbuf *req)
{
	పూర్ణాంకం r;
	u_int type;
	అక్షరం *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	నిర్మాణం sshbuf *challenge, *attest, *kbuf, *resp;
	నిర్మాణం sshkey *కీలకం;

	ఒకవేళ ((attest = sshbuf_new()) == ఖాళీ ||
	    (kbuf = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);

	ఒకవేళ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ఖాళీ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ఒకవేళ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	ఒకవేళ (type > గరిష్ఠ_పూర్ణాంకం)
		fatal("%s: bad type %u", __progname, type);
	ఒకవేళ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ఖాళీ;
	}
	null_ఖాళీలు(&device);
	null_ఖాళీలు(&userid);
	null_ఖాళీలు(&pin);

	ఒకవేళ ((r = sshsk_enroll((పూర్ణాంకం)type, provider, device, application, userid,
	    flags, pin, challenge, &కీలకం, attest)) != 0) {
		resp = జవాబు_error(r, "Enrollment failed: %s", ssh_err(r));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(కీలకం, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	ఒకవేళ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 బహిర్గతం:
	sshkey_free(కీలకం);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	విడుదల(provider);
	విడుదల(application);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));

	తిరిగి resp;
}

స్థిర నిర్మాణం sshbuf *
process_ఎక్కించు_resident(నిర్మాణం sshbuf *req)
{
	పూర్ణాంకం r;
	అక్షరం *provider, *pin, *device;
	నిర్మాణం sshbuf *kbuf, *resp;
	నిర్మాణం sshsk_resident_కీలకం **srks = ఖాళీ;
	కొలత_t nsrks = 0, i;
	u_int flags;

	ఒకవేళ ((kbuf = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);

	ఒకవేళ ((r = sshbuf_get_cstring(req, &provider, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	ఒకవేళ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_ఖాళీలు(&device);
	null_ఖాళీలు(&pin);

	ఒకవేళ ((r = sshsk_ఎక్కించు_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = జవాబు_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((resp = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);

	ఒకవేళ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ఎక్కించు_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	కొరకు (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->కీలకం), srks[i]->కీలకం->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(srks[i]->కీలకం, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		ఒకవేళ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 బహిర్గతం:
	sshsk_free_resident_కీలకాలు(srks, nsrks);
	sshbuf_free(kbuf);
	విడుదల(provider);
	విడుదల(device);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
	తిరిగి resp;
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	నిర్మాణం sshbuf *req, *resp;
	పూర్ణాంకం లోపల, బహిర్గతం, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t సంస్కరణ, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	అయితే ((ch = getopt(argc, argv, "v")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'v':
			vflag = 1;
			ఒకవేళ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ఆపు;
		అప్రమేయ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			నిష్క్రమించు(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	ఒకవేళ ((లోపల = dup(STDIN_FILENO)) == -1 || (బహిర్గతం = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	ఒకవేళ ((req = sshbuf_new()) == ఖాళీ)
		fatal("%s: sshbuf_new failed", __progname);
	ఒకవేళ (ssh_సందేశం_recv(లోపల, req) < 0)
		fatal("ssh_msg_recv failed");
	close(లోపల);
	debug_f("received message len %zu", sshbuf_len(req));

	ఒకవేళ ((r = sshbuf_get_u8(req, &సంస్కరణ)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	ఒకవేళ (సంస్కరణ != SSH_SK_HELPER_సంస్కరణ) {
		fatal("unsupported version: received %d, expected %d",
		    సంస్కరణ, SSH_SK_HELPER_సంస్కరణ);
	}

	ఒకవేళ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	ఒకవేళ (!vflag && log_level_name((LogLevel)ll) != ఖాళీ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	ఎంపిక (rtype) {
	స్థితి SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		ఆపు;
	స్థితి SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		ఆపు;
	స్థితి SSH_SK_HELPER_ఎక్కించు_RESIDENT:
		resp = process_ఎక్కించు_resident(req);
		ఆపు;
	అప్రమేయ:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	ఒకవేళ (ssh_సందేశం_send(బహిర్గతం, SSH_SK_HELPER_సంస్కరణ, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(బహిర్గతం);

	తిరిగి (0);
}
#లేకపోతే /* ENABLE_SK */

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	తిరిగి -1;
}
#అయితే_ముగింపు /* ENABLE_SK */
