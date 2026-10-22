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

#ifdef ENABLE_SK
बाह्य अक्षर *__progname;

स्थिर संरचना sshbuf *reply_error(पूर्णांक r, अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

स्थिर संरचना sshbuf *
reply_error(पूर्णांक r, अक्षर *fmt, ...)
{
	अक्षर *संदेश;
	बहु_सूची ap;
	संरचना sshbuf *resp;

	बहु_शुरू(ap, fmt);
	xvasprintf(&संदेश, fmt, ap);
	बहु_पूर्ण(ap);
	debug("%s: %s", __progname, संदेश);
	मुक्त(संदेश);

	जर (r >= 0)
		fatal_f("invalid error code %d", r);

	जर ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	जर (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	परत resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
स्थिर शून्य
null_empty(अक्षर **s)
{
	जर (s == रिक्त || *s == रिक्त || **s != '\0')
		परत;

	मुक्त(*s);
	*s = रिक्त;
}

/* stubs */
पूर्णांक
pkcs11_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider,
    स्थिरांक अक्षर *sk_pin, u_int compat)
{
	परत SSH_ERR_INTERNAL_ERROR;
}

शून्य
pkcs11_किल्ली_free(संरचना sshkey *किल्ली)
{
}

स्थिर संरचना sshbuf *
process_sign(संरचना sshbuf *req)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *resp, *kbuf;
	संरचना sshkey *किल्ली = रिक्त;
	uint32_t compat;
	स्थिरांक u_char *message;
	u_char *sig = रिक्त;
	माप_प्रकार msglen, siglen = 0;
	अक्षर *provider = रिक्त, *pin = रिक्त;

	जर ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, रिक्त, रिक्त)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0)
		fatal_r(r, "%s: parse", __progname);
	जर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	जर ((r = sshkey_private_deserialize(kbuf, &किल्ली)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	जर (!sshkey_is_sk(किल्ली)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(किल्ली));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(किल्ली),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	जर ((r = sshsk_sign(provider, किल्ली, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		जा out;
	}

	जर ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	जर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(किल्ली);
	sshbuf_free(kbuf);
	मुक्त(provider);
	जर (sig != रिक्त)
		freezero(sig, siglen);
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
	परत resp;
}

स्थिर संरचना sshbuf *
process_enroll(संरचना sshbuf *req)
{
	पूर्णांक r;
	u_int type;
	अक्षर *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	संरचना sshbuf *challenge, *attest, *kbuf, *resp;
	संरचना sshkey *किल्ली;

	जर ((attest = sshbuf_new()) == रिक्त ||
	    (kbuf = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	जर ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	जर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	जर (type > पूर्णांक_उच्च)
		fatal("%s: bad type %u", __progname, type);
	जर (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = रिक्त;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	जर ((r = sshsk_enroll((पूर्णांक)type, provider, device, application, userid,
	    flags, pin, challenge, &किल्ली, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		जा out;
	}

	जर ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	जर ((r = sshkey_private_serialize(किल्ली, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	जर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(किल्ली);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	मुक्त(provider);
	मुक्त(application);
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));

	परत resp;
}

स्थिर संरचना sshbuf *
process_load_resident(संरचना sshbuf *req)
{
	पूर्णांक r;
	अक्षर *provider, *pin, *device;
	संरचना sshbuf *kbuf, *resp;
	संरचना sshsk_resident_किल्ली **srks = रिक्त;
	माप_प्रकार nsrks = 0, i;
	u_int flags;

	जर ((kbuf = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	जर ((r = sshbuf_get_cstring(req, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	जर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	जर ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		जा out;
	}

	जर ((resp = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);

	जर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	साठी (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->किल्ली), srks[i]->किल्ली->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		जर ((r = sshkey_private_serialize(srks[i]->किल्ली, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		जर ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_किल्ल्या(srks, nsrks);
	sshbuf_free(kbuf);
	मुक्त(provider);
	मुक्त(device);
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
	परत resp;
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	संरचना sshbuf *req, *resp;
	पूर्णांक in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	पर्यंत ((ch = getopt(argc, argv, "v")) != -1) {
		निवड (ch) {
		स्थिती 'v':
			vflag = 1;
			जर (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा जर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			थांबा;
		पूर्वनिर्धारित:
			ख_लिखो(मानक_त्रुटि, "usage: %s [-v]\n", __progname);
			निकास(1);
		}
	}
	log_init(__progname, log_level, log_facility, vflag);

	/*
	 * Rearrange our file descriptors a little; we don't trust the
	 * providers not to fiddle with stdin/out.
	 */
	closefrom(STDERR_FILENO + 1);
	जर ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, म_त्रुटि(त्रुटि_सं));
	बंद(STDIN_FILENO);
	बंद(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	जर ((req = sshbuf_new()) == रिक्त)
		fatal("%s: sshbuf_new failed", __progname);
	जर (ssh_संदेश_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	बंद(in);
	debug_f("received message len %zu", sshbuf_len(req));

	जर ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	जर (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	जर ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	जर (!vflag && log_level_name((LogLevel)ll) != रिक्त)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	निवड (rtype) {
	स्थिती SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		थांबा;
	स्थिती SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		थांबा;
	स्थिती SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		थांबा;
	पूर्वनिर्धारित:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	जर (ssh_संदेश_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	बंद(out);

	परत (0);
}
#अन्यथा /* ENABLE_SK */

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	ख_लिखो(मानक_त्रुटि, "ssh-sk-helper: disabled at compile time\n");
	परत -1;
}
#endif /* ENABLE_SK */
