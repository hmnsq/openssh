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

#समावेश "includes.h"

#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <errno.h>

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "msg.h"
#समावेश "uidswap.h"
#समावेश "ssherr.h"
#समावेश "ssh-sk.h"
#समावेश "ssh-pkcs11.h"

#अगर_घोषित ENABLE_SK
बाह्य अक्षर *__progname;

अटल काष्ठा sshbuf *reply_error(पूर्णांक r, अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

अटल काष्ठा sshbuf *
reply_error(पूर्णांक r, अक्षर *fmt, ...)
{
	अक्षर *संदेश;
	बहु_सूची ap;
	काष्ठा sshbuf *resp;

	बहु_शुरू(ap, fmt);
	xvasprintf(&संदेश, fmt, ap);
	बहु_पूर्ण(ap);
	debug("%s: %s", __progname, संदेश);
	मुक्त(संदेश);

	अगर (r >= 0)
		fatal_f("invalid error code %d", r);

	अगर ((resp = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);
	अगर (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	वापस resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
अटल व्योम
null_empty(अक्षर **s)
{
	अगर (s == शून्य || *s == शून्य || **s != '\0')
		वापस;

	मुक्त(*s);
	*s = शून्य;
}

/* stubs */
पूर्णांक
pkcs11_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	वापस SSH_ERR_INTERNAL_ERROR;
}

व्योम
pkcs11_कुंजी_free(काष्ठा sshkey *कुंजी)
{
}

अटल काष्ठा sshbuf *
process_sign(काष्ठा sshbuf *req)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *resp, *kbuf;
	काष्ठा sshkey *कुंजी = शून्य;
	uint32_t compat;
	स्थिर u_char *message;
	u_char *sig = शून्य;
	माप_प्रकार msglen, siglen = 0;
	अक्षर *provider = शून्य, *pin = शून्य;

	अगर ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, शून्य, शून्य)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, शून्य)) != 0)
		fatal_r(r, "%s: parse", __progname);
	अगर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	अगर ((r = sshkey_private_deserialize(kbuf, &कुंजी)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	अगर (!sshkey_is_sk(कुंजी)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(कुंजी));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(कुंजी),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	अगर ((r = sshsk_sign(provider, कुंजी, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		जाओ out;
	}

	अगर ((resp = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);

	अगर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(कुंजी);
	sshbuf_free(kbuf);
	मुक्त(provider);
	अगर (sig != शून्य)
		freezero(sig, siglen);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
	वापस resp;
}

अटल काष्ठा sshbuf *
process_enroll(काष्ठा sshbuf *req)
{
	पूर्णांक r;
	u_int type;
	अक्षर *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	काष्ठा sshbuf *challenge, *attest, *kbuf, *resp;
	काष्ठा sshkey *कुंजी;

	अगर ((attest = sshbuf_new()) == शून्य ||
	    (kbuf = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);

	अगर ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, शून्य)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, शून्य)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	अगर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	अगर (type > पूर्णांक_उच्च)
		fatal("%s: bad type %u", __progname, type);
	अगर (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = शून्य;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	अगर ((r = sshsk_enroll((पूर्णांक)type, provider, device, application, userid,
	    flags, pin, challenge, &कुंजी, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		जाओ out;
	}

	अगर ((resp = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);
	अगर ((r = sshkey_private_serialize(कुंजी, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	अगर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(कुंजी);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	मुक्त(provider);
	मुक्त(application);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));

	वापस resp;
}

अटल काष्ठा sshbuf *
process_load_resident(काष्ठा sshbuf *req)
{
	पूर्णांक r;
	अक्षर *provider, *pin, *device;
	काष्ठा sshbuf *kbuf, *resp;
	काष्ठा sshsk_resident_कुंजी **srks = शून्य;
	माप_प्रकार nsrks = 0, i;
	u_int flags;

	अगर ((kbuf = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);

	अगर ((r = sshbuf_get_cstring(req, &provider, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	अगर (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	अगर ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		जाओ out;
	}

	अगर ((resp = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);

	अगर ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	क्रम (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->कुंजी), srks[i]->कुंजी->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		अगर ((r = sshkey_private_serialize(srks[i]->कुंजी, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		अगर ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	sshbuf_free(kbuf);
	मुक्त(provider);
	मुक्त(device);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
	वापस resp;
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	काष्ठा sshbuf *req, *resp;
	पूर्णांक in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	जबतक ((ch = getopt(argc, argv, "v")) != -1) {
		चयन (ch) {
		हाल 'v':
			vflag = 1;
			अगर (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा अगर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अवरोध;
		शेष:
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
	अगर ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, म_त्रुटि(त्रुटि_सं));
	बंद(STDIN_FILENO);
	बंद(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	अगर ((req = sshbuf_new()) == शून्य)
		fatal("%s: sshbuf_new failed", __progname);
	अगर (ssh_संदेश_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	बंद(in);
	debug_f("received message len %zu", sshbuf_len(req));

	अगर ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	अगर (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	अगर ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	अगर (!vflag && log_level_name((LogLevel)ll) != शून्य)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	चयन (rtype) {
	हाल SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		अवरोध;
	हाल SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		अवरोध;
	हाल SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		अवरोध;
	शेष:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	अगर (ssh_संदेश_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	बंद(out);

	वापस (0);
}
#अन्यथा /* ENABLE_SK */

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	ख_लिखो(मानक_त्रुटि, "ssh-sk-helper: disabled at compile time\n");
	वापस -1;
}
#पूर्ण_अगर /* ENABLE_SK */
