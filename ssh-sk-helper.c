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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <errno.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"

#ifdef ENABLE_SK
ബാഹ്യ അക്ഷരം *__progname;

സ്ഥിതം ഘടന sshbuf *reply_error(പൂർണ്ണസംഖ്യ r, അക്ഷരം *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

സ്ഥിതം ഘടന sshbuf *
reply_error(പൂർണ്ണസംഖ്യ r, അക്ഷരം *fmt, ...)
{
	അക്ഷരം *സന്ദേശം;
	va_list ap;
	ഘടന sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&സന്ദേശം, fmt, ap);
	va_end(ap);
	debug("%s: %s", __progname, സന്ദേശം);
	സ്വതന്ത്രം(സന്ദേശം);

	എങ്കിൽ (r >= 0)
		fatal_f("invalid error code %d", r);

	എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);
	എങ്കിൽ (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", __progname);
	തിരികെ resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
സ്ഥിതം ശൂന്യം
null_empty(അക്ഷരം **s)
{
	എങ്കിൽ (s == ശൂന്യ || *s == ശൂന്യ || **s != '\0')
		തിരികെ;

	സ്വതന്ത്രം(*s);
	*s = ശൂന്യ;
}

/* stubs */
പൂർണ്ണസംഖ്യ
pkcs11_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	തിരികെ SSH_ERR_INTERNAL_ERROR;
}

ശൂന്യം
pkcs11_താക്കോൽ_free(ഘടന sshkey *താക്കോൽ)
{
}

സ്ഥിതം ഘടന sshbuf *
process_sign(ഘടന sshbuf *req)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *resp, *kbuf;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	uint32_t compat;
	സ്ഥിരം u_char *message;
	u_char *sig = ശൂന്യ;
	size_t msglen, siglen = 0;
	അക്ഷരം *provider = ശൂന്യ, *pin = ശൂന്യ;

	എങ്കിൽ ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, ശൂന്യ, ശൂന്യ)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ശൂന്യ)) != 0)
		fatal_r(r, "%s: parse", __progname);
	എങ്കിൽ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	എങ്കിൽ ((r = sshkey_private_deserialize(kbuf, &താക്കോൽ)) != 0)
		fatal_r(r, "%s: Unable to parse private key", __progname);
	എങ്കിൽ (!sshkey_is_sk(താക്കോൽ)) {
		fatal("%s: Unsupported key type %s",
		    __progname, sshkey_ssh_name(താക്കോൽ));
	}

	debug_f("ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", sshkey_type(താക്കോൽ),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	എങ്കിൽ ((r = sshsk_sign(provider, താക്കോൽ, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		പോകുക out;
	}

	എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);

	എങ്കിൽ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal_r(r, "%s: compose", __progname);
 out:
	sshkey_free(താക്കോൽ);
	sshbuf_free(kbuf);
	സ്വതന്ത്രം(provider);
	എങ്കിൽ (sig != ശൂന്യ)
		freezero(sig, siglen);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
	തിരികെ resp;
}

സ്ഥിതം ഘടന sshbuf *
process_enroll(ഘടന sshbuf *req)
{
	പൂർണ്ണസംഖ്യ r;
	u_int type;
	അക്ഷരം *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	ഘടന sshbuf *challenge, *attest, *kbuf, *resp;
	ഘടന sshkey *താക്കോൽ;

	എങ്കിൽ ((attest = sshbuf_new()) == ശൂന്യ ||
	    (kbuf = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);

	എങ്കിൽ ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ശൂന്യ)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal_r(r, "%s: parse", __progname);
	എങ്കിൽ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	എങ്കിൽ (type > INT_MAX)
		fatal("%s: bad type %u", __progname, type);
	എങ്കിൽ (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = ശൂന്യ;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	എങ്കിൽ ((r = sshsk_enroll((പൂർണ്ണസംഖ്യ)type, provider, device, application, userid,
	    flags, pin, challenge, &താക്കോൽ, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		പോകുക out;
	}

	എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);
	എങ്കിൽ ((r = sshkey_private_serialize(താക്കോൽ, kbuf)) != 0)
		fatal_r(r, "%s: encode key", __progname);
	എങ്കിൽ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal_r(r, "%s: compose", __progname);

 out:
	sshkey_free(താക്കോൽ);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	സ്വതന്ത്രം(provider);
	സ്വതന്ത്രം(application);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));

	തിരികെ resp;
}

സ്ഥിതം ഘടന sshbuf *
process_load_resident(ഘടന sshbuf *req)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *provider, *pin, *device;
	ഘടന sshbuf *kbuf, *resp;
	ഘടന sshsk_resident_താക്കോൽ **srks = ശൂന്യ;
	size_t nsrks = 0, i;
	u_int flags;

	എങ്കിൽ ((kbuf = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);

	എങ്കിൽ ((r = sshbuf_get_cstring(req, &provider, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(req, &flags)) != 0)
		fatal_r(r, "%s: parse", __progname);
	എങ്കിൽ (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", __progname);

	null_empty(&device);
	null_empty(&pin);

	എങ്കിൽ ((r = sshsk_load_resident(provider, device, pin, flags,
	    &srks, &nsrks)) != 0) {
		resp = reply_error(r, "sshsk_load_resident failed: %s",
		    ssh_err(r));
		പോകുക out;
	}

	എങ്കിൽ ((resp = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);

	എങ്കിൽ ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal_r(r, "%s: compose", __progname);

	വേണ്ടി (i = 0; i < nsrks; i++) {
		debug_f("key %zu %s %s uidlen %zu", i,
		    sshkey_type(srks[i]->താക്കോൽ), srks[i]->താക്കോൽ->sk_application,
		    srks[i]->user_id_len);
		sshbuf_reset(kbuf);
		എങ്കിൽ ((r = sshkey_private_serialize(srks[i]->താക്കോൽ, kbuf)) != 0)
			fatal_r(r, "%s: encode key", __progname);
		എങ്കിൽ ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0 || /* comment */
		    (r = sshbuf_put_string(resp, srks[i]->user_id,
		    srks[i]->user_id_len)) != 0)
			fatal_r(r, "%s: compose key", __progname);
	}

 out:
	sshsk_free_resident_താക്കോലുകൾ(srks, nsrks);
	sshbuf_free(kbuf);
	സ്വതന്ത്രം(provider);
	സ്വതന്ത്രം(device);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
	തിരികെ resp;
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ഘടന sshbuf *req, *resp;
	പൂർണ്ണസംഖ്യ in, out, ch, r, vflag = 0;
	u_int rtype, ll = 0;
	uint8_t version, log_stderr = 0;

	sanitise_stdfd();
	log_init(__progname, log_level, log_facility, log_stderr);

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "v")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'v':
			vflag = 1;
			എങ്കിൽ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
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
	എങ്കിൽ ((in = dup(STDIN_FILENO)) == -1 || (out = dup(STDOUT_FILENO)) == -1)
		fatal("%s: dup: %s", __progname, strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	sanitise_stdfd(); /* resets to /dev/null */

	എങ്കിൽ ((req = sshbuf_new()) == ശൂന്യ)
		fatal("%s: sshbuf_new failed", __progname);
	എങ്കിൽ (ssh_സന്ദേശം_recv(in, req) < 0)
		fatal("ssh_msg_recv failed");
	close(in);
	debug_f("received message len %zu", sshbuf_len(req));

	എങ്കിൽ ((r = sshbuf_get_u8(req, &version)) != 0)
		fatal_r(r, "%s: parse version", __progname);
	എങ്കിൽ (version != SSH_SK_HELPER_VERSION) {
		fatal("unsupported version: received %d, expected %d",
		    version, SSH_SK_HELPER_VERSION);
	}

	എങ്കിൽ ((r = sshbuf_get_u32(req, &rtype)) != 0 ||
	    (r = sshbuf_get_u8(req, &log_stderr)) != 0 ||
	    (r = sshbuf_get_u32(req, &ll)) != 0)
		fatal_r(r, "%s: parse", __progname);

	എങ്കിൽ (!vflag && log_level_name((LogLevel)ll) != ശൂന്യ)
		log_init(__progname, (LogLevel)ll, log_facility, log_stderr);

	തിരഞ്ഞെടുപ്പ് (rtype) {
	അവസ്ഥ SSH_SK_HELPER_SIGN:
		resp = process_sign(req);
		നിർത്തുക;
	അവസ്ഥ SSH_SK_HELPER_ENROLL:
		resp = process_enroll(req);
		നിർത്തുക;
	അവസ്ഥ SSH_SK_HELPER_LOAD_RESIDENT:
		resp = process_load_resident(req);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("%s: unsupported request type %u", __progname, rtype);
	}
	sshbuf_free(req);
	debug_f("reply len %zu", sshbuf_len(resp));

	എങ്കിൽ (ssh_സന്ദേശം_send(out, SSH_SK_HELPER_VERSION, resp) == -1)
		fatal("ssh_msg_send failed");
	sshbuf_free(resp);
	close(out);

	തിരികെ (0);
}
#അല്ലെങ്കിൽ /* ENABLE_SK */

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	fprintf(stderr, "ssh-sk-helper: disabled at compile time\n");
	തിരികെ -1;
}
#endif /* ENABLE_SK */
