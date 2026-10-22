/* $OpenBSD: ssh-pkcs11-helper.c,v 1.31 2026/02/11 17:03:17 dtucker Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "ssh-pkcs11.h"
#अन्तर्भाव "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

स्थिर वर्ण *providername; /* Provider for this helper */

#define MAX_सन्देश_LENGTH		10240 /*XXX*/

/* input and output queue */
संरचना sshbuf *iqueue;
संरचना sshbuf *oqueue;

स्थिर शून्य
send_सन्देश(संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

स्थिर शून्य
process_add(शून्य)
{
	वर्ण *pin;
	संरचना sshkey **साँचोहरू = रिक्त;
	पूर्णाङ्क r, i, nkeys;
	संरचना sshbuf *सन्देश;
	वर्ण **labels = रिक्त;

	यदि (providername != रिक्त)
		fatal_f("provider already set");
	यदि ((सन्देश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_get_cstring(iqueue, &providername, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	यदि ((nkeys = pkcs11_add_provider(providername, pin,
	    &साँचोहरू, &labels)) > 0) {
		यदि ((r = sshbuf_put_u8(सन्देश,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(सन्देश, nkeys)) != 0)
			fatal_fr(r, "compose");
		लागि (i = 0; i < nkeys; i++) {
			यदि ((r = sshkey_puts(साँचोहरू[i], सन्देश)) != 0 ||
			    (r = sshbuf_put_cstring(सन्देश, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(साँचोहरू[i]), labels[i]);
			मुक्त(labels[i]);
		}
	} अन्यथा यदि ((r = sshbuf_put_u8(सन्देश, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(सन्देश, -nkeys)) != 0)
		fatal_fr(r, "compose");
	मुक्त(labels);
	मुक्त(साँचोहरू); /* keys themselves are transferred to pkcs11_keylist */
	मुक्त(pin);
	send_सन्देश(सन्देश);
	sshbuf_free(सन्देश);
}

स्थिर शून्य
process_sign(शून्य)
{
	अचर u_char *data;
	u_char *signature = रिक्त;
	माप_प्रकार dlen, slen = 0;
	u_int compat;
	पूर्णाङ्क r, ok = -1;
	संरचना sshkey *साँचो = रिक्त;
	संरचना sshbuf *सन्देश;
	वर्ण *alg = रिक्त;

	यदि ((r = sshkey_froms(iqueue, &साँचो)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	यदि (*alg == '\0') {
		मुक्त(alg);
		alg = रिक्त;
	}

	यदि ((r = pkcs11_sign(साँचो, &signature, &slen, data, dlen,
	    alg, रिक्त, रिक्त, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(साँचो));
		गच्छ reply;
	}

	/* success */
	ok = 0;
 reply:
	यदि ((सन्देश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि (ok == 0) {
		यदि ((r = sshbuf_put_u8(सन्देश, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(सन्देश, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} अन्यथा {
		यदि ((r = sshbuf_put_u8(सन्देश, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(साँचो);
	मुक्त(alg);
	मुक्त(signature);
	send_सन्देश(सन्देश);
	sshbuf_free(सन्देश);
}

स्थिर शून्य
process(शून्य)
{
	u_int सन्देश_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	अचर u_char *cp;
	पूर्णाङ्क r;

	buf_len = sshbuf_len(iqueue);
	यदि (buf_len < 5)
		फर्काऊ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	सन्देश_len = get_u32(cp);
	यदि (सन्देश_len > MAX_सन्देश_LENGTH) {
		error("bad message len %d", सन्देश_len);
		cleanup_exit(11);
	}
	यदि (buf_len < सन्देश_len + 4)
		फर्काऊ;
	यदि ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	विकल्प (type) {
	पक्ष SSH_AGENTC_ADD_SMARTCARD_साँचो:
		debug("process_add");
		process_add();
		रोक;
	पक्ष SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		रोक;
	स्वभाव:
		error("Unknown message %d", type);
		रोक;
	}
	/* discard the remaining bytes from the current packet */
	यदि (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	यदि (सन्देश_len < consumed) {
		error("msg_len %d < consumed %d", सन्देश_len, consumed);
		cleanup_exit(255);
	}
	यदि (सन्देश_len > consumed) {
		यदि ((r = sshbuf_consume(iqueue, सन्देश_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

शून्य
cleanup_exit(पूर्णाङ्क i)
{
	/* XXX */
	_exit(i);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	वर्ण buf[4*4096];
	बाह्य वर्ण *__progname;
	संरचना pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	जबसम्म ((ch = getopt(argc, argv, "v")) != -1) {
		विकल्प (ch) {
		पक्ष 'v':
			log_stderr = 1;
			यदि (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			रोक;
		स्वभाव:
			ख_लिखो(मानक_त्रुटि, "usage: %s [-v]\n", __progname);
			निकास(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	यदि ((iqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((oqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	जबसम्म (1) {
		स_रखो(pfd, 0, परिमाण(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		यदि ((r = sshbuf_check_reserve(iqueue, परिमाण(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_सन्देश_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		अन्यथा यदि (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		यदि (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		यदि ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			यदि (r == 0 || त्रुटि_सं == EINTR)
				जारी;
			fatal("poll: %s", म_त्रुटि(त्रुटि_सं));
		}

		/* copy stdin to iqueue */
		यदि ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = पठ(in, buf, परिमाण buf);
			यदि (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} अन्यथा यदि (len < 0) {
				error("read: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा यदि ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		यदि ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = लिख(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			यदि (len < 0) {
				error("write: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा यदि ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		यदि ((r = sshbuf_check_reserve(oqueue, MAX_सन्देश_LENGTH)) == 0)
			process();
		अन्यथा यदि (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#अन्यथा /* ENABLE_PKCS11 */
पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	बाह्य वर्ण *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
