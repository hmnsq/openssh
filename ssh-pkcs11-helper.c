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

#यदि_परिभाषितम् ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

स्थिर वर्ण *providername; /* Provider for this helper */

#परिभाषय MAX_सन्देशः_दीर्घता		10240 /*XXX*/

/* input and output queue */
संरचना sshbuf *iqueue;
संरचना sshbuf *oqueue;

स्थिर शून्य
send_सन्देशः(संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

स्थिर शून्य
process_सङ्कलय(शून्य)
{
	वर्ण *pin;
	संरचना sshkey **कुञ्चिकाः = रिक्त;
	पूर्णाङ्क r, i, nkeys;
	संरचना sshbuf *सन्देशः;
	वर्ण **labels = रिक्त;

	यदि (providername != रिक्त)
		fatal_f("provider already set");
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_get_cstring(iqueue, &providername, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	यदि ((nkeys = pkcs11_सङ्कलय_provider(providername, pin,
	    &कुञ्चिकाः, &labels)) > 0) {
		यदि ((r = sshbuf_put_u8(सन्देशः,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(सन्देशः, nkeys)) != 0)
			fatal_fr(r, "compose");
		प्रति (i = 0; i < nkeys; i++) {
			यदि ((r = sshkey_puts(कुञ्चिकाः[i], सन्देशः)) != 0 ||
			    (r = sshbuf_put_cstring(सन्देशः, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(कुञ्चिकाः[i]), labels[i]);
			मुक्त(labels[i]);
		}
	} अन्यथा यदि ((r = sshbuf_put_u8(सन्देशः, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, -nkeys)) != 0)
		fatal_fr(r, "compose");
	मुक्त(labels);
	मुक्त(कुञ्चिकाः); /* keys themselves are transferred to pkcs11_keylist */
	मुक्त(pin);
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
process_sign(शून्य)
{
	ध्रुव u_char *दत्त;
	u_char *signature = रिक्त;
	आकार_t dlen, slen = 0;
	u_int compat;
	पूर्णाङ्क r, ok = -1;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *सन्देशः;
	वर्ण *alg = रिक्त;

	यदि ((r = sshkey_froms(iqueue, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(iqueue, &दत्त, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	यदि (*alg == '\0') {
		मुक्त(alg);
		alg = रिक्त;
	}

	यदि ((r = pkcs11_sign(कुञ्चिका, &signature, &slen, दत्त, dlen,
	    alg, रिक्त, रिक्त, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(कुञ्चिका));
		गच्छ प्रत्युत्तरम्;
	}

	/* success */
	ok = 0;
 प्रत्युत्तरम्:
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि (ok == 0) {
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(सन्देशः, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} अन्यथा {
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(कुञ्चिका);
	मुक्त(alg);
	मुक्त(signature);
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
process(शून्य)
{
	u_int सन्देशः_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ध्रुव u_char *cp;
	पूर्णाङ्क r;

	buf_len = sshbuf_len(iqueue);
	यदि (buf_len < 5)
		प्रत्यागम;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	सन्देशः_len = get_u32(cp);
	यदि (सन्देशः_len > MAX_सन्देशः_दीर्घता) {
		error("bad message len %d", सन्देशः_len);
		cleanup_exit(11);
	}
	यदि (buf_len < सन्देशः_len + 4)
		प्रत्यागम;
	यदि ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	विकल्प (type) {
	पक्ष SSH_AGENTC_सङ्कलय_SMARTCARD_कुञ्चिका:
		debug("process_add");
		process_सङ्कलय();
		भङ्ग;
	पक्ष SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		भङ्ग;
	स्वभाव:
		error("Unknown message %d", type);
		भङ्ग;
	}
	/* discard the remaining bytes from the current packet */
	यदि (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	यदि (सन्देशः_len < consumed) {
		error("msg_len %d < consumed %d", सन्देशः_len, consumed);
		cleanup_exit(255);
	}
	यदि (सन्देशः_len > consumed) {
		यदि ((r = sshbuf_consume(iqueue, सन्देशः_len - consumed)) != 0)
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
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, ch, अन्तर्, बहिर्गमनम्, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	वर्ण buf[4*4096];
	बाह्य वर्ण *__progname;
	संरचना pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	बीजम्_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	यावत् ((ch = getopt(argc, argv, "v")) != -1) {
		विकल्प (ch) {
		पक्ष 'v':
			log_stderr = 1;
			यदि (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			भङ्ग;
		स्वभाव:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			निर्गच्छ(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	अन्तर् = STDIN_FILENO;
	बहिर्गमनम् = STDOUT_FILENO;

	यदि ((iqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((oqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यावत् (1) {
		स्मृतिं_पूरय(pfd, 0, परिमाण(pfd));
		pfd[0].fd = अन्तर्;
		pfd[1].fd = बहिर्गमनम्;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		यदि ((r = sshbuf_check_reserve(iqueue, परिमाण(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_सन्देशः_दीर्घता)) == 0)
			pfd[0].events = POLLIN;
		अन्यथा यदि (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");

		यदि (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		यदि ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			यदि (r == 0 || errno == EINTR)
				अनुवर्त;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		यदि ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = पठ(अन्तर्, buf, परिमाण buf);
			यदि (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} अन्यथा यदि (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} अन्यथा यदि ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		यदि ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = लिख(बहिर्गमनम्, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			यदि (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} अन्यथा यदि ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		यदि ((r = sshbuf_check_reserve(oqueue, MAX_सन्देशः_दीर्घता)) == 0)
			process();
		अन्यथा यदि (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");
	}
}
#अन्यथा /* ENABLE_PKCS11 */
पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	बाह्य वर्ण *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#यदि_अन्तः /* ENABLE_PKCS11 */
