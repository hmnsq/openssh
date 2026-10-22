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

स्थिर अक्षर *providername; /* Provider for this helper */

#define MAX_संदेश_LENGTH		10240 /*XXX*/

/* input and output queue */
संरचना sshbuf *iqueue;
संरचना sshbuf *oqueue;

स्थिर शून्य
send_संदेश(संरचना sshbuf *m)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

स्थिर शून्य
process_add(शून्य)
{
	अक्षर *pin;
	संरचना sshkey **किल्ल्या = रिक्त;
	पूर्णांक r, i, nkeys;
	संरचना sshbuf *संदेश;
	अक्षर **labels = रिक्त;

	जर (providername != रिक्त)
		fatal_f("provider already set");
	जर ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_get_cstring(iqueue, &providername, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	जर ((nkeys = pkcs11_add_provider(providername, pin,
	    &किल्ल्या, &labels)) > 0) {
		जर ((r = sshbuf_put_u8(संदेश,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, nkeys)) != 0)
			fatal_fr(r, "compose");
		साठी (i = 0; i < nkeys; i++) {
			जर ((r = sshkey_puts(किल्ल्या[i], संदेश)) != 0 ||
			    (r = sshbuf_put_cstring(संदेश, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(किल्ल्या[i]), labels[i]);
			मुक्त(labels[i]);
		}
	} अन्यथा जर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, -nkeys)) != 0)
		fatal_fr(r, "compose");
	मुक्त(labels);
	मुक्त(किल्ल्या); /* keys themselves are transferred to pkcs11_keylist */
	मुक्त(pin);
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

स्थिर शून्य
process_sign(शून्य)
{
	स्थिरांक u_char *data;
	u_char *signature = रिक्त;
	माप_प्रकार dlen, slen = 0;
	u_int compat;
	पूर्णांक r, ok = -1;
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshbuf *संदेश;
	अक्षर *alg = रिक्त;

	जर ((r = sshkey_froms(iqueue, &किल्ली)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	जर (*alg == '\0') {
		मुक्त(alg);
		alg = रिक्त;
	}

	जर ((r = pkcs11_sign(किल्ली, &signature, &slen, data, dlen,
	    alg, रिक्त, रिक्त, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(किल्ली));
		जा reply;
	}

	/* success */
	ok = 0;
 reply:
	जर ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर (ok == 0) {
		जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(संदेश, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} अन्यथा {
		जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(किल्ली);
	मुक्त(alg);
	मुक्त(signature);
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

स्थिर शून्य
process(शून्य)
{
	u_int संदेश_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	स्थिरांक u_char *cp;
	पूर्णांक r;

	buf_len = sshbuf_len(iqueue);
	जर (buf_len < 5)
		परत;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	संदेश_len = get_u32(cp);
	जर (संदेश_len > MAX_संदेश_LENGTH) {
		error("bad message len %d", संदेश_len);
		cleanup_exit(11);
	}
	जर (buf_len < संदेश_len + 4)
		परत;
	जर ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	निवड (type) {
	स्थिती SSH_AGENTC_ADD_SMARTCARD_किल्ली:
		debug("process_add");
		process_add();
		थांबा;
	स्थिती SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		थांबा;
	पूर्वनिर्धारित:
		error("Unknown message %d", type);
		थांबा;
	}
	/* discard the remaining bytes from the current packet */
	जर (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	जर (संदेश_len < consumed) {
		error("msg_len %d < consumed %d", संदेश_len, consumed);
		cleanup_exit(255);
	}
	जर (संदेश_len > consumed) {
		जर ((r = sshbuf_consume(iqueue, संदेश_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

शून्य
cleanup_exit(पूर्णांक i)
{
	/* XXX */
	_exit(i);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	अक्षर buf[4*4096];
	बाह्य अक्षर *__progname;
	संरचना pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	पर्यंत ((ch = getopt(argc, argv, "v")) != -1) {
		निवड (ch) {
		स्थिती 'v':
			log_stderr = 1;
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

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	जर ((iqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((oqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	पर्यंत (1) {
		स_रखो(pfd, 0, आकार(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		जर ((r = sshbuf_check_reserve(iqueue, आकार(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_संदेश_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		अन्यथा जर (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		जर (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		जर ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			जर (r == 0 || त्रुटि_सं == EINTR)
				सुरूठेवा;
			fatal("poll: %s", म_त्रुटि(त्रुटि_सं));
		}

		/* copy stdin to iqueue */
		जर ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = पठ(in, buf, आकार buf);
			जर (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} अन्यथा जर (len < 0) {
				error("read: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा जर ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		जर ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = लिख(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			जर (len < 0) {
				error("write: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा जर ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		जर ((r = sshbuf_check_reserve(oqueue, MAX_संदेश_LENGTH)) == 0)
			process();
		अन्यथा जर (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#अन्यथा /* ENABLE_PKCS11 */
पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	बाह्य अक्षर *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
