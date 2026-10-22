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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/time.h>

#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <poll.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "ssh-pkcs11.h"
#समावेश "ssherr.h"

#अगर_घोषित ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

अटल अक्षर *providername; /* Provider for this helper */

#घोषणा MAX_संदेश_लंबाई		10240 /*XXX*/

/* input and output queue */
काष्ठा sshbuf *iqueue;
काष्ठा sshbuf *oqueue;

अटल व्योम
send_संदेश(काष्ठा sshbuf *m)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

अटल व्योम
process_add(व्योम)
{
	अक्षर *pin;
	काष्ठा sshkey **कुंजियाँ = शून्य;
	पूर्णांक r, i, nkeys;
	काष्ठा sshbuf *संदेश;
	अक्षर **labels = शून्य;

	अगर (providername != शून्य)
		fatal_f("provider already set");
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_get_cstring(iqueue, &providername, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, शून्य)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	अगर ((nkeys = pkcs11_add_provider(providername, pin,
	    &कुंजियाँ, &labels)) > 0) {
		अगर ((r = sshbuf_put_u8(संदेश,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, nkeys)) != 0)
			fatal_fr(r, "compose");
		क्रम (i = 0; i < nkeys; i++) {
			अगर ((r = sshkey_puts(कुंजियाँ[i], संदेश)) != 0 ||
			    (r = sshbuf_put_cstring(संदेश, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(कुंजियाँ[i]), labels[i]);
			मुक्त(labels[i]);
		}
	} अन्यथा अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, -nkeys)) != 0)
		fatal_fr(r, "compose");
	मुक्त(labels);
	मुक्त(कुंजियाँ); /* keys themselves are transferred to pkcs11_keylist */
	मुक्त(pin);
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
process_sign(व्योम)
{
	स्थिर u_char *तथ्य;
	u_char *signature = शून्य;
	माप_प्रकार dlen, slen = 0;
	u_int compat;
	पूर्णांक r, ok = -1;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *संदेश;
	अक्षर *alg = शून्य;

	अगर ((r = sshkey_froms(iqueue, &कुंजी)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &तथ्य, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	अगर (*alg == '\0') {
		मुक्त(alg);
		alg = शून्य;
	}

	अगर ((r = pkcs11_sign(कुंजी, &signature, &slen, तथ्य, dlen,
	    alg, शून्य, शून्य, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(कुंजी));
		जाओ reply;
	}

	/* success */
	ok = 0;
 reply:
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर (ok == 0) {
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(संदेश, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} अन्यथा {
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(कुंजी);
	मुक्त(alg);
	मुक्त(signature);
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
process(व्योम)
{
	u_int संदेश_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	स्थिर u_char *cp;
	पूर्णांक r;

	buf_len = sshbuf_len(iqueue);
	अगर (buf_len < 5)
		वापस;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	संदेश_len = get_u32(cp);
	अगर (संदेश_len > MAX_संदेश_लंबाई) {
		error("bad message len %d", संदेश_len);
		cleanup_exit(11);
	}
	अगर (buf_len < संदेश_len + 4)
		वापस;
	अगर ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	चयन (type) {
	हाल SSH_AGENTC_ADD_SMARTCARD_कुंजी:
		debug("process_add");
		process_add();
		अवरोध;
	हाल SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		अवरोध;
	शेष:
		error("Unknown message %d", type);
		अवरोध;
	}
	/* discard the remaining bytes from the current packet */
	अगर (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	अगर (संदेश_len < consumed) {
		error("msg_len %d < consumed %d", संदेश_len, consumed);
		cleanup_exit(255);
	}
	अगर (संदेश_len > consumed) {
		अगर ((r = sshbuf_consume(iqueue, संदेश_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

व्योम
cleanup_exit(पूर्णांक i)
{
	/* XXX */
	_निकास(i);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	अक्षर buf[4*4096];
	बाह्य अक्षर *__progname;
	काष्ठा pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	जबतक ((ch = getopt(argc, argv, "v")) != -1) {
		चयन (ch) {
		हाल 'v':
			log_stderr = 1;
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

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	अगर ((iqueue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((oqueue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	जबतक (1) {
		स_रखो(pfd, 0, माप(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		अगर ((r = sshbuf_check_reserve(iqueue, माप(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_संदेश_लंबाई)) == 0)
			pfd[0].events = POLLIN;
		अन्यथा अगर (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");

		अगर (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		अगर ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			अगर (r == 0 || त्रुटि_सं == EINTR)
				जारी;
			fatal("poll: %s", म_त्रुटि(त्रुटि_सं));
		}

		/* copy stdin to iqueue */
		अगर ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = पढ़ो(in, buf, माप buf);
			अगर (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} अन्यथा अगर (len < 0) {
				error("read: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा अगर ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		अगर ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ग_लिखो(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			अगर (len < 0) {
				error("write: %s", म_त्रुटि(त्रुटि_सं));
				cleanup_exit(1);
			} अन्यथा अगर ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		अगर ((r = sshbuf_check_reserve(oqueue, MAX_संदेश_लंबाई)) == 0)
			process();
		अन्यथा अगर (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");
	}
}
#अन्यथा /* ENABLE_PKCS11 */
पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	बाह्य अक्षर *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#पूर्ण_अगर /* ENABLE_PKCS11 */
