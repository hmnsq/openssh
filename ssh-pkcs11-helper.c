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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ಸ್ಥಿರ ಅಕ್ಷರ *providername; /* Provider for this helper */

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ		10240 /*XXX*/

/* input and output queue */
ರಚನೆ sshbuf *iqueue;
ರಚನೆ sshbuf *oqueue;

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_ಕೂಡಿಸು(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *pin;
	ರಚನೆ sshkey **ಕೀಲಿಗಳು = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, i, nkeys;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಅಕ್ಷರ **labels = ಖಾಲಿ;

	ಆದರೆ (providername != ಖಾಲಿ)
		fatal_f("provider already set");
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &providername, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ಆದರೆ ((nkeys = pkcs11_ಕೂಡಿಸು_provider(providername, pin,
	    &ಕೀಲಿಗಳು, &labels)) > 0) {
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, nkeys)) != 0)
			fatal_fr(r, "compose");
		ಗಾಗಿ (i = 0; i < nkeys; i++) {
			ಆದರೆ ((r = sshkey_puts(ಕೀಲಿಗಳು[i], ಸಂದೇಶ)) != 0 ||
			    (r = sshbuf_put_cstring(ಸಂದೇಶ, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(ಕೀಲಿಗಳು[i]), labels[i]);
			ಬಿಡುಗಡೆ(labels[i]);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, -nkeys)) != 0)
		fatal_fr(r, "compose");
	ಬಿಡುಗಡೆ(labels);
	ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು); /* keys themselves are transferred to pkcs11_keylist */
	ಬಿಡುಗಡೆ(pin);
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_sign(ಶೂನ್ಯ)
{
	ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ;
	u_char *signature = ಖಾಲಿ;
	ಗಾತ್ರ_t dlen, slen = 0;
	u_int compat;
	ಪೂರ್ಣಾಂಕ r, ok = -1;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಅಕ್ಷರ *alg = ಖಾಲಿ;

	ಆದರೆ ((r = sshkey_froms(iqueue, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(iqueue, &ದತ್ತಾಂಶ, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (*alg == '\0') {
		ಬಿಡುಗಡೆ(alg);
		alg = ಖಾಲಿ;
	}

	ಆದರೆ ((r = pkcs11_sign(ಕೀಲಿ, &signature, &slen, ದತ್ತಾಂಶ, dlen,
	    alg, ಖಾಲಿ, ಖಾಲಿ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(ಕೀಲಿ));
		ಹೋಗು ಉತ್ತರ;
	}

	/* success */
	ok = 0;
 ಉತ್ತರ:
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ (ok == 0) {
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(ಕೀಲಿ);
	ಬಿಡುಗಡೆ(alg);
	ಬಿಡುಗಡೆ(signature);
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process(ಶೂನ್ಯ)
{
	u_int ಸಂದೇಶ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಪೂರ್ಣಾಂಕ r;

	buf_len = sshbuf_len(iqueue);
	ಆದರೆ (buf_len < 5)
		ಹಿಂತಿರುಗಿ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ಸಂದೇಶ_len = get_u32(cp);
	ಆದರೆ (ಸಂದೇಶ_len > MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ) {
		error("bad message len %d", ಸಂದೇಶ_len);
		cleanup_exit(11);
	}
	ಆದರೆ (buf_len < ಸಂದೇಶ_len + 4)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ:
		debug("process_add");
		process_ಕೂಡಿಸು();
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("Unknown message %d", type);
		ನಿಲ್ಲಿಸು;
	}
	/* discard the remaining bytes from the current packet */
	ಆದರೆ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ಆದರೆ (ಸಂದೇಶ_len < consumed) {
		error("msg_len %d < consumed %d", ಸಂದೇಶ_len, consumed);
		cleanup_exit(255);
	}
	ಆದರೆ (ಸಂದೇಶ_len > consumed) {
		ಆದರೆ ((r = sshbuf_consume(iqueue, ಸಂದೇಶ_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	/* XXX */
	_exit(i);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ r, ch, ಒಳ, ಹೊರಹೋಗು, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ಅಕ್ಷರ buf[4*4096];
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;
	ರಚನೆ pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	ಬೀಜ_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ಆಗ ((ch = getopt(argc, argv, "v")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'v':
			log_stderr = 1;
			ಆದರೆ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			ನಿರ್ಗಮಿಸು(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	ಒಳ = STDIN_FILENO;
	ಹೊರಹೋಗು = STDOUT_FILENO;

	ಆದರೆ ((iqueue = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((oqueue = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆಗ (1) {
		memset(pfd, 0, ಗಾತ್ರ(pfd));
		pfd[0].fd = ಒಳ;
		pfd[1].fd = ಹೊರಹೋಗು;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ಆದರೆ ((r = sshbuf_check_reserve(iqueue, ಗಾತ್ರ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ)) == 0)
			pfd[0].events = POLLIN;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_NO_ಬಫರ್_SPACE)
			fatal_fr(r, "reserve");

		ಆದರೆ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ಆದರೆ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ಆದರೆ (r == 0 || errno == EINTR)
				ಮುಂದುವರಿ;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ಆದರೆ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = ಪಠ(ಒಳ, buf, ಗಾತ್ರ buf);
			ಆದರೆ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ಆದರೆ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ಲಿಖ(ಹೊರಹೋಗು, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ಆದರೆ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ಆದರೆ ((r = sshbuf_check_reserve(oqueue, MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ)) == 0)
			process();
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_NO_ಬಫರ್_SPACE)
			fatal_fr(r, "reserve");
	}
}
#ಇಲ್ಲದಿದ್ದರೆ /* ENABLE_PKCS11 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
