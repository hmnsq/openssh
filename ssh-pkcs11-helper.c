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

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ಸ್ಥಿರ ವರ್ಣ *providername; /* Provider for this helper */

#define MAX_ಸಂದೇಶ_LENGTH		10240 /*XXX*/

/* input and output queue */
ಸಂರಚನಾ sshbuf *iqueue;
ಸಂರಚನಾ sshbuf *oqueue;

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_add(ಶೂನ್ಯ)
{
	ವರ್ಣ *pin;
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, i, nkeys;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ವರ್ಣ **labels = ರಿಕ್ತ;

	ಯದಿ (providername != ರಿಕ್ತ)
		fatal_f("provider already set");
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &providername, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ಯದಿ ((nkeys = pkcs11_add_provider(providername, pin,
	    &ಕೀಲಿಗಳು, &labels)) > 0) {
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, nkeys)) != 0)
			fatal_fr(r, "compose");
		ಪ್ರತಿ (i = 0; i < nkeys; i++) {
			ಯದಿ ((r = sshkey_puts(ಕೀಲಿಗಳು[i], ಸಂದೇಶ)) != 0 ||
			    (r = sshbuf_put_cstring(ಸಂದೇಶ, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(ಕೀಲಿಗಳು[i]), labels[i]);
			ಮುಕ್ತ(labels[i]);
		}
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, -nkeys)) != 0)
		fatal_fr(r, "compose");
	ಮುಕ್ತ(labels);
	ಮುಕ್ತ(ಕೀಲಿಗಳು); /* keys themselves are transferred to pkcs11_keylist */
	ಮುಕ್ತ(pin);
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_sign(ಶೂನ್ಯ)
{
	ಧ್ರುವ u_char *data;
	u_char *signature = ರಿಕ್ತ;
	size_t dlen, slen = 0;
	u_int compat;
	ಪೂರ್ಣಾಙ್ಕ r, ok = -1;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ವರ್ಣ *alg = ರಿಕ್ತ;

	ಯದಿ ((r = sshkey_froms(iqueue, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (*alg == '\0') {
		ಮುಕ್ತ(alg);
		alg = ರಿಕ್ತ;
	}

	ಯದಿ ((r = pkcs11_sign(ಕೀಲಿ, &signature, &slen, data, dlen,
	    alg, ರಿಕ್ತ, ರಿಕ್ತ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(ಕೀಲಿ));
		ಗಚ್ಛ reply;
	}

	/* success */
	ok = 0;
 reply:
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ (ok == 0) {
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(ಕೀಲಿ);
	ಮುಕ್ತ(alg);
	ಮುಕ್ತ(signature);
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
	ಧ್ರುವ u_char *cp;
	ಪೂರ್ಣಾಙ್ಕ r;

	buf_len = sshbuf_len(iqueue);
	ಯದಿ (buf_len < 5)
		ಪ್ರತ್ಯಾಗಮ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ಸಂದೇಶ_len = get_u32(cp);
	ಯದಿ (ಸಂದೇಶ_len > MAX_ಸಂದೇಶ_LENGTH) {
		error("bad message len %d", ಸಂದೇಶ_len);
		cleanup_exit(11);
	}
	ಯದಿ (buf_len < ಸಂದೇಶ_len + 4)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ:
		debug("process_add");
		process_add();
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error("Unknown message %d", type);
		ಭಙ್ಗ;
	}
	/* discard the remaining bytes from the current packet */
	ಯದಿ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ಯದಿ (ಸಂದೇಶ_len < consumed) {
		error("msg_len %d < consumed %d", ಸಂದೇಶ_len, consumed);
		cleanup_exit(255);
	}
	ಯದಿ (ಸಂದೇಶ_len > consumed) {
		ಯದಿ ((r = sshbuf_consume(iqueue, ಸಂದೇಶ_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	/* XXX */
	_exit(i);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ವರ್ಣ buf[4*4096];
	ಬಾಹ್ಯ ವರ್ಣ *__progname;
	ಸಂರಚನಾ pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ಯಾವತ್ ((ch = getopt(argc, argv, "v")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'v':
			log_stderr = 1;
			ಯದಿ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	ಯದಿ ((iqueue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((oqueue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯಾವತ್ (1) {
		memset(pfd, 0, ಪರಿಮಾಣ(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ಯದಿ ((r = sshbuf_check_reserve(iqueue, ಪರಿಮಾಣ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_ಸಂದೇಶ_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		ಯದಿ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ಯದಿ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ಯದಿ (r == 0 || errno == EINTR)
				ಅನುವರ್ತ;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ಯದಿ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = ಪಠ(in, buf, ಪರಿಮಾಣ buf);
			ಯದಿ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} ಅನ್ಯಥಾ ಯದಿ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ಯದಿ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ಲಿಖ(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ಯದಿ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ಯದಿ ((r = sshbuf_check_reserve(oqueue, MAX_ಸಂದೇಶ_LENGTH)) == 0)
			process();
		ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#ಅನ್ಯಥಾ /* ENABLE_PKCS11 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಬಾಹ್ಯ ವರ್ಣ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
