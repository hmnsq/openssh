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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "ssh-pkcs11.h"
#অন্তর্ভাব "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

স্থির বর্ণ *providername; /* Provider for this helper */

#define MAX_বার্তা_LENGTH		10240 /*XXX*/

/* input and output queue */
সংরচনা sshbuf *iqueue;
সংরচনা sshbuf *oqueue;

স্থির শূন্য
send_বার্তা(সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

স্থির শূন্য
process_add(শূন্য)
{
	বর্ণ *pin;
	সংরচনা sshkey **চাবিগুলি = রিক্ত;
	পূর্ণাঙ্ক r, i, nkeys;
	সংরচনা sshbuf *বার্তা;
	বর্ণ **labels = রিক্ত;

	যদি (providername != রিক্ত)
		fatal_f("provider already set");
	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_get_cstring(iqueue, &providername, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	যদি ((nkeys = pkcs11_add_provider(providername, pin,
	    &চাবিগুলি, &labels)) > 0) {
		যদি ((r = sshbuf_put_u8(বার্তা,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(বার্তা, nkeys)) != 0)
			fatal_fr(r, "compose");
		প্রতি (i = 0; i < nkeys; i++) {
			যদি ((r = sshkey_puts(চাবিগুলি[i], বার্তা)) != 0 ||
			    (r = sshbuf_put_cstring(বার্তা, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(চাবিগুলি[i]), labels[i]);
			মুক্ত(labels[i]);
		}
	} অন্যথা যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, -nkeys)) != 0)
		fatal_fr(r, "compose");
	মুক্ত(labels);
	মুক্ত(চাবিগুলি); /* keys themselves are transferred to pkcs11_keylist */
	মুক্ত(pin);
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
process_sign(শূন্য)
{
	ধ্রুব u_char *data;
	u_char *signature = রিক্ত;
	size_t dlen, slen = 0;
	u_int compat;
	পূর্ণাঙ্ক r, ok = -1;
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshbuf *বার্তা;
	বর্ণ *alg = রিক্ত;

	যদি ((r = sshkey_froms(iqueue, &চাবি)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	যদি (*alg == '\0') {
		মুক্ত(alg);
		alg = রিক্ত;
	}

	যদি ((r = pkcs11_sign(চাবি, &signature, &slen, data, dlen,
	    alg, রিক্ত, রিক্ত, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(চাবি));
		গচ্ছ reply;
	}

	/* success */
	ok = 0;
 reply:
	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি (ok == 0) {
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(বার্তা, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} অন্যথা {
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(চাবি);
	মুক্ত(alg);
	মুক্ত(signature);
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
process(শূন্য)
{
	u_int বার্তা_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ধ্রুব u_char *cp;
	পূর্ণাঙ্ক r;

	buf_len = sshbuf_len(iqueue);
	যদি (buf_len < 5)
		প্রত্যাগম;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	বার্তা_len = get_u32(cp);
	যদি (বার্তা_len > MAX_বার্তা_LENGTH) {
		error("bad message len %d", বার্তা_len);
		cleanup_exit(11);
	}
	যদি (buf_len < বার্তা_len + 4)
		প্রত্যাগম;
	যদি ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	বিকল্প (type) {
	পক্ষ SSH_AGENTC_ADD_SMARTCARD_চাবি:
		debug("process_add");
		process_add();
		ভঙ্গ;
	পক্ষ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ভঙ্গ;
	স্বভাব:
		error("Unknown message %d", type);
		ভঙ্গ;
	}
	/* discard the remaining bytes from the current packet */
	যদি (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	যদি (বার্তা_len < consumed) {
		error("msg_len %d < consumed %d", বার্তা_len, consumed);
		cleanup_exit(255);
	}
	যদি (বার্তা_len > consumed) {
		যদি ((r = sshbuf_consume(iqueue, বার্তা_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

শূন্য
cleanup_exit(পূর্ণাঙ্ক i)
{
	/* XXX */
	_exit(i);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	পূর্ণাঙ্ক r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	বর্ণ buf[4*4096];
	বাহ্য বর্ণ *__progname;
	সংরচনা pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	যাবত্ ((ch = getopt(argc, argv, "v")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'v':
			log_stderr = 1;
			যদি (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ভঙ্গ;
		স্বভাব:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	যদি ((iqueue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((oqueue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	যাবত্ (1) {
		memset(pfd, 0, পরিমাণ(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		যদি ((r = sshbuf_check_reserve(iqueue, পরিমাণ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_বার্তা_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		অন্যথা যদি (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		যদি (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		যদি ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			যদি (r == 0 || errno == EINTR)
				অনুবর্ত;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		যদি ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = পঠ(in, buf, পরিমাণ buf);
			যদি (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} অন্যথা যদি (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} অন্যথা যদি ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		যদি ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = লিখ(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			যদি (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} অন্যথা যদি ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		যদি ((r = sshbuf_check_reserve(oqueue, MAX_বার্তা_LENGTH)) == 0)
			process();
		অন্যথা যদি (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#অন্যথা /* ENABLE_PKCS11 */
পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	বাহ্য বর্ণ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
