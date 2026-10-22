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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "ssh-pkcs11.h"
#அந்தர்பாவ "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

நிலையான எழுத்து *providername; /* Provider for this helper */

#define MAX_செய்தி_LENGTH		10240 /*XXX*/

/* input and output queue */
கட்டமைப்பு sshbuf *iqueue;
கட்டமைப்பு sshbuf *oqueue;

நிலையான வெறுமை
send_செய்தி(கட்டமைப்பு sshbuf *m)
{
	முழு r;

	எனில் ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

நிலையான வெறுமை
process_add(வெறுமை)
{
	எழுத்து *pin;
	கட்டமைப்பு sshkey **சாவிகள் = வெற்று;
	முழு r, i, nkeys;
	கட்டமைப்பு sshbuf *செய்தி;
	எழுத்து **labels = வெற்று;

	எனில் (providername != வெற்று)
		fatal_f("provider already set");
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_get_cstring(iqueue, &providername, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, வெற்று)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	எனில் ((nkeys = pkcs11_add_provider(providername, pin,
	    &சாவிகள், &labels)) > 0) {
		எனில் ((r = sshbuf_put_u8(செய்தி,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(செய்தி, nkeys)) != 0)
			fatal_fr(r, "compose");
		க்கு (i = 0; i < nkeys; i++) {
			எனில் ((r = sshkey_puts(சாவிகள்[i], செய்தி)) != 0 ||
			    (r = sshbuf_put_cstring(செய்தி, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(சாவிகள்[i]), labels[i]);
			விடுவி(labels[i]);
		}
	} இல்லையெனில் எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, -nkeys)) != 0)
		fatal_fr(r, "compose");
	விடுவி(labels);
	விடுவி(சாவிகள்); /* keys themselves are transferred to pkcs11_keylist */
	விடுவி(pin);
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
process_sign(வெறுமை)
{
	மாறிலி u_char *data;
	u_char *signature = வெற்று;
	size_t dlen, slen = 0;
	u_int compat;
	முழு r, ok = -1;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *செய்தி;
	எழுத்து *alg = வெற்று;

	எனில் ((r = sshkey_froms(iqueue, &சாவி)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	எனில் (*alg == '\0') {
		விடுவி(alg);
		alg = வெற்று;
	}

	எனில் ((r = pkcs11_sign(சாவி, &signature, &slen, data, dlen,
	    alg, வெற்று, வெற்று, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(சாவி));
		செல் reply;
	}

	/* success */
	ok = 0;
 reply:
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் (ok == 0) {
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(செய்தி, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} இல்லையெனில் {
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(சாவி);
	விடுவி(alg);
	விடுவி(signature);
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
process(வெறுமை)
{
	u_int செய்தி_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	மாறிலி u_char *cp;
	முழு r;

	buf_len = sshbuf_len(iqueue);
	எனில் (buf_len < 5)
		திரும்பு;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	செய்தி_len = get_u32(cp);
	எனில் (செய்தி_len > MAX_செய்தி_LENGTH) {
		error("bad message len %d", செய்தி_len);
		cleanup_exit(11);
	}
	எனில் (buf_len < செய்தி_len + 4)
		திரும்பு;
	எனில் ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	தேர்வு (type) {
	நிலை SSH_AGENTC_ADD_SMARTCARD_சாவி:
		debug("process_add");
		process_add();
		நிறுத்து;
	நிலை SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		நிறுத்து;
	இயல்பு:
		error("Unknown message %d", type);
		நிறுத்து;
	}
	/* discard the remaining bytes from the current packet */
	எனில் (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	எனில் (செய்தி_len < consumed) {
		error("msg_len %d < consumed %d", செய்தி_len, consumed);
		cleanup_exit(255);
	}
	எனில் (செய்தி_len > consumed) {
		எனில் ((r = sshbuf_consume(iqueue, செய்தி_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

வெறுமை
cleanup_exit(முழு i)
{
	/* XXX */
	_exit(i);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	எழுத்து buf[4*4096];
	வெளி எழுத்து *__progname;
	கட்டமைப்பு pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	போது ((ch = getopt(argc, argv, "v")) != -1) {
		தேர்வு (ch) {
		நிலை 'v':
			log_stderr = 1;
			எனில் (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			நிறுத்து;
		இயல்பு:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	எனில் ((iqueue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((oqueue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	போது (1) {
		memset(pfd, 0, அளவு(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		எனில் ((r = sshbuf_check_reserve(iqueue, அளவு(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_செய்தி_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		இல்லையெனில் எனில் (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		எனில் (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		எனில் ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			எனில் (r == 0 || errno == EINTR)
				தொடர்;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		எனில் ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = பட(in, buf, அளவு buf);
			எனில் (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} இல்லையெனில் எனில் (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} இல்லையெனில் எனில் ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		எனில் ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = லிக(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			எனில் (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} இல்லையெனில் எனில் ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		எனில் ((r = sshbuf_check_reserve(oqueue, MAX_செய்தி_LENGTH)) == 0)
			process();
		இல்லையெனில் எனில் (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#இல்லையெனில் /* ENABLE_PKCS11 */
முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	வெளி எழுத்து *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
