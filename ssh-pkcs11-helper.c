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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/time.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <poll.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "ssh-pkcs11.h"
#شامل "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ایستا نویسه *providername; /* Provider for this helper */

#define MAX_پیام_LENGTH		10240 /*XXX*/

/* input and output queue */
ساختار sshbuf *iqueue;
ساختار sshbuf *oqueue;

ایستا تهی
send_پیام(ساختار sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ایستا تهی
process_add(تهی)
{
	نویسه *pin;
	ساختار sshkey **کلیدها = پوچ;
	صحیح r, i, nkeys;
	ساختار sshbuf *پیام;
	نویسه **labels = پوچ;

	اگر (providername != پوچ)
		fatal_f("provider already set");
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_get_cstring(iqueue, &providername, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, پوچ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	اگر ((nkeys = pkcs11_add_provider(providername, pin,
	    &کلیدها, &labels)) > 0) {
		اگر ((r = sshbuf_put_u8(پیام,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(پیام, nkeys)) != 0)
			fatal_fr(r, "compose");
		برای (i = 0; i < nkeys; i++) {
			اگر ((r = sshkey_puts(کلیدها[i], پیام)) != 0 ||
			    (r = sshbuf_put_cstring(پیام, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(کلیدها[i]), labels[i]);
			آزاد(labels[i]);
		}
	} وگرنه اگر ((r = sshbuf_put_u8(پیام, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(پیام, -nkeys)) != 0)
		fatal_fr(r, "compose");
	آزاد(labels);
	آزاد(کلیدها); /* keys themselves are transferred to pkcs11_keylist */
	آزاد(pin);
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
process_sign(تهی)
{
	ثابت u_char *data;
	u_char *signature = پوچ;
	size_t dlen, slen = 0;
	u_int compat;
	صحیح r, ok = -1;
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *پیام;
	نویسه *alg = پوچ;

	اگر ((r = sshkey_froms(iqueue, &کلید)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	اگر (*alg == '\0') {
		آزاد(alg);
		alg = پوچ;
	}

	اگر ((r = pkcs11_sign(کلید, &signature, &slen, data, dlen,
	    alg, پوچ, پوچ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(کلید));
		برو reply;
	}

	/* success */
	ok = 0;
 reply:
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر (ok == 0) {
		اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیام, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} وگرنه {
		اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(کلید);
	آزاد(alg);
	آزاد(signature);
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
process(تهی)
{
	u_int پیام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحیح r;

	buf_len = sshbuf_len(iqueue);
	اگر (buf_len < 5)
		بازگشت;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیام_len = get_u32(cp);
	اگر (پیام_len > MAX_پیام_LENGTH) {
		error("bad message len %d", پیام_len);
		cleanup_exit(11);
	}
	اگر (buf_len < پیام_len + 4)
		بازگشت;
	اگر ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	انتخاب (type) {
	حالت SSH_AGENTC_ADD_SMARTCARD_کلید:
		debug("process_add");
		process_add();
		بشکن;
	حالت SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		بشکن;
	پیشفرض:
		error("Unknown message %d", type);
		بشکن;
	}
	/* discard the remaining bytes from the current packet */
	اگر (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	اگر (پیام_len < consumed) {
		error("msg_len %d < consumed %d", پیام_len, consumed);
		cleanup_exit(255);
	}
	اگر (پیام_len > consumed) {
		اگر ((r = sshbuf_consume(iqueue, پیام_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

تهی
cleanup_exit(صحیح i)
{
	/* XXX */
	_exit(i);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	نویسه buf[4*4096];
	بیرونی نویسه *__progname;
	ساختار pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	وقتی ((ch = getopt(argc, argv, "v")) != -1) {
		انتخاب (ch) {
		حالت 'v':
			log_stderr = 1;
			اگر (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			بشکن;
		پیشفرض:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	اگر ((iqueue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((oqueue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	وقتی (1) {
		memset(pfd, 0, اندازه(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		اگر ((r = sshbuf_check_reserve(iqueue, اندازه(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_پیام_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		وگرنه اگر (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		اگر (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		اگر ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			اگر (r == 0 || errno == EINTR)
				ادامه;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		اگر ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = اقرأ(in, buf, اندازه buf);
			اگر (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} وگرنه اگر (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} وگرنه اگر ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		اگر ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = اكتب(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			اگر (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} وگرنه اگر ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		اگر ((r = sshbuf_check_reserve(oqueue, MAX_پیام_LENGTH)) == 0)
			process();
		وگرنه اگر (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#وگرنه /* ENABLE_PKCS11 */
صحیح
اصلی(صحیح argc, نویسه **argv)
{
	بیرونی نویسه *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
