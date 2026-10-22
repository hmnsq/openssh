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

#اگر_تعریف_شدہ ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ساکن حرف *providername; /* Provider for this helper */

#تعریف_کرو MAX_پیغام_لمبائی		10240 /*XXX*/

/* input and output queue */
ساخت sshbuf *iqueue;
ساخت sshbuf *oqueue;

ساکن خالی
send_پیغام(ساخت sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ساکن خالی
process_جوڑو(خالی)
{
	حرف *pin;
	ساخت sshkey **کلیدیں = تہی;
	صحیح r, i, nkeys;
	ساخت sshbuf *پیغام;
	حرف **labels = تہی;

	اگر (providername != تہی)
		fatal_f("provider already set");
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_get_cstring(iqueue, &providername, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, تہی)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	اگر ((nkeys = pkcs11_جوڑو_provider(providername, pin,
	    &کلیدیں, &labels)) > 0) {
		اگر ((r = sshbuf_put_u8(پیغام,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, nkeys)) != 0)
			fatal_fr(r, "compose");
		برائے (i = 0; i < nkeys; i++) {
			اگر ((r = sshkey_puts(کلیدیں[i], پیغام)) != 0 ||
			    (r = sshbuf_put_cstring(پیغام, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(کلیدیں[i]), labels[i]);
			آزاد(labels[i]);
		}
	} ورنہ اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, -nkeys)) != 0)
		fatal_fr(r, "compose");
	آزاد(labels);
	آزاد(کلیدیں); /* keys themselves are transferred to pkcs11_keylist */
	آزاد(pin);
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
process_sign(خالی)
{
	ثابت u_char *ڈیٹا;
	u_char *signature = تہی;
	سائز_t dlen, slen = 0;
	u_int compat;
	صحیح r, ok = -1;
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *پیغام;
	حرف *alg = تہی;

	اگر ((r = sshkey_froms(iqueue, &کلید)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(iqueue, &ڈیٹا, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, تہی)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	اگر (*alg == '\0') {
		آزاد(alg);
		alg = تہی;
	}

	اگر ((r = pkcs11_sign(کلید, &signature, &slen, ڈیٹا, dlen,
	    alg, تہی, تہی, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(کلید));
		جاؤ جواب;
	}

	/* success */
	ok = 0;
 جواب:
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر (ok == 0) {
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیغام, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} ورنہ {
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(کلید);
	آزاد(alg);
	آزاد(signature);
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
process(خالی)
{
	u_int پیغام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحیح r;

	buf_len = sshbuf_len(iqueue);
	اگر (buf_len < 5)
		واپس;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیغام_len = get_u32(cp);
	اگر (پیغام_len > MAX_پیغام_لمبائی) {
		error("bad message len %d", پیغام_len);
		cleanup_exit(11);
	}
	اگر (buf_len < پیغام_len + 4)
		واپس;
	اگر ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	انتخاب (type) {
	حالت SSH_AGENTC_جوڑو_SMARTCARD_کلید:
		debug("process_add");
		process_جوڑو();
		توڑو;
	حالت SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		توڑو;
	طےشدہ:
		error("Unknown message %d", type);
		توڑو;
	}
	/* discard the remaining bytes from the current packet */
	اگر (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	اگر (پیغام_len < consumed) {
		error("msg_len %d < consumed %d", پیغام_len, consumed);
		cleanup_exit(255);
	}
	اگر (پیغام_len > consumed) {
		اگر ((r = sshbuf_consume(iqueue, پیغام_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

خالی
cleanup_exit(صحیح i)
{
	/* XXX */
	_exit(i);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح r, ch, اندر, برآمد, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	حرف buf[4*4096];
	خارجی حرف *__progname;
	ساخت pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	بیج_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	جب ((ch = getopt(argc, argv, "v")) != -1) {
		انتخاب (ch) {
		حالت 'v':
			log_stderr = 1;
			اگر (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ورنہ اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			توڑو;
		طےشدہ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			باہر_نکلو(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	اندر = STDIN_FILENO;
	برآمد = STDOUT_FILENO;

	اگر ((iqueue = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((oqueue = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	جب (1) {
		memset(pfd, 0, حجم(pfd));
		pfd[0].fd = اندر;
		pfd[1].fd = برآمد;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		اگر ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_پیغام_لمبائی)) == 0)
			pfd[0].events = POLLIN;
		ورنہ اگر (r != SSH_ERR_NO_بفر_SPACE)
			fatal_fr(r, "reserve");

		اگر (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		اگر ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			اگر (r == 0 || errno == EINTR)
				جاری;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		اگر ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = اقرأ(اندر, buf, حجم buf);
			اگر (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} ورنہ اگر (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} ورنہ اگر ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		اگر ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = اكتب(برآمد, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			اگر (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} ورنہ اگر ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		اگر ((r = sshbuf_check_reserve(oqueue, MAX_پیغام_لمبائی)) == 0)
			process();
		ورنہ اگر (r != SSH_ERR_NO_بفر_SPACE)
			fatal_fr(r, "reserve");
	}
}
#ورنہ /* ENABLE_PKCS11 */
صحیح
مین(صحیح argc, حرف **argv)
{
	خارجی حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#اگر_ختم /* ENABLE_PKCS11 */
