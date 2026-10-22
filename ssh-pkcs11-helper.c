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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/time.h>

#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <poll.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "ssh-pkcs11.h"
#ضمن "ssherr.h"

#اگر_تعریف_شده ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ساكن حرف *providername; /* Provider for this helper */

#تعریف_کن MAX_پیام_درازی		10240 /*XXX*/

/* input and output queue */
بنية sshbuf *iqueue;
بنية sshbuf *oqueue;

ساكن فراغ
send_پیام(بنية sshbuf *m)
{
	صحيح r;

	إذا ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ساكن فراغ
process_جمع_کن(فراغ)
{
	حرف *pin;
	بنية sshkey **کلیدها = عدم;
	صحيح r, i, nkeys;
	بنية sshbuf *پیام;
	حرف **labels = عدم;

	إذا (providername != عدم)
		fatal_f("provider already set");
	إذا ((پیام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_get_cstring(iqueue, &providername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, عدم)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	إذا ((nkeys = pkcs11_جمع_کن_provider(providername, pin,
	    &کلیدها, &labels)) > 0) {
		إذا ((r = sshbuf_put_u8(پیام,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(پیام, nkeys)) != 0)
			fatal_fr(r, "compose");
		لكل (i = 0; i < nkeys; i++) {
			إذا ((r = sshkey_puts(کلیدها[i], پیام)) != 0 ||
			    (r = sshbuf_put_cstring(پیام, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(کلیدها[i]), labels[i]);
			حرر(labels[i]);
		}
	} وإلا إذا ((r = sshbuf_put_u8(پیام, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(پیام, -nkeys)) != 0)
		fatal_fr(r, "compose");
	حرر(labels);
	حرر(کلیدها); /* keys themselves are transferred to pkcs11_keylist */
	حرر(pin);
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ساكن فراغ
process_sign(فراغ)
{
	ثابت u_char *داده;
	u_char *signature = عدم;
	اندازه_t dlen, slen = 0;
	u_int compat;
	صحيح r, ok = -1;
	بنية sshkey *کلید = عدم;
	بنية sshbuf *پیام;
	حرف *alg = عدم;

	إذا ((r = sshkey_froms(iqueue, &کلید)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(iqueue, &داده, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, عدم)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	إذا (*alg == '\0') {
		حرر(alg);
		alg = عدم;
	}

	إذا ((r = pkcs11_sign(کلید, &signature, &slen, داده, dlen,
	    alg, عدم, عدم, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(کلید));
		اذهب پاسخ;
	}

	/* success */
	ok = 0;
 پاسخ:
	إذا ((پیام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا (ok == 0) {
		إذا ((r = sshbuf_put_u8(پیام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیام, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} وإلا {
		إذا ((r = sshbuf_put_u8(پیام, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(کلید);
	حرر(alg);
	حرر(signature);
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ساكن فراغ
process(فراغ)
{
	u_int پیام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحيح r;

	buf_len = sshbuf_len(iqueue);
	إذا (buf_len < 5)
		أرجع;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیام_len = get_u32(cp);
	إذا (پیام_len > MAX_پیام_درازی) {
		error("bad message len %d", پیام_len);
		cleanup_exit(11);
	}
	إذا (buf_len < پیام_len + 4)
		أرجع;
	إذا ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	بدل (type) {
	حالة SSH_AGENTC_جمع_کن_SMARTCARD_کلید:
		debug("process_add");
		process_جمع_کن();
		اكسر;
	حالة SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		اكسر;
	افتراضي:
		error("Unknown message %d", type);
		اكسر;
	}
	/* discard the remaining bytes from the current packet */
	إذا (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	إذا (پیام_len < consumed) {
		error("msg_len %d < consumed %d", پیام_len, consumed);
		cleanup_exit(255);
	}
	إذا (پیام_len > consumed) {
		إذا ((r = sshbuf_consume(iqueue, پیام_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

فراغ
cleanup_exit(صحيح i)
{
	/* XXX */
	_exit(i);
}

صحيح
اصلی(صحيح argc, حرف **argv)
{
	صحيح r, ch, درون, بیرون, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	حرف buf[4*4096];
	خارجي حرف *__progname;
	بنية pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	دانه_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	طالما ((ch = getopt(argc, argv, "v")) != -1) {
		بدل (ch) {
		حالة 'v':
			log_stderr = 1;
			إذا (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			اكسر;
		افتراضي:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			خروج(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	درون = STDIN_FILENO;
	بیرون = STDOUT_FILENO;

	إذا ((iqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((oqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	طالما (1) {
		memset(pfd, 0, حجم(pfd));
		pfd[0].fd = درون;
		pfd[1].fd = بیرون;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		إذا ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_پیام_درازی)) == 0)
			pfd[0].events = POLLIN;
		وإلا إذا (r != SSH_ERR_NO_میانگیر_SPACE)
			fatal_fr(r, "reserve");

		إذا (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		إذا ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			إذا (r == 0 || errno == EINTR)
				استمر;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		إذا ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = اقرأ(درون, buf, حجم buf);
			إذا (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} وإلا إذا (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} وإلا إذا ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		إذا ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = اكتب(بیرون, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			إذا (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} وإلا إذا ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		إذا ((r = sshbuf_check_reserve(oqueue, MAX_پیام_درازی)) == 0)
			process();
		وإلا إذا (r != SSH_ERR_NO_میانگیر_SPACE)
			fatal_fr(r, "reserve");
	}
}
#وإلا /* ENABLE_PKCS11 */
صحيح
اصلی(صحيح argc, حرف **argv)
{
	خارجي حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#پایان_اگر /* ENABLE_PKCS11 */
