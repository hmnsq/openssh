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

#که_تعریف_شوی ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ساكن حرف *providername; /* Provider for this helper */

#تعریف_کړه MAX_پیغام_اوږدتیا		10240 /*XXX*/

/* input and output queue */
بنية sshbuf *iqueue;
بنية sshbuf *oqueue;

ساكن فراغ
send_پیغام(بنية sshbuf *m)
{
	صحيح r;

	إذا ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ساكن فراغ
process_جمع_کړه(فراغ)
{
	حرف *pin;
	بنية sshkey **کلیګانې = عدم;
	صحيح r, i, nkeys;
	بنية sshbuf *پیغام;
	حرف **labels = عدم;

	إذا (providername != عدم)
		fatal_f("provider already set");
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_get_cstring(iqueue, &providername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, عدم)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	إذا ((nkeys = pkcs11_جمع_کړه_provider(providername, pin,
	    &کلیګانې, &labels)) > 0) {
		إذا ((r = sshbuf_put_u8(پیغام,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, nkeys)) != 0)
			fatal_fr(r, "compose");
		لكل (i = 0; i < nkeys; i++) {
			إذا ((r = sshkey_puts(کلیګانې[i], پیغام)) != 0 ||
			    (r = sshbuf_put_cstring(پیغام, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(کلیګانې[i]), labels[i]);
			حرر(labels[i]);
		}
	} وإلا إذا ((r = sshbuf_put_u8(پیغام, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, -nkeys)) != 0)
		fatal_fr(r, "compose");
	حرر(labels);
	حرر(کلیګانې); /* keys themselves are transferred to pkcs11_keylist */
	حرر(pin);
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساكن فراغ
process_sign(فراغ)
{
	ثابت u_char *معلومات;
	u_char *signature = عدم;
	اندازه_t dlen, slen = 0;
	u_int compat;
	صحيح r, ok = -1;
	بنية sshkey *کلی = عدم;
	بنية sshbuf *پیغام;
	حرف *alg = عدم;

	إذا ((r = sshkey_froms(iqueue, &کلی)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(iqueue, &معلومات, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, عدم)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	إذا (*alg == '\0') {
		حرر(alg);
		alg = عدم;
	}

	إذا ((r = pkcs11_sign(کلی, &signature, &slen, معلومات, dlen,
	    alg, عدم, عدم, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(کلی));
		اذهب ځواب;
	}

	/* success */
	ok = 0;
 ځواب:
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا (ok == 0) {
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیغام, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} وإلا {
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(کلی);
	حرر(alg);
	حرر(signature);
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساكن فراغ
process(فراغ)
{
	u_int پیغام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحيح r;

	buf_len = sshbuf_len(iqueue);
	إذا (buf_len < 5)
		أرجع;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیغام_len = get_u32(cp);
	إذا (پیغام_len > MAX_پیغام_اوږدتیا) {
		error("bad message len %d", پیغام_len);
		cleanup_exit(11);
	}
	إذا (buf_len < پیغام_len + 4)
		أرجع;
	إذا ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	بدل (type) {
	حالة SSH_AGENTC_جمع_کړه_SMARTCARD_کلی:
		debug("process_add");
		process_جمع_کړه();
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
	إذا (پیغام_len < consumed) {
		error("msg_len %d < consumed %d", پیغام_len, consumed);
		cleanup_exit(255);
	}
	إذا (پیغام_len > consumed) {
		إذا ((r = sshbuf_consume(iqueue, پیغام_len - consumed)) != 0)
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
اصلي(صحيح argc, حرف **argv)
{
	صحيح r, ch, دننه, بهر, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	حرف buf[4*4096];
	خارجي حرف *__progname;
	بنية pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	تخم_rng();

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
			وتل(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	دننه = STDIN_FILENO;
	بهر = STDOUT_FILENO;

	إذا ((iqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((oqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	طالما (1) {
		memset(pfd, 0, حجم(pfd));
		pfd[0].fd = دننه;
		pfd[1].fd = بهر;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		إذا ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_پیغام_اوږدتیا)) == 0)
			pfd[0].events = POLLIN;
		وإلا إذا (r != SSH_ERR_NO_بفر_SPACE)
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
			len = اقرأ(دننه, buf, حجم buf);
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
			len = اكتب(بهر, sshbuf_ptr(oqueue),
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
		إذا ((r = sshbuf_check_reserve(oqueue, MAX_پیغام_اوږدتیا)) == 0)
			process();
		وإلا إذا (r != SSH_ERR_NO_بفر_SPACE)
			fatal_fr(r, "reserve");
	}
}
#وإلا /* ENABLE_PKCS11 */
صحيح
اصلي(صحيح argc, حرف **argv)
{
	خارجي حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#د_که_پای /* ENABLE_PKCS11 */
