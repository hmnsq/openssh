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

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ساكن حرف *providername; /* Provider for this helper */

#define MAX_MSG_LENGTH		10240 /*XXX*/

/* input and output queue */
بنية sshbuf *iqueue;
بنية sshbuf *oqueue;

ساكن فراغ
send_msg(بنية sshbuf *m)
{
	صحيح r;

	אם ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ساكن فراغ
process_add(فراغ)
{
	حرف *pin;
	بنية sshkey **keys = عدم;
	صحيح r, i, nkeys;
	بنية sshbuf *msg;
	حرف **labels = عدم;

	אם (providername != عدم)
		fatal_f("provider already set");
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_get_cstring(iqueue, &providername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, عدم)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	אם ((nkeys = pkcs11_add_provider(providername, pin,
	    &keys, &labels)) > 0) {
		אם ((r = sshbuf_put_u8(msg,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(msg, nkeys)) != 0)
			fatal_fr(r, "compose");
		עבור (i = 0; i < nkeys; i++) {
			אם ((r = sshkey_puts(keys[i], msg)) != 0 ||
			    (r = sshbuf_put_cstring(msg, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(keys[i]), labels[i]);
			حرر(labels[i]);
		}
	} אחרת אם ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(msg, -nkeys)) != 0)
		fatal_fr(r, "compose");
	حرر(labels);
	حرر(keys); /* keys themselves are transferred to pkcs11_keylist */
	حرر(pin);
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
process_sign(فراغ)
{
	ثابت u_char *data;
	u_char *signature = عدم;
	size_t dlen, slen = 0;
	u_int compat;
	صحيح r, ok = -1;
	بنية sshkey *key = عدم;
	بنية sshbuf *msg;
	حرف *alg = عدم;

	אם ((r = sshkey_froms(iqueue, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, عدم)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	אם (*alg == '\0') {
		حرر(alg);
		alg = عدم;
	}

	אם ((r = pkcs11_sign(key, &signature, &slen, data, dlen,
	    alg, عدم, عدم, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(key));
		اذهب reply;
	}

	/* success */
	ok = 0;
 reply:
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם (ok == 0) {
		אם ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} אחרת {
		אם ((r = sshbuf_put_u8(msg, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(key);
	حرر(alg);
	حرر(signature);
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
process(فراغ)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحيح r;

	buf_len = sshbuf_len(iqueue);
	אם (buf_len < 5)
		החזר;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	אם (msg_len > MAX_MSG_LENGTH) {
		error("bad message len %d", msg_len);
		cleanup_exit(11);
	}
	אם (buf_len < msg_len + 4)
		החזר;
	אם ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	بدل (type) {
	حالة SSH_AGENTC_ADD_SMARTCARD_KEY:
		debug("process_add");
		process_add();
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
	אם (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	אם (msg_len < consumed) {
		error("msg_len %d < consumed %d", msg_len, consumed);
		cleanup_exit(255);
	}
	אם (msg_len > consumed) {
		אם ((r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
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
main(صحيح argc, حرف **argv)
{
	صحيح r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	حرف buf[4*4096];
	خارجي حرف *__progname;
	بنية pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	כלעוד ((ch = getopt(argc, argv, "v")) != -1) {
		بدل (ch) {
		حالة 'v':
			log_stderr = 1;
			אם (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			אחרת אם (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			اكسر;
		افتراضي:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	אם ((iqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((oqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	כלעוד (1) {
		memset(pfd, 0, حجم(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		אם ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_MSG_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		אחרת אם (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		אם (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		אם ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			אם (r == 0 || errno == EINTR)
				استمر;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		אם ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = اقرأ(in, buf, حجم buf);
			אם (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} אחרת אם (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} אחרת אם ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		אם ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = اكتب(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			אם (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} אחרת אם ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		אם ((r = sshbuf_check_reserve(oqueue, MAX_MSG_LENGTH)) == 0)
			process();
		אחרת אם (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#אחרת /* ENABLE_PKCS11 */
صحيح
main(صحيح argc, حرف **argv)
{
	خارجي حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
