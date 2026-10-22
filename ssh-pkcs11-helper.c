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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "ssh-pkcs11.h"
#అన్తర్భావ "ssherr.h"

#నిర్వచితమైతే ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

స్థిర అక్షరం *providername; /* Provider for this helper */

#నిర్వచించు MAX_సందేశం_నిడివి		10240 /*XXX*/

/* input and output queue */
నిర్మాణం sshbuf *iqueue;
నిర్మాణం sshbuf *oqueue;

స్థిర శూన్య
send_సందేశం(నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

స్థిర శూన్య
process_కూడు(శూన్య)
{
	అక్షరం *pin;
	నిర్మాణం sshkey **కీలకాలు = ఖాళీ;
	పూర్ణాంకం r, i, nkeys;
	నిర్మాణం sshbuf *సందేశం;
	అక్షరం **labels = ఖాళీ;

	ఒకవేళ (providername != ఖాళీ)
		fatal_f("provider already set");
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &providername, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ఒకవేళ ((nkeys = pkcs11_కూడు_provider(providername, pin,
	    &కీలకాలు, &labels)) > 0) {
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(సందేశం, nkeys)) != 0)
			fatal_fr(r, "compose");
		కొరకు (i = 0; i < nkeys; i++) {
			ఒకవేళ ((r = sshkey_puts(కీలకాలు[i], సందేశం)) != 0 ||
			    (r = sshbuf_put_cstring(సందేశం, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(కీలకాలు[i]), labels[i]);
			విడుదల(labels[i]);
		}
	} లేకపోతే ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, -nkeys)) != 0)
		fatal_fr(r, "compose");
	విడుదల(labels);
	విడుదల(కీలకాలు); /* keys themselves are transferred to pkcs11_keylist */
	విడుదల(pin);
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
process_sign(శూన్య)
{
	స్థిరరాశి u_char *దత్తాంశం;
	u_char *signature = ఖాళీ;
	కొలత_t dlen, slen = 0;
	u_int compat;
	పూర్ణాంకం r, ok = -1;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *సందేశం;
	అక్షరం *alg = ఖాళీ;

	ఒకవేళ ((r = sshkey_froms(iqueue, &కీలకం)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(iqueue, &దత్తాంశం, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (*alg == '\0') {
		విడుదల(alg);
		alg = ఖాళీ;
	}

	ఒకవేళ ((r = pkcs11_sign(కీలకం, &signature, &slen, దత్తాంశం, dlen,
	    alg, ఖాళీ, ఖాళీ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(కీలకం));
		వెళ్ళు జవాబు;
	}

	/* success */
	ok = 0;
 జవాబు:
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ (ok == 0) {
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(సందేశం, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} లేకపోతే {
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(కీలకం);
	విడుదల(alg);
	విడుదల(signature);
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
process(శూన్య)
{
	u_int సందేశం_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	స్థిరరాశి u_char *cp;
	పూర్ణాంకం r;

	buf_len = sshbuf_len(iqueue);
	ఒకవేళ (buf_len < 5)
		తిరిగి;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	సందేశం_len = get_u32(cp);
	ఒకవేళ (సందేశం_len > MAX_సందేశం_నిడివి) {
		error("bad message len %d", సందేశం_len);
		cleanup_exit(11);
	}
	ఒకవేళ (buf_len < సందేశం_len + 4)
		తిరిగి;
	ఒకవేళ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	ఎంపిక (type) {
	స్థితి SSH_AGENTC_కూడు_SMARTCARD_కీలకం:
		debug("process_add");
		process_కూడు();
		ఆపు;
	స్థితి SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ఆపు;
	అప్రమేయ:
		error("Unknown message %d", type);
		ఆపు;
	}
	/* discard the remaining bytes from the current packet */
	ఒకవేళ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ఒకవేళ (సందేశం_len < consumed) {
		error("msg_len %d < consumed %d", సందేశం_len, consumed);
		cleanup_exit(255);
	}
	ఒకవేళ (సందేశం_len > consumed) {
		ఒకవేళ ((r = sshbuf_consume(iqueue, సందేశం_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	/* XXX */
	_exit(i);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం r, ch, లోపల, బహిర్గతం, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	అక్షరం buf[4*4096];
	బాహ్య అక్షరం *__progname;
	నిర్మాణం pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	విత్తనం_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	అయితే ((ch = getopt(argc, argv, "v")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'v':
			log_stderr = 1;
			ఒకవేళ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ఆపు;
		అప్రమేయ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			నిష్క్రమించు(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	లోపల = STDIN_FILENO;
	బహిర్గతం = STDOUT_FILENO;

	ఒకవేళ ((iqueue = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((oqueue = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	అయితే (1) {
		memset(pfd, 0, పరిమాణం(pfd));
		pfd[0].fd = లోపల;
		pfd[1].fd = బహిర్గతం;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ఒకవేళ ((r = sshbuf_check_reserve(iqueue, పరిమాణం(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_సందేశం_నిడివి)) == 0)
			pfd[0].events = POLLIN;
		లేకపోతే ఒకవేళ (r != SSH_ERR_NO_బఫరు_SPACE)
			fatal_fr(r, "reserve");

		ఒకవేళ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ఒకవేళ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ఒకవేళ (r == 0 || errno == EINTR)
				కొనసాగు;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ఒకవేళ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = పఠ(లోపల, buf, పరిమాణం buf);
			ఒకవేళ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} లేకపోతే ఒకవేళ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} లేకపోతే ఒకవేళ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ఒకవేళ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = లిఖ(బహిర్గతం, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ఒకవేళ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} లేకపోతే ఒకవేళ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ఒకవేళ ((r = sshbuf_check_reserve(oqueue, MAX_సందేశం_నిడివి)) == 0)
			process();
		లేకపోతే ఒకవేళ (r != SSH_ERR_NO_బఫరు_SPACE)
			fatal_fr(r, "reserve");
	}
}
#లేకపోతే /* ENABLE_PKCS11 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	బాహ్య అక్షరం *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#అయితే_ముగింపు /* ENABLE_PKCS11 */
