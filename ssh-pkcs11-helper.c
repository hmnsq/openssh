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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ସ୍ଥିର ଅକ୍ଷର *providername; /* Provider for this helper */

#define MAX_ସନ୍ଦେଶ_LENGTH		10240 /*XXX*/

/* input and output queue */
ସଂରଚନା sshbuf *iqueue;
ସଂରଚନା sshbuf *oqueue;

ସ୍ଥିର ଶୂନ୍ୟ
send_ସନ୍ଦେଶ(ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ସ୍ଥିର ଶୂନ୍ୟ
process_add(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *pin;
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, nkeys;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ଅକ୍ଷର **labels = ଖାଲି;

	ଯଦି (providername != ଖାଲି)
		fatal_f("provider already set");
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_get_cstring(iqueue, &providername, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ଯଦି ((nkeys = pkcs11_add_provider(providername, pin,
	    &ଚାବିଗୁଡ଼ିକ, &labels)) > 0) {
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(ସନ୍ଦେଶ, nkeys)) != 0)
			fatal_fr(r, "compose");
		ପାଇଁ (i = 0; i < nkeys; i++) {
			ଯଦି ((r = sshkey_puts(ଚାବିଗୁଡ଼ିକ[i], ସନ୍ଦେଶ)) != 0 ||
			    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(ଚାବିଗୁଡ଼ିକ[i]), labels[i]);
			ମୁକ୍ତ(labels[i]);
		}
	} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, -nkeys)) != 0)
		fatal_fr(r, "compose");
	ମୁକ୍ତ(labels);
	ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ); /* keys themselves are transferred to pkcs11_keylist */
	ମୁକ୍ତ(pin);
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_sign(ଶୂନ୍ୟ)
{
	ଅଚଳ u_char *data;
	u_char *signature = ଖାଲି;
	size_t dlen, slen = 0;
	u_int compat;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok = -1;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ଅକ୍ଷର *alg = ଖାଲି;

	ଯଦି ((r = sshkey_froms(iqueue, &ଚାବି)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (*alg == '\0') {
		ମୁକ୍ତ(alg);
		alg = ଖାଲି;
	}

	ଯଦି ((r = pkcs11_sign(ଚାବି, &signature, &slen, data, dlen,
	    alg, ଖାଲି, ଖାଲି, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(ଚାବି));
		ଯାଅ reply;
	}

	/* success */
	ok = 0;
 reply:
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି (ok == 0) {
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ସନ୍ଦେଶ, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(ଚାବି);
	ମୁକ୍ତ(alg);
	ମୁକ୍ତ(signature);
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
process(ଶୂନ୍ୟ)
{
	u_int ସନ୍ଦେଶ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ଅଚଳ u_char *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	buf_len = sshbuf_len(iqueue);
	ଯଦି (buf_len < 5)
		ଫେରନ୍ତୁ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ସନ୍ଦେଶ_len = get_u32(cp);
	ଯଦି (ସନ୍ଦେଶ_len > MAX_ସନ୍ଦେଶ_LENGTH) {
		error("bad message len %d", ସନ୍ଦେଶ_len);
		cleanup_exit(11);
	}
	ଯଦି (buf_len < ସନ୍ଦେଶ_len + 4)
		ଫେରନ୍ତୁ;
	ଯଦି ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	ବାଛ (type) {
	ସ୍ଥିତି SSH_AGENTC_ADD_SMARTCARD_ଚାବି:
		debug("process_add");
		process_add();
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("Unknown message %d", type);
		ଭାଙ୍ଗ;
	}
	/* discard the remaining bytes from the current packet */
	ଯଦି (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ଯଦି (ସନ୍ଦେଶ_len < consumed) {
		error("msg_len %d < consumed %d", ସନ୍ଦେଶ_len, consumed);
		cleanup_exit(255);
	}
	ଯଦି (ସନ୍ଦେଶ_len > consumed) {
		ଯଦି ((r = sshbuf_consume(iqueue, ସନ୍ଦେଶ_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	/* XXX */
	_exit(i);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ଅକ୍ଷର buf[4*4096];
	ବାହ୍ୟ ଅକ୍ଷର *__progname;
	ସଂରଚନା pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "v")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'v':
			log_stderr = 1;
			ଯଦି (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	ଯଦି ((iqueue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((oqueue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯେତେବେଳେ (1) {
		memset(pfd, 0, ଆକାର(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ଯଦି ((r = sshbuf_check_reserve(iqueue, ଆକାର(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_ସନ୍ଦେଶ_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		ଯଦି (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ଯଦି ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ଯଦି (r == 0 || errno == EINTR)
				ଜାରି;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ଯଦି ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = ପଠ(in, buf, ଆକାର buf);
			ଯଦି (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} ଅନ୍ୟଥା ଯଦି (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ଯଦି ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ଲିଖ(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ଯଦି (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ଯଦି ((r = sshbuf_check_reserve(oqueue, MAX_ସନ୍ଦେଶ_LENGTH)) == 0)
			process();
		ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#ଅନ୍ୟଥା /* ENABLE_PKCS11 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ବାହ୍ୟ ଅକ୍ଷର *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
