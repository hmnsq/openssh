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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "ssh-pkcs11.h"
#અન્તર્ભાવ "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

સ્થિર અક્ષર *providername; /* Provider for this helper */

#define MAX_સંદેશ_LENGTH		10240 /*XXX*/

/* input and output queue */
સંરચના sshbuf *iqueue;
સંરચના sshbuf *oqueue;

સ્થિર શૂન્ય
send_સંદેશ(સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

સ્થિર શૂન્ય
process_add(શૂન્ય)
{
	અક્ષર *pin;
	સંરચના sshkey **ચાવીઓ = ખાલી;
	પૂર્ણાંક r, i, nkeys;
	સંરચના sshbuf *સંદેશ;
	અક્ષર **labels = ખાલી;

	જો (providername != ખાલી)
		fatal_f("provider already set");
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_get_cstring(iqueue, &providername, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ખાલી)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	જો ((nkeys = pkcs11_add_provider(providername, pin,
	    &ચાવીઓ, &labels)) > 0) {
		જો ((r = sshbuf_put_u8(સંદેશ,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(સંદેશ, nkeys)) != 0)
			fatal_fr(r, "compose");
		માટે (i = 0; i < nkeys; i++) {
			જો ((r = sshkey_puts(ચાવીઓ[i], સંદેશ)) != 0 ||
			    (r = sshbuf_put_cstring(સંદેશ, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(ચાવીઓ[i]), labels[i]);
			મુક્ત(labels[i]);
		}
	} નહીંતર જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, -nkeys)) != 0)
		fatal_fr(r, "compose");
	મુક્ત(labels);
	મુક્ત(ચાવીઓ); /* keys themselves are transferred to pkcs11_keylist */
	મુક્ત(pin);
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
process_sign(શૂન્ય)
{
	અચલ u_char *data;
	u_char *signature = ખાલી;
	size_t dlen, slen = 0;
	u_int compat;
	પૂર્ણાંક r, ok = -1;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *સંદેશ;
	અક્ષર *alg = ખાલી;

	જો ((r = sshkey_froms(iqueue, &ચાવી)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	જો (*alg == '\0') {
		મુક્ત(alg);
		alg = ખાલી;
	}

	જો ((r = pkcs11_sign(ચાવી, &signature, &slen, data, dlen,
	    alg, ખાલી, ખાલી, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(ચાવી));
		જાઓ reply;
	}

	/* success */
	ok = 0;
 reply:
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો (ok == 0) {
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(સંદેશ, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} નહીંતર {
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(ચાવી);
	મુક્ત(alg);
	મુક્ત(signature);
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
process(શૂન્ય)
{
	u_int સંદેશ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	અચલ u_char *cp;
	પૂર્ણાંક r;

	buf_len = sshbuf_len(iqueue);
	જો (buf_len < 5)
		પાછા;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	સંદેશ_len = get_u32(cp);
	જો (સંદેશ_len > MAX_સંદેશ_LENGTH) {
		error("bad message len %d", સંદેશ_len);
		cleanup_exit(11);
	}
	જો (buf_len < સંદેશ_len + 4)
		પાછા;
	જો ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	પસંદગી (type) {
	સ્થિતિ SSH_AGENTC_ADD_SMARTCARD_ચાવી:
		debug("process_add");
		process_add();
		તોડો;
	સ્થિતિ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		તોડો;
	મૂળભૂત:
		error("Unknown message %d", type);
		તોડો;
	}
	/* discard the remaining bytes from the current packet */
	જો (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	જો (સંદેશ_len < consumed) {
		error("msg_len %d < consumed %d", સંદેશ_len, consumed);
		cleanup_exit(255);
	}
	જો (સંદેશ_len > consumed) {
		જો ((r = sshbuf_consume(iqueue, સંદેશ_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	/* XXX */
	_exit(i);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	અક્ષર buf[4*4096];
	બાહ્ય અક્ષર *__progname;
	સંરચના pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	જ્યારે ((ch = getopt(argc, argv, "v")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'v':
			log_stderr = 1;
			જો (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			તોડો;
		મૂળભૂત:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	જો ((iqueue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((oqueue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જ્યારે (1) {
		memset(pfd, 0, કદ(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		જો ((r = sshbuf_check_reserve(iqueue, કદ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_સંદેશ_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		નહીંતર જો (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		જો (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		જો ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			જો (r == 0 || errno == EINTR)
				ચાલુ;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		જો ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = પઠ(in, buf, કદ buf);
			જો (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} નહીંતર જો (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} નહીંતર જો ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		જો ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = લિખ(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			જો (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} નહીંતર જો ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		જો ((r = sshbuf_check_reserve(oqueue, MAX_સંદેશ_LENGTH)) == 0)
			process();
		નહીંતર જો (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#નહીંતર /* ENABLE_PKCS11 */
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	બાહ્ય અક્ષર *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
