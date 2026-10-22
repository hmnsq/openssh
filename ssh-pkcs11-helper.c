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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

ਸਥਿਰ ਅੱਖਰ *providername; /* Provider for this helper */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ		10240 /*XXX*/

/* input and output queue */
ਬਣਤਰ sshbuf *iqueue;
ਬਣਤਰ sshbuf *oqueue;

ਸਥਿਰ ਖਾਲੀ
send_ਸੁਨੇਹਾ(ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

ਸਥਿਰ ਖਾਲੀ
process_ਜੋੜੋ(ਖਾਲੀ)
{
	ਅੱਖਰ *pin;
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ = ਨਿਰਾ;
	ਪੂਰਨ r, i, nkeys;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਅੱਖਰ **labels = ਨਿਰਾ;

	ਜੇ (providername != ਨਿਰਾ)
		fatal_f("provider already set");
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_get_cstring(iqueue, &providername, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ਜੇ ((nkeys = pkcs11_ਜੋੜੋ_provider(providername, pin,
	    &ਕੁੰਜੀਆਂ, &labels)) > 0) {
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, nkeys)) != 0)
			fatal_fr(r, "compose");
		ਲਈ (i = 0; i < nkeys; i++) {
			ਜੇ ((r = sshkey_puts(ਕੁੰਜੀਆਂ[i], ਸੁਨੇਹਾ)) != 0 ||
			    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(ਕੁੰਜੀਆਂ[i]), labels[i]);
			ਮੁਕਤ(labels[i]);
		}
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, -nkeys)) != 0)
		fatal_fr(r, "compose");
	ਮੁਕਤ(labels);
	ਮੁਕਤ(ਕੁੰਜੀਆਂ); /* keys themselves are transferred to pkcs11_keylist */
	ਮੁਕਤ(pin);
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_sign(ਖਾਲੀ)
{
	ਅਚਲ u_char *ਅੰਕੜੇ;
	u_char *signature = ਨਿਰਾ;
	ਮਾਪ_t dlen, slen = 0;
	u_int compat;
	ਪੂਰਨ r, ok = -1;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਅੱਖਰ *alg = ਨਿਰਾ;

	ਜੇ ((r = sshkey_froms(iqueue, &ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(iqueue, &ਅੰਕੜੇ, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (*alg == '\0') {
		ਮੁਕਤ(alg);
		alg = ਨਿਰਾ;
	}

	ਜੇ ((r = pkcs11_sign(ਕੁੰਜੀ, &signature, &slen, ਅੰਕੜੇ, dlen,
	    alg, ਨਿਰਾ, ਨਿਰਾ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(ਕੁੰਜੀ));
		ਜਾਓ ਜਵਾਬ;
	}

	/* success */
	ok = 0;
 ਜਵਾਬ:
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ (ok == 0) {
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ਸੁਨੇਹਾ, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(ਕੁੰਜੀ);
	ਮੁਕਤ(alg);
	ਮੁਕਤ(signature);
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
process(ਖਾਲੀ)
{
	u_int ਸੁਨੇਹਾ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ਅਚਲ u_char *cp;
	ਪੂਰਨ r;

	buf_len = sshbuf_len(iqueue);
	ਜੇ (buf_len < 5)
		ਵਾਪਸ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ਸੁਨੇਹਾ_len = get_u32(cp);
	ਜੇ (ਸੁਨੇਹਾ_len > MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ) {
		error("bad message len %d", ਸੁਨੇਹਾ_len);
		cleanup_exit(11);
	}
	ਜੇ (buf_len < ਸੁਨੇਹਾ_len + 4)
		ਵਾਪਸ;
	ਜੇ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	ਚੋਣ (type) {
	ਹਾਲਤ SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ:
		debug("process_add");
		process_ਜੋੜੋ();
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		ਰੋਕੋ;
	ਮੂਲ:
		error("Unknown message %d", type);
		ਰੋਕੋ;
	}
	/* discard the remaining bytes from the current packet */
	ਜੇ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ਜੇ (ਸੁਨੇਹਾ_len < consumed) {
		error("msg_len %d < consumed %d", ਸੁਨੇਹਾ_len, consumed);
		cleanup_exit(255);
	}
	ਜੇ (ਸੁਨੇਹਾ_len > consumed) {
		ਜੇ ((r = sshbuf_consume(iqueue, ਸੁਨੇਹਾ_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	/* XXX */
	_exit(i);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ r, ch, ਵਿੱਚ, ਬਾਹਰਲਾ, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	ਅੱਖਰ buf[4*4096];
	ਬਾਹਰੀ ਅੱਖਰ *__progname;
	ਬਣਤਰ pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	ਬੀਜ_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ਜਦੋਂ ((ch = getopt(argc, argv, "v")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'v':
			log_stderr = 1;
			ਜੇ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ਰੋਕੋ;
		ਮੂਲ:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	ਵਿੱਚ = STDIN_FILENO;
	ਬਾਹਰਲਾ = STDOUT_FILENO;

	ਜੇ ((iqueue = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((oqueue = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜਦੋਂ (1) {
		memset(pfd, 0, ਆਕਾਰ(pfd));
		pfd[0].fd = ਵਿੱਚ;
		pfd[1].fd = ਬਾਹਰਲਾ;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ਜੇ ((r = sshbuf_check_reserve(iqueue, ਆਕਾਰ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ)) == 0)
			pfd[0].events = POLLIN;
		ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_NO_ਬਫਰ_SPACE)
			fatal_fr(r, "reserve");

		ਜੇ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ਜੇ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ਜੇ (r == 0 || errno == EINTR)
				ਜਾਰੀ;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ਜੇ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = ਪਠ(ਵਿੱਚ, buf, ਆਕਾਰ buf);
			ਜੇ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} ਨਹੀਂਤਾਂ ਜੇ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ਜੇ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ਲਿਖ(ਬਾਹਰਲਾ, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ਜੇ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ਜੇ ((r = sshbuf_check_reserve(oqueue, MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ)) == 0)
			process();
		ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_NO_ਬਫਰ_SPACE)
			fatal_fr(r, "reserve");
	}
}
#ਨਹੀਂਤਾਂ /* ENABLE_PKCS11 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਬਾਹਰੀ ਅੱਖਰ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
