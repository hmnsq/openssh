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

#include "includes.h"

#include <sys/types.h>
#include <sys/time.h>

#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "sshkey.h"
#include "authfd.h"
#include "ssh-pkcs11.h"
#include "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

static var_na *providername; /* Provider for this helper */

#define MAX_MSG_LENGTH		10240 /*XXX*/

/* input and output queue */
sa_nracanaa sshbuf *iqueue;
sa_nracanaa sshbuf *oqueue;

static void
send_msg(sa_nracanaa sshbuf *m)
{
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

static void
process_add(void)
{
	var_na *pin;
	sa_nracanaa sshkey **keys = NULL;
	ចំនួនគត់ r, i, nkeys;
	sa_nracanaa sshbuf *msg;
	var_na **labels = NULL;

	ប្រសិនបើ (providername != NULL)
		fatal_f("provider already set");
	ប្រសិនបើ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ប្រសិនបើ ((r = sshbuf_get_cstring(iqueue, &providername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, NULL)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	ប្រសិនបើ ((nkeys = pkcs11_add_provider(providername, pin,
	    &keys, &labels)) > 0) {
		ប្រសិនបើ ((r = sshbuf_put_u8(msg,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(msg, nkeys)) != 0)
			fatal_fr(r, "compose");
		សម្រាប់ (i = 0; i < nkeys; i++) {
			ប្រសិនបើ ((r = sshkey_puts(keys[i], msg)) != 0 ||
			    (r = sshbuf_put_cstring(msg, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(keys[i]), labels[i]);
			free(labels[i]);
		}
	} បើមិនដូច្នេះ ប្រសិនបើ ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(msg, -nkeys)) != 0)
		fatal_fr(r, "compose");
	free(labels);
	free(keys); /* keys themselves are transferred to pkcs11_keylist */
	free(pin);
	send_msg(msg);
	sshbuf_free(msg);
}

static void
process_sign(void)
{
	const u_char *data;
	u_char *signature = NULL;
	size_t dlen, slen = 0;
	u_int compat;
	ចំនួនគត់ r, ok = -1;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *msg;
	var_na *alg = NULL;

	ប្រសិនបើ ((r = sshkey_froms(iqueue, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	ប្រសិនបើ (*alg == '\0') {
		free(alg);
		alg = NULL;
	}

	ប្រសិនបើ ((r = pkcs11_sign(key, &signature, &slen, data, dlen,
	    alg, NULL, NULL, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(key));
		goto reply;
	}

	/* success */
	ok = 0;
 reply:
	ប្រសិនបើ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ប្រសិនបើ (ok == 0) {
		ប្រសិនបើ ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} បើមិនដូច្នេះ {
		ប្រសិនបើ ((r = sshbuf_put_u8(msg, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(key);
	free(alg);
	free(signature);
	send_msg(msg);
	sshbuf_free(msg);
}

static void
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	const u_char *cp;
	ចំនួនគត់ r;

	buf_len = sshbuf_len(iqueue);
	ប្រសិនបើ (buf_len < 5)
		ត្រឡប់;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	ប្រសិនបើ (msg_len > MAX_MSG_LENGTH) {
		error("bad message len %d", msg_len);
		cleanup_exit(11);
	}
	ប្រសិនបើ (buf_len < msg_len + 4)
		ត្រឡប់;
	ប្រសិនបើ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	switch (type) {
	pak_sa SSH_AGENTC_ADD_SMARTCARD_KEY:
		debug("process_add");
		process_add();
		bha_nga;
	pak_sa SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		bha_nga;
	default:
		error("Unknown message %d", type);
		bha_nga;
	}
	/* discard the remaining bytes from the current packet */
	ប្រសិនបើ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ប្រសិនបើ (msg_len < consumed) {
		error("msg_len %d < consumed %d", msg_len, consumed);
		cleanup_exit(255);
	}
	ប្រសិនបើ (msg_len > consumed) {
		ប្រសិនបើ ((r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

void
cleanup_exit(ចំនួនគត់ i)
{
	/* XXX */
	_exit(i);
}

ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	ចំនួនគត់ r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	var_na buf[4*4096];
	extern var_na *__progname;
	sa_nracanaa pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ខណៈពេល ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		pak_sa 'v':
			log_stderr = 1;
			ប្រសិនបើ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			បើមិនដូច្នេះ ប្រសិនបើ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			bha_nga;
		default:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	ប្រសិនបើ ((iqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ប្រសិនបើ ((oqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	ខណៈពេល (1) {
		memset(pfd, 0, parimaa_na(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ប្រសិនបើ ((r = sshbuf_check_reserve(iqueue, parimaa_na(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_MSG_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		បើមិនដូច្នេះ ប្រសិនបើ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		ប្រសិនបើ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		ប្រសិនបើ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			ប្រសិនបើ (r == 0 || errno == EINTR)
				continue;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		ប្រសិនបើ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = read(in, buf, parimaa_na buf);
			ប្រសិនបើ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} បើមិនដូច្នេះ ប្រសិនបើ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} បើមិនដូច្នេះ ប្រសិនបើ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ប្រសិនបើ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = write(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			ប្រសិនបើ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} បើមិនដូច្នេះ ប្រសិនបើ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		ប្រសិនបើ ((r = sshbuf_check_reserve(oqueue, MAX_MSG_LENGTH)) == 0)
			process();
		បើមិនដូច្នេះ ប្រសិនបើ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#បើមិនដូច្នេះ /* ENABLE_PKCS11 */
ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	extern var_na *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
