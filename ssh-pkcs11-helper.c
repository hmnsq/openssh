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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"
#അന്തര്ഭാവ "ssherr.h"

#ifdef ENABLE_PKCS11

/* borrows code from sftp-server and ssh-agent */

സ്ഥിതം അക്ഷരം *providername; /* Provider for this helper */

#define MAX_സന്ദേശം_LENGTH		10240 /*XXX*/

/* input and output queue */
ഘടന sshbuf *iqueue;
ഘടന sshbuf *oqueue;

സ്ഥിതം ശൂന്യം
send_സന്ദേശം(ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

സ്ഥിതം ശൂന്യം
process_add(ശൂന്യം)
{
	അക്ഷരം *pin;
	ഘടന sshkey **താക്കോലുകൾ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, i, nkeys;
	ഘടന sshbuf *സന്ദേശം;
	അക്ഷരം **labels = ശൂന്യ;

	എങ്കിൽ (providername != ശൂന്യ)
		fatal_f("provider already set");
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &providername, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &pin, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	debug3_f("add %s", providername);
	എങ്കിൽ ((nkeys = pkcs11_add_provider(providername, pin,
	    &താക്കോലുകൾ, &labels)) > 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം,
		    SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
		    (r = sshbuf_put_u32(സന്ദേശം, nkeys)) != 0)
			fatal_fr(r, "compose");
		വേണ്ടി (i = 0; i < nkeys; i++) {
			എങ്കിൽ ((r = sshkey_puts(താക്കോലുകൾ[i], സന്ദേശം)) != 0 ||
			    (r = sshbuf_put_cstring(സന്ദേശം, labels[i])) != 0)
				fatal_fr(r, "compose key");
			debug3_f("%s: %s \"%s\"", providername,
			    sshkey_type(താക്കോലുകൾ[i]), labels[i]);
			സ്വതന്ത്രം(labels[i]);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENT_FAILURE)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, -nkeys)) != 0)
		fatal_fr(r, "compose");
	സ്വതന്ത്രം(labels);
	സ്വതന്ത്രം(താക്കോലുകൾ); /* keys themselves are transferred to pkcs11_keylist */
	സ്വതന്ത്രം(pin);
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
process_sign(ശൂന്യം)
{
	സ്ഥിരം u_char *data;
	u_char *signature = ശൂന്യ;
	size_t dlen, slen = 0;
	u_int compat;
	പൂർണ്ണസംഖ്യ r, ok = -1;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *സന്ദേശം;
	അക്ഷരം *alg = ശൂന്യ;

	എങ്കിൽ ((r = sshkey_froms(iqueue, &താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_string_direct(iqueue, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &alg, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &compat)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (*alg == '\0') {
		സ്വതന്ത്രം(alg);
		alg = ശൂന്യ;
	}

	എങ്കിൽ ((r = pkcs11_sign(താക്കോൽ, &signature, &slen, data, dlen,
	    alg, ശൂന്യ, ശൂന്യ, compat)) != 0) {
		error_fr(r, "sign %s", sshkey_type(താക്കോൽ));
		പോകുക reply;
	}

	/* success */
	ok = 0;
 reply:
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ (ok == 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(സന്ദേശം, signature, slen)) != 0)
			fatal_fr(r, "compose response");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENT_FAILURE)) != 0)
			fatal_fr(r, "compose failure response");
	}
	sshkey_free(താക്കോൽ);
	സ്വതന്ത്രം(alg);
	സ്വതന്ത്രം(signature);
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
process(ശൂന്യം)
{
	u_int സന്ദേശം_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	സ്ഥിരം u_char *cp;
	പൂർണ്ണസംഖ്യ r;

	buf_len = sshbuf_len(iqueue);
	എങ്കിൽ (buf_len < 5)
		തിരികെ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	സന്ദേശം_len = get_u32(cp);
	എങ്കിൽ (സന്ദേശം_len > MAX_സന്ദേശം_LENGTH) {
		error("bad message len %d", സന്ദേശം_len);
		cleanup_exit(11);
	}
	എങ്കിൽ (buf_len < സന്ദേശം_len + 4)
		തിരികെ;
	എങ്കിൽ ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type/len");
	buf_len -= 4;
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ:
		debug("process_add");
		process_add();
		നിർത്തുക;
	അവസ്ഥ SSH2_AGENTC_SIGN_REQUEST:
		debug("process_sign");
		process_sign();
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error("Unknown message %d", type);
		നിർത്തുക;
	}
	/* discard the remaining bytes from the current packet */
	എങ്കിൽ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	എങ്കിൽ (സന്ദേശം_len < consumed) {
		error("msg_len %d < consumed %d", സന്ദേശം_len, consumed);
		cleanup_exit(255);
	}
	എങ്കിൽ (സന്ദേശം_len > consumed) {
		എങ്കിൽ ((r = sshbuf_consume(iqueue, സന്ദേശം_len - consumed)) != 0)
			fatal_fr(r, "consume");
	}
}

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	/* XXX */
	_exit(i);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ r, ch, in, out, log_stderr = 0;
	ssize_t len;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_ERROR;
	അക്ഷരം buf[4*4096];
	ബാഹ്യ അക്ഷരം *__progname;
	ഘടന pollfd pfd[2];

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	sanitise_stdfd();
	closefrom(STDERR_FILENO + 1);
	log_init(__progname, log_level, log_facility, log_stderr);

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "v")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'v':
			log_stderr = 1;
			എങ്കിൽ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	pkcs11_init(0);
	in = STDIN_FILENO;
	out = STDOUT_FILENO;

	എങ്കിൽ ((iqueue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((oqueue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	ആകുമ്പോൾ (1) {
		memset(pfd, 0, വലുപ്പം(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		എങ്കിൽ ((r = sshbuf_check_reserve(iqueue, വലുപ്പം(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue, MAX_സന്ദേശം_LENGTH)) == 0)
			pfd[0].events = POLLIN;
		അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		എങ്കിൽ (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		എങ്കിൽ ((r = poll(pfd, 2, -1 /* INFTIM */)) <= 0) {
			എങ്കിൽ (r == 0 || errno == EINTR)
				തുടരുക;
			fatal("poll: %s", strerror(errno));
		}

		/* copy stdin to iqueue */
		എങ്കിൽ ((pfd[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			len = പഠ(in, buf, വലുപ്പം buf);
			എങ്കിൽ (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} അല്ലെങ്കിൽ എങ്കിൽ (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		എങ്കിൽ ((pfd[1].revents & (POLLOUT|POLLHUP)) != 0) {
			len = ലിഖ(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			എങ്കിൽ (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		എങ്കിൽ ((r = sshbuf_check_reserve(oqueue, MAX_സന്ദേശം_LENGTH)) == 0)
			process();
		അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
#അല്ലെങ്കിൽ /* ENABLE_PKCS11 */
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ബാഹ്യ അക്ഷരം *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("PKCS#11 support disabled at compile time");
}
#endif /* ENABLE_PKCS11 */
