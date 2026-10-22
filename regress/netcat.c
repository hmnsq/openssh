/* $OpenBSD: netcat.c,v 1.131 2015/09/03 23:06:28 sobrado Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/tcp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ERR_H
# include <err.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#ਜੇ_ਅੰਤ

/* rename to avoid collision in libssh */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IAC	255
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DONT	254
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DO	253
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WONT	252
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WILL	251

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SUN_LEN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SUN_LEN(su) \
	(ਆਕਾਰ(*(su)) - ਆਕਾਰ((su)->sun_ਰਸਤਾ) + ਲੜੀ_ਲੰਬਾਈ((su)->sun_ਰਸਤਾ))
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੋਰਟ_MAX	65535
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੋਰਟ_MAX_LEN	6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UNIX_DG_TMP_SOCKET_ਮਾਪ	19

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLL_STDIN 0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLL_NETOUT 1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLL_NETIN 2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLL_STDOUT 3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BUFSIZE 16384

/* Command Line Options */
ਪੂਰਨ	dflag;					/* detached, no stdin */
ਪੂਰਨ	Fflag;					/* fdpass sock to stdout */
ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ iflag;				/* Interval Flag */
ਪੂਰਨ	kflag;					/* More than one connect */
ਪੂਰਨ	lflag;					/* Bind to local port */
ਪੂਰਨ	Nflag;					/* shutdown() network socket */
ਪੂਰਨ	nflag;					/* Don't do name look up */
ਅੱਖਰ   *Pflag;					/* Proxy username */
ਅੱਖਰ   *pflag;					/* Localport flag */
ਪੂਰਨ	rflag;					/* Random ports flag */
ਅੱਖਰ   *sflag;					/* Source Address */
ਪੂਰਨ	tflag;					/* Telnet Emulation */
ਪੂਰਨ	uflag;					/* UDP - Default to TCP */
ਪੂਰਨ	vflag;					/* Verbosity */
ਪੂਰਨ	xflag;					/* Socks proxy */
ਪੂਰਨ	zflag;					/* Port Scan Flag */
ਪੂਰਨ	Dflag;					/* sodebug */
ਪੂਰਨ	Iflag;					/* TCP receive buffer size */
ਪੂਰਨ	Oflag;					/* TCP send buffer size */
ਪੂਰਨ	Sflag;					/* TCP MD5 signature option */
ਪੂਰਨ	Tflag = -1;				/* IP Type of Service */
ਪੂਰਨ	rtableid = -1;

ਪੂਰਨ timeout = -1;
ਪੂਰਨ family = AF_UNSPEC;
ਅੱਖਰ *portlist[ਪੋਰਟ_MAX+1];
ਅੱਖਰ *unix_dg_tmp_socket;

ਖਾਲੀ	atelnet(ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
ਖਾਲੀ	build_ports(ਅੱਖਰ *);
ਖਾਲੀ	help(ਖਾਲੀ);
ਪੂਰਨ	local_listen(ਅੱਖਰ *, ਅੱਖਰ *, ਬਣਤਰ addrinfo);
ਖਾਲੀ	readwrite(ਪੂਰਨ);
ਖਾਲੀ	fdpass(ਪੂਰਨ nfd) __attribute__((noreturn));
ਪੂਰਨ	remote_connect(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo);
ਪੂਰਨ	timeout_connect(ਪੂਰਨ, ਅਚਲ ਬਣਤਰ sockaddr *, socklen_t);
ਪੂਰਨ	socks_connect(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo,
	    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	udptest(ਪੂਰਨ);
ਪੂਰਨ	unix_bind(ਅੱਖਰ *);
ਪੂਰਨ	unix_connect(ਅੱਖਰ *);
ਪੂਰਨ	unix_listen(ਅੱਖਰ *);
ਖਾਲੀ	ਸੈੱਟ_common_sockopts(ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	map_tos(ਅੱਖਰ *, ਪੂਰਨ *);
ਖਾਲੀ	report_connect(ਅਚਲ ਬਣਤਰ sockaddr *, socklen_t);
ਖਾਲੀ	usage(ਪੂਰਨ);
ssize_t drainbuf(ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t *);
ssize_t fillbuf(ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t *);


ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ *argv[])
{
	ਪੂਰਨ ch, s, ret, socksv;
	ਅੱਖਰ *host, *uport;
	ਬਣਤਰ addrinfo hints;
	ਬਣਤਰ servent *sv;
	socklen_t len;
	ਬਣਤਰ sockaddr_storage cliaddr;
	ਅੱਖਰ *proxy = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *errstr, *proxyhost = "", *proxyport = ਨਿਰਾ;
	ਬਣਤਰ addrinfo proxyhints;
	ਅੱਖਰ unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_ਮਾਪ];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ਨਿਰਾ;
	uport = ਨਿਰਾ;
	sv = ਨਿਰਾ;

	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);

	ਜਦੋਂ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ '4':
			family = AF_INET;
			ਰੋਕੋ;
		ਹਾਲਤ '6':
			family = AF_INET6;
			ਰੋਕੋ;
		ਹਾਲਤ 'U':
			family = AF_UNIX;
			ਰੋਕੋ;
		ਹਾਲਤ 'X':
			ਜੇ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ਨਹੀਂਤਾਂ
				errx(1, "unsupported proxy protocol");
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			dflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'F':
			Fflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			help();
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ਜੇ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			kflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			lflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'N':
			Nflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'n':
			nflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			Pflag = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			pflag = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			rflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			sflag = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			tflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			uflag = 1;
			ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_RTABLE
		ਹਾਲਤ 'V':
			rtableid = (ਪੂਰਨ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ਜੇ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ
		ਹਾਲਤ 'v':
			vflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'w':
			timeout = strtonum(optarg, 0, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / 1000, &errstr);
			ਜੇ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ਰੋਕੋ;
		ਹਾਲਤ 'x':
			xflag = 1;
			ਜੇ ((proxy = strdup(optarg)) == ਨਿਰਾ)
				errx(1, "strdup");
			ਰੋਕੋ;
		ਹਾਲਤ 'z':
			zflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			Dflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ਜੇ (errstr != ਨਿਰਾ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ਜੇ (errstr != ਨਿਰਾ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			Sflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			errstr = ਨਿਰਾ;
			errno = 0;
			ਜੇ (map_tos(optarg, &Tflag))
				ਰੋਕੋ;
			ਜੇ (ਲੜੀ_ਲੰਬਾਈ(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ਪੂਰਨ)strtol(optarg, ਨਿਰਾ, 16);
			ਨਹੀਂਤਾਂ
				Tflag = (ਪੂਰਨ)strtonum(optarg, 0, 255,
				    &errstr);
			ਜੇ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ਰੋਕੋ;
		ਮੂਲ:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ਜੇ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (argv[0] && !argv[1]) {
		ਜੇ  (!lflag)
			usage(1);
		uport = argv[0];
		host = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ਨਹੀਂਤਾਂ
		usage(1);

	ਜੇ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ਜੇ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ਜੇ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ਜੇ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ਜੇ ((family == AF_UNIX) && uflag && !lflag) {
		ਜੇ (sflag) {
			unix_dg_tmp_socket = sflag;
		} ਨਹੀਂਤਾਂ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_ਮਾਪ);
			ਜੇ (mktemp(unix_dg_tmp_socket_buf) == ਨਿਰਾ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ਜੇ (family != AF_UNIX) {
		memset(&hints, 0, ਆਕਾਰ(ਬਣਤਰ addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ਜੇ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ਜੇ (xflag) {
		ਜੇ (uflag)
			errx(1, "no proxy support for UDP mode");

		ਜੇ (lflag)
			errx(1, "no proxy support for listen");

		ਜੇ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ਜੇ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ਜੇ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, ਆਕਾਰ(ਬਣਤਰ addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ਜੇ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ਜੇ (lflag) {
		ਪੂਰਨ connfd;
		ret = 0;

		ਜੇ (family == AF_UNIX) {
			ਜੇ (uflag)
				s = unix_bind(host);
			ਨਹੀਂਤਾਂ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ਲਈ (;;) {
			ਜੇ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ਜੇ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ਜੇ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ਨਹੀਂਤਾਂ ਜੇ (uflag && !kflag) {
				ਪੂਰਨ rv, plen;
				ਅੱਖਰ buf[16384];
				ਬਣਤਰ sockaddr_storage z;

				len = ਆਕਾਰ(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ਬਣਤਰ sockaddr *)&z, &len);
				ਜੇ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ਬਣਤਰ sockaddr *)&z, len);
				ਜੇ (rv < 0)
					err(1, "connect");

				ਜੇ (vflag)
					report_connect((ਬਣਤਰ sockaddr *)&z, len);

				readwrite(s);
			} ਨਹੀਂਤਾਂ {
				len = ਆਕਾਰ(cliaddr);
				connfd = accept(s, (ਬਣਤਰ sockaddr *)&cliaddr,
				    &len);
				ਜੇ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ਜੇ (vflag)
					report_connect((ਬਣਤਰ sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ਜੇ (family != AF_UNIX)
				close(s);
			ਨਹੀਂਤਾਂ ਜੇ (uflag) {
				ਜੇ (connect(s, ਨਿਰਾ, 0) < 0)
					err(1, "connect");
			}

			ਜੇ (!kflag)
				ਰੋਕੋ;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (family == AF_UNIX) {
		ret = 0;

		ਜੇ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ਨਹੀਂਤਾਂ
			ret = 1;

		ਜੇ (uflag)
			unlink(unix_dg_tmp_socket);
		ਬਾਹਰ_ਨਿਕਲੋ(ret);

	} ਨਹੀਂਤਾਂ {
		ਪੂਰਨ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ਲਈ (i = 0; portlist[i] != ਨਿਰਾ; i++) {
			ਜੇ (s)
				close(s);

			ਜੇ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ਨਹੀਂਤਾਂ
				s = remote_connect(host, portlist[i], hints);

			ਜੇ (s < 0)
				ਜਾਰੀ;

			ret = 0;
			ਜੇ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ਜੇ (uflag) {
					ਜੇ (udptest(s) == -1) {
						ret = 1;
						ਜਾਰੀ;
					}
				}

				/* Don't look up port if -n. */
				ਜੇ (nflag)
					sv = ਨਿਰਾ;
				ਨਹੀਂਤਾਂ {
					sv = getservbyport(
					    ntohs(atoi(portlist[i])),
					    uflag ? "udp" : "tcp");
				}

				fprintf(stderr,
				    "Connection to %s %s port [%s/%s] "
				    "succeeded!\n", host, portlist[i],
				    uflag ? "udp" : "tcp",
				    sv ? sv->s_name : "*");
			}
			ਜੇ (Fflag)
				fdpass(s);
			ਨਹੀਂਤਾਂ ਜੇ (!zflag)
				readwrite(s);
		}
	}

	ਜੇ (s)
		close(s);

	ਬਾਹਰ_ਨਿਕਲੋ(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ਪੂਰਨ
unix_bind(ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sockaddr_un sun_sa;
	ਪੂਰਨ s;

	/* Create unix domain socket. */
	ਜੇ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ਵਾਪਸ (-1);

	memset(&sun_sa, 0, ਆਕਾਰ(ਬਣਤਰ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ਜੇ (strlcpy(sun_sa.sun_ਰਸਤਾ, ਰਸਤਾ, ਆਕਾਰ(sun_sa.sun_ਰਸਤਾ)) >=
	    ਆਕਾਰ(sun_sa.sun_ਰਸਤਾ)) {
		close(s);
		errno = ENAMETOOLONG;
		ਵਾਪਸ (-1);
	}

	ਜੇ (bind(s, (ਬਣਤਰ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ਪੂਰਨ
unix_connect(ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sockaddr_un sun_sa;
	ਪੂਰਨ s;

	ਜੇ (uflag) {
		ਜੇ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ਵਾਪਸ (-1);
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ਵਾਪਸ (-1);
	}
	(ਖਾਲੀ)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, ਆਕਾਰ(ਬਣਤਰ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ਜੇ (strlcpy(sun_sa.sun_ਰਸਤਾ, ਰਸਤਾ, ਆਕਾਰ(sun_sa.sun_ਰਸਤਾ)) >=
	    ਆਕਾਰ(sun_sa.sun_ਰਸਤਾ)) {
		close(s);
		errno = ENAMETOOLONG;
		ਵਾਪਸ (-1);
	}
	ਜੇ (connect(s, (ਬਣਤਰ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ਪੂਰਨ
unix_listen(ਅੱਖਰ *ਰਸਤਾ)
{
	ਪੂਰਨ s;
	ਜੇ ((s = unix_bind(ਰਸਤਾ)) < 0)
		ਵਾਪਸ (-1);

	ਜੇ (listen(s, 5) < 0) {
		close(s);
		ਵਾਪਸ (-1);
	}
	ਵਾਪਸ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ਪੂਰਨ
remote_connect(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ਪੋਰਟ, ਬਣਤਰ addrinfo hints)
{
	ਬਣਤਰ addrinfo *res, *res0;
	ਪੂਰਨ s, error;
#ਜੇ defined(SO_RTABLE) || defined(SO_BINDANY)
	ਪੂਰਨ on = 1;
#ਜੇ_ਅੰਤ

	ਜੇ ((error = getaddrinfo(host, ਪੋਰਟ, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ਕਰੋ {
		ਜੇ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ਜਾਰੀ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_RTABLE
		ਜੇ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ਆਕਾਰ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#ਜੇ_ਅੰਤ
		/* Bind to a local port or source address if specified. */
		ਜੇ (sflag || pflag) {
			ਬਣਤਰ addrinfo ahints, *ares;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, ਆਕਾਰ(on));
#ਜੇ_ਅੰਤ
			memset(&ahints, 0, ਆਕਾਰ(ਬਣਤਰ addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ਜੇ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ਜੇ (bind(s, (ਬਣਤਰ sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		ਸੈੱਟ_common_sockopts(s, res0->ai_family);

		ਜੇ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ਰੋਕੋ;
		ਨਹੀਂਤਾਂ ਜੇ (vflag)
			warn("connect to %s port %s (%s) failed", host, ਪੋਰਟ,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ਜਦੋਂ ((res0 = res0->ai_next) != ਨਿਰਾ);

	freeaddrinfo(res);

	ਵਾਪਸ (s);
}

ਪੂਰਨ
timeout_connect(ਪੂਰਨ s, ਅਚਲ ਬਣਤਰ sockaddr *name, socklen_t namelen)
{
	ਬਣਤਰ pollfd pfd;
	socklen_t optlen;
	ਪੂਰਨ flags = 0, optval;
	ਪੂਰਨ ret;

	ਜੇ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ਜੇ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ਜੇ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ਜੇ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = ਆਕਾਰ(optval);
			ਜੇ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ਨਹੀਂਤਾਂ
			err(1, "poll failed");
	}

	ਜੇ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ਵਾਪਸ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ਪੂਰਨ
local_listen(ਅੱਖਰ *host, ਅੱਖਰ *ਪੋਰਟ, ਬਣਤਰ addrinfo hints)
{
	ਬਣਤਰ addrinfo *res, *res0;
	ਪੂਰਨ s, ret, x = 1;
	ਪੂਰਨ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ਜੇ (host == ਨਿਰਾ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ਜੇ ((error = getaddrinfo(host, ਪੋਰਟ, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ਕਰੋ {
		ਜੇ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ਜਾਰੀ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_RTABLE
		ਜੇ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ਆਕਾਰ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, ਆਕਾਰ(x));
		ਜੇ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, ਆਕਾਰ(x));
		ਜੇ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#ਜੇ_ਅੰਤ
		ਸੈੱਟ_common_sockopts(s, res0->ai_family);

		ਜੇ (bind(s, (ਬਣਤਰ sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ਰੋਕੋ;

		close(s);
		s = -1;
	} ਜਦੋਂ ((res0 = res0->ai_next) != ਨਿਰਾ);

	ਜੇ (!uflag && s != -1) {
		ਜੇ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ਵਾਪਸ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
ਖਾਲੀ
readwrite(ਪੂਰਨ net_fd)
{
	ਬਣਤਰ pollfd pfd[4];
	ਪੂਰਨ stdin_fd = STDIN_FILENO;
	ਪੂਰਨ stdout_fd = STDOUT_FILENO;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ netinbuf[BUFSIZE];
	ਮਾਪ_t netinbufpos = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ stdinbuf[BUFSIZE];
	ਮਾਪ_t stdinbufpos = 0;
	ਪੂਰਨ n, ਅੰਕ_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ਜੇ (dflag)
		stdin_fd = -1;

	/* stdin */
	pfd[POLL_STDIN].fd = stdin_fd;
	pfd[POLL_STDIN].events = POLLIN;

	/* network out */
	pfd[POLL_NETOUT].fd = net_fd;
	pfd[POLL_NETOUT].events = 0;

	/* network in */
	pfd[POLL_NETIN].fd = net_fd;
	pfd[POLL_NETIN].events = POLLIN;

	/* stdout */
	pfd[POLL_STDOUT].fd = stdout_fd;
	pfd[POLL_STDOUT].events = 0;

	ਜਦੋਂ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ਜੇ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ਵਾਪਸ;
		}
		/* both outputs are gone, we can't continue */
		ਜੇ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ਵਾਪਸ;
		}
		/* listen and net in gone, queues empty, done */
		ਜੇ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ਵਾਪਸ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ਜੇ (iflag)
			sleep(iflag);

		/* poll */
		ਅੰਕ_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ਜੇ (ਅੰਕ_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ਜੇ (ਅੰਕ_fds == 0)
			ਵਾਪਸ;

		/* treat socket error conditions */
		ਲਈ (n = 0; n < 4; n++) {
			ਜੇ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ਜੇ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ਜੇ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ਜੇ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ਜੇ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ਜੇ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ਜੇ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ਜੇ (pfd[POLL_STDOUT].fd == -1) {
			ਜੇ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ਜੇ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ਜੇ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ਜੇ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ਜੇ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ਜੇ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ਜੇ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ਜੇ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ਜੇ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ਜੇ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ਜੇ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ਜੇ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ਜੇ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ਜੇ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ਜੇ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ਜੇ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ਜੇ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ਜੇ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ਜੇ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ਜੇ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ਜੇ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ਜੇ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ਪੂਰਨ fd, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *buf, ਮਾਪ_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ਲਿਖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ਜੇ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ਜੇ (n <= 0)
		ਵਾਪਸ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ਜੇ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ਵਾਪਸ n;
}


ssize_t
fillbuf(ਪੂਰਨ fd, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *buf, ਮਾਪ_t *bufpos)
{
	ਮਾਪ_t ਅੰਕ = BUFSIZE - *bufpos;
	ssize_t n;

	n = ਪਠ(fd, buf + *bufpos, ਅੰਕ);
	/* don't treat EAGAIN, EINTR as error */
	ਜੇ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ਜੇ (n <= 0)
		ਵਾਪਸ n;
	*bufpos += n;
	ਵਾਪਸ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
ਖਾਲੀ
fdpass(ਪੂਰਨ nfd)
{
#ਜੇ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR) || defined(HAVE_CONTROL_ਵਿੱਚ_MSGHDR))
	ਬਣਤਰ msghdr ਸੁਨੇਹਾ;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੰਘ {
		ਬਣਤਰ cmsghdr hdr;
		ਅੱਖਰ buf[CMSG_SPACE(ਆਕਾਰ(ਪੂਰਨ))];
	} cmsgbuf;
	ਬਣਤਰ cmsghdr *cmsg;
#ਜੇ_ਅੰਤ
	ਬਣਤਰ iovec vec;
	ਅੱਖਰ ch = '\0';
	ਬਣਤਰ pollfd pfd;
	ssize_t r;

	memset(&ਸੁਨੇਹਾ, 0, ਆਕਾਰ(ਸੁਨੇਹਾ));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ACCRIGHTS_ਵਿੱਚ_MSGHDR
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrights = (caddr_t)&nfd;
	ਸੁਨੇਹਾ.ਸੁਨੇਹਾ_accrightslen = ਆਕਾਰ(nfd);
#ਨਹੀਂਤਾਂ
	memset(&cmsgbuf, 0, ਆਕਾਰ(cmsgbuf));
	ਸੁਨੇਹਾ.msg_control = (caddr_t)&cmsgbuf.buf;
	ਸੁਨੇਹਾ.msg_controllen = ਆਕਾਰ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ਸੁਨੇਹਾ);
	cmsg->cmsg_len = CMSG_LEN(ਆਕਾਰ(ਪੂਰਨ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ਪੂਰਨ *)CMSG_DATA(cmsg) = nfd;
#ਜੇ_ਅੰਤ

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ਸੁਨੇਹਾ.msg_iov = &vec;
	ਸੁਨੇਹਾ.msg_iovlen = 1;

	bzero(&pfd, ਆਕਾਰ(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ਲਈ (;;) {
		r = sendmsg(STDOUT_FILENO, &ਸੁਨੇਹਾ, 0);
		ਜੇ (r == -1) {
			ਜੇ (errno == EAGAIN || errno == EINTR) {
				ਜੇ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ਜਾਰੀ;
			}
			err(1, "sendmsg");
		} ਨਹੀਂਤਾਂ ਜੇ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	ਬਾਹਰ_ਨਿਕਲੋ(0);
#ਨਹੀਂਤਾਂ
	errx(1, "%s: file descriptor passing not supported", __func__);
#ਜੇ_ਅੰਤ
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
ਖਾਲੀ
atelnet(ਪੂਰਨ nfd, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *buf, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ ਮਾਪ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *p, *ਸਿਰਾ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ obuf[4];

	ਜੇ (ਮਾਪ < 3)
		ਵਾਪਸ;
	ਸਿਰਾ = buf + ਮਾਪ - 2;

	ਲਈ (p = buf; p < ਸਿਰਾ; p++) {
		ਜੇ (*p != IAC)
			ਜਾਰੀ;

		obuf[0] = IAC;
		p++;
		ਜੇ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ਨਹੀਂਤਾਂ ਜੇ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ਨਹੀਂਤਾਂ
			ਜਾਰੀ;

		p++;
		obuf[2] = *p;
		ਜੇ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
ਖਾਲੀ
build_ports(ਅੱਖਰ *p)
{
	ਅਚਲ ਅੱਖਰ *errstr;
	ਅੱਖਰ *n;
	ਪੂਰਨ hi, lo, cp;
	ਪੂਰਨ x = 0;

	ਜੇ ((n = strchr(p, '-')) != ਨਿਰਾ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, ਪੋਰਟ_MAX, &errstr);
		ਜੇ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, ਪੋਰਟ_MAX, &errstr);
		ਜੇ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ਜੇ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ਲਈ (cp = lo; cp <= hi; cp++) {
			portlist[x] = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਪੋਰਟ_MAX_LEN);
			ਜੇ (portlist[x] == ਨਿਰਾ)
				errx(1, "calloc");
			snprintf(portlist[x], ਪੋਰਟ_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ਜੇ (rflag) {
			ਪੂਰਨ y;
			ਅੱਖਰ *c;

			ਲਈ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_ਇਕਸਾਰ(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ਨਹੀਂਤਾਂ {
		hi = strtonum(p, 1, ਪੋਰਟ_MAX, &errstr);
		ਜੇ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ਜੇ (portlist[0] == ਨਿਰਾ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ਪੂਰਨ
udptest(ਪੂਰਨ s)
{
	ਪੂਰਨ i, ret;

	ਲਈ (i = 0; i <= 3; i++) {
		ਜੇ (ਲਿਖ(s, "X", 1) == 1)
			ret = 1;
		ਨਹੀਂਤਾਂ
			ret = -1;
	}
	ਵਾਪਸ (ret);
}

ਖਾਲੀ
ਸੈੱਟ_common_sockopts(ਪੂਰਨ s, ਪੂਰਨ af)
{
	ਪੂਰਨ x = 1;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TCP_MD5SIG
	ਜੇ (Sflag) {
		ਜੇ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, ਆਕਾਰ(x)) == -1)
			err(1, "setsockopt");
	}
#ਜੇ_ਅੰਤ
	ਜੇ (Dflag) {
		ਜੇ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, ਆਕਾਰ(x)) == -1)
			err(1, "setsockopt");
	}
#ਜੇ defined(IP_TOS) && defined(IPV6_TCLASS)
	ਜੇ (Tflag != -1) {
		ਪੂਰਨ proto, option;

		ਜੇ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ਨਹੀਂਤਾਂ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ਜੇ (setsockopt(s, proto, option, &Tflag, ਆਕਾਰ(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#ਜੇ_ਅੰਤ
	ਜੇ (Iflag) {
		ਜੇ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, ਆਕਾਰ(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ਜੇ (Oflag) {
		ਜੇ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, ਆਕਾਰ(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ਪੂਰਨ
map_tos(ਅੱਖਰ *s, ਪੂਰਨ *val)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ਅਚਲ ਬਣਤਰ toskeywords {
		ਅਚਲ ਅੱਖਰ	*keyword;
		ਪੂਰਨ		 val;
	} *t, toskeywords[] = {
		{ "af11",		IPTOS_DSCP_AF11 },
		{ "af12",		IPTOS_DSCP_AF12 },
		{ "af13",		IPTOS_DSCP_AF13 },
		{ "af21",		IPTOS_DSCP_AF21 },
		{ "af22",		IPTOS_DSCP_AF22 },
		{ "af23",		IPTOS_DSCP_AF23 },
		{ "af31",		IPTOS_DSCP_AF31 },
		{ "af32",		IPTOS_DSCP_AF32 },
		{ "af33",		IPTOS_DSCP_AF33 },
		{ "af41",		IPTOS_DSCP_AF41 },
		{ "af42",		IPTOS_DSCP_AF42 },
		{ "af43",		IPTOS_DSCP_AF43 },
		{ "critical",		IPTOS_PREC_CRITIC_ECP },
		{ "cs0",		IPTOS_DSCP_CS0 },
		{ "cs1",		IPTOS_DSCP_CS1 },
		{ "cs2",		IPTOS_DSCP_CS2 },
		{ "cs3",		IPTOS_DSCP_CS3 },
		{ "cs4",		IPTOS_DSCP_CS4 },
		{ "cs5",		IPTOS_DSCP_CS5 },
		{ "cs6",		IPTOS_DSCP_CS6 },
		{ "cs7",		IPTOS_DSCP_CS7 },
		{ "ef",			IPTOS_DSCP_EF },
		{ "inetcontrol",	IPTOS_PREC_INTERNETCONTROL },
		{ "lowdelay",		IPTOS_LOWDELAY },
		{ "netcontrol",		IPTOS_PREC_NETCONTROL },
		{ "reliability",	IPTOS_RELIABILITY },
		{ "throughput",		IPTOS_THROUGHPUT },
		{ ਨਿਰਾ, 		-1 },
	};

	ਲਈ (t = toskeywords; t->keyword != ਨਿਰਾ; t++) {
		ਜੇ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ਵਾਪਸ (1);
		}
	}
#ਜੇ_ਅੰਤ

	ਵਾਪਸ (0);
}

ਖਾਲੀ
report_connect(ਅਚਲ ਬਣਤਰ sockaddr *sa, socklen_t salen)
{
	ਅੱਖਰ remote_host[NI_MAXHOST];
	ਅੱਖਰ remote_ਪੋਰਟ[NI_MAXSERV];
	ਪੂਰਨ herr;
	ਪੂਰਨ flags = NI_NUMERICSERV;
	
	ਜੇ (nflag)
		flags |= NI_NUMERICHOST;
	
	ਜੇ ((herr = getnameinfo(sa, salen,
	    remote_host, ਆਕਾਰ(remote_host),
	    remote_ਪੋਰਟ, ਆਕਾਰ(remote_ਪੋਰਟ),
	    flags)) != 0) {
		ਜੇ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ਨਹੀਂਤਾਂ
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_ਪੋਰਟ);
}

ਖਾਲੀ
help(ਖਾਲੀ)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n\
	\t-F		Pass socket fd\n\
	\t-h		This help ਪਾਠ\n\
	\t-I ਲੰਮਾਈ	TCP receive ਬਫਰ ਲੰਮਾਈ\n\
	\t-i secs\t	Delay interval ਲਈ ਸਤਰਾਂ ਭੇਜਿਆ, ports scanned\n\
	\t-k		Keep inbound sockets open ਲਈ ਗੁਣਜ connects\n\
	\t-l		Listen ਬਹੁਲਕ, ਲਈ inbound connects\n\
	\t-N		Shutdown the ਜਾਲ socket after EOF on stdin\n\
	\t-n		Suppress name/ਪੋਰਟ resolutions\n\
	\t-O ਲੰਮਾਈ	TCP send ਬਫਰ ਲੰਮਾਈ\n\
	\t-P proxyuser\tUsername ਲਈ proxy authentication\n\
	\t-p ਪੋਰਟ\t	Specify local ਪੋਰਟ ਲਈ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local ਸਰੋਤ ਪਤਾ\n\
	\t-T toskeyword\t_ਸੈੱਟ IP Type ਦਾ Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP ਬਹੁਲਕ\n\
	\t-V rtable	Specify alternate routing ਸਾਰਣੀ\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ਲਈ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:ਪੋਰਟ]\tSpecify proxy ਪਤਾ and ਪੋਰਟ\n\
	\t-z		Zero-I/O ਬਹੁਲਕ [ਵਰਤਿਆ ਲਈ scanning]\n\
	ਪੋਰਟ_2 numbers can be individual or ranges: lo-hi [inclusive]\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਖਾਲੀ
usage(ਪੂਰਨ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ਜੇ (ret)
		ਬਾਹਰ_ਨਿਕਲੋ(1);
}

/* *** src/usr.bin/nc/socks.c *** */


/*	$OpenBSD: socks.c,v 1.20 2012/03/08 09:56:28 espie Exp $	*/

/*
 * Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <resolv.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_ਪੋਰਟ	"1080"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HTTP_PROXY_ਪੋਰਟ	"3128"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HTTP_MAXHDRS	64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_V5	5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_V4	4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_NOAUTH	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_NOMETHOD	0xff
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_CONNECT	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_IPV4	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_DOMAIN	3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKS_IPV6	4

ਪੂਰਨ	remote_connect(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo);
ਪੂਰਨ	socks_connect(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo,
	    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ addrinfo, ਪੂਰਨ,
	    ਅਚਲ ਅੱਖਰ *);

ਸਥਿਰ ਪੂਰਨ
decode_addrport(ਅਚਲ ਅੱਖਰ *h, ਅਚਲ ਅੱਖਰ *p, ਬਣਤਰ sockaddr *addr,
    socklen_t addrlen, ਪੂਰਨ v4only, ਪੂਰਨ numeric)
{
	ਪੂਰਨ r;
	ਬਣਤਰ addrinfo hints, *res;

	bzero(&hints, ਆਕਾਰ(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ਜੇ (r != 0) {
		ਜੇ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ਵਾਪਸ (-1);
	}
	ਜੇ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
proxy_read_ਸਤਰ(ਪੂਰਨ fd, ਅੱਖਰ *buf, ਮਾਪ_t bufsz)
{
	ਮਾਪ_t off;

	ਲਈ(off = 0;;) {
		ਜੇ (off >= bufsz)
			errx(1, "proxy read too long");
		ਜੇ (atomicio(ਪਠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ਜੇ (buf[off] == '\r')
			ਜਾਰੀ;
		ਜੇ (buf[off] == '\n') {
			buf[off] = '\0';
			ਰੋਕੋ;
		}
		off++;
	}
	ਵਾਪਸ (off);
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
getproxypass(ਅਚਲ ਅੱਖਰ *proxyuser, ਅਚਲ ਅੱਖਰ *proxyhost)
{
	ਅੱਖਰ prompt[512];
	ਸਥਿਰ ਅੱਖਰ pw[256];

	snprintf(prompt, ਆਕਾਰ(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ਜੇ (readpassphrase(prompt, pw, ਆਕਾਰ(pw), RPP_REQUIRE_TTY) == ਨਿਰਾ)
		errx(1, "Unable to read proxy passphrase");
	ਵਾਪਸ (pw);
}

ਪੂਰਨ
socks_connect(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ਪੋਰਟ,
    ਬਣਤਰ addrinfo hints __attribute__ ((__unused__)),
    ਅਚਲ ਅੱਖਰ *proxyhost, ਅਚਲ ਅੱਖਰ *proxyport, ਬਣਤਰ addrinfo proxyhints,
    ਪੂਰਨ socksv, ਅਚਲ ਅੱਖਰ *proxyuser)
{
	ਪੂਰਨ proxyfd, r, authretry = 0;
	ਮਾਪ_t hlen, wlen = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ buf[1024];
	ਮਾਪ_t cnt;
	ਬਣਤਰ sockaddr_storage addr;
	ਬਣਤਰ sockaddr_in *in4 = (ਬਣਤਰ sockaddr_in *)&addr;
	ਬਣਤਰ sockaddr_in6 *in6 = (ਬਣਤਰ sockaddr_in6 *)&addr;
	in_port_t serverport;
	ਅਚਲ ਅੱਖਰ *proxypass = ਨਿਰਾ;

	ਜੇ (proxyport == ਨਿਰਾ)
		proxyport = (socksv == -1) ? HTTP_PROXY_ਪੋਰਟ : SOCKS_ਪੋਰਟ;

	/* Abuse API to lookup port */
	ਜੇ (decode_addrport("0.0.0.0", ਪੋਰਟ, (ਬਣਤਰ sockaddr *)&addr,
	    ਆਕਾਰ(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", ਪੋਰਟ);
	serverport = in4->sin_port;

 again:
	ਜੇ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ਜੇ (proxyfd < 0)
		ਵਾਪਸ (-1);

	ਜੇ (socksv == 5) {
		ਜੇ (decode_addrport(host, ਪੋਰਟ, (ਬਣਤਰ sockaddr *)&addr,
		    ਆਕਾਰ(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ਜੇ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(ਪਠ, proxyfd, buf, 2);
		ਜੇ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ਜੇ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		ਚੋਣ (addr.ss_family) {
		ਹਾਲਤ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = ਲੜੀ_ਲੰਬਾਈ(host);
			ਜੇ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 5, host, hlen);			
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 5 + hlen, &serverport, ਆਕਾਰ serverport);
			wlen = 7 + hlen;
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 4, &in4->sin_addr, ਆਕਾਰ in4->sin_addr);
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 8, &in4->sin_port, ਆਕਾਰ in4->sin_port);
			wlen = 10;
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 4, &in6->sin6_addr, ਆਕਾਰ in6->sin6_addr);
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 20, &in6->sin6_port,
			    ਆਕਾਰ in6->sin6_port);
			wlen = 22;
			ਰੋਕੋ;
		ਮੂਲ:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ਜੇ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ਪਠ, proxyfd, buf, 4);
		ਜੇ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ਜੇ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		ਚੋਣ (buf[3]) {
		ਹਾਲਤ SOCKS_IPV4:
			cnt = atomicio(ਪਠ, proxyfd, buf + 4, 6);
			ਜੇ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ਰੋਕੋ;
		ਹਾਲਤ SOCKS_IPV6:
			cnt = atomicio(ਪਠ, proxyfd, buf + 4, 18);
			ਜੇ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ਰੋਕੋ;
		ਮੂਲ:
			errx(1, "connection failed, unsupported address type");
		}
	} ਨਹੀਂਤਾਂ ਜੇ (socksv == 4 || socksv == 44) {
		ਜੇ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, ਪੋਰਟ, (ਬਣਤਰ sockaddr *)&addr,
			    ਆਕਾਰ(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 2, &in4->sin_port, ਆਕਾਰ in4->sin_port);
		ਜੇ (socksv == 4) {
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf + 4, &in4->sin_addr, ਆਕਾਰ in4->sin_addr);
		} ਨਹੀਂਤਾਂ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ਜੇ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ਜੇ (strlcpy(buf + 9, host,
			    ਆਕਾਰ(buf) - 9) >= ਆਕਾਰ(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + ਲੜੀ_ਲੰਬਾਈ(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ਜੇ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ਪਠ, proxyfd, buf, 8);
		ਜੇ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ਜੇ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ਨਹੀਂਤਾਂ ਜੇ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ਜੇ (strcspn(host, "\r\n\t []:") != ਲੜੀ_ਲੰਬਾਈ(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ਜੇ (strchr(host, ':') != ਨਿਰਾ) {
			r = snprintf(buf, ਆਕਾਰ(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ਨਹੀਂਤਾਂ {
			r = snprintf(buf, ਆਕਾਰ(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ਜੇ (r == -1 || (ਮਾਪ_t)r >= ਆਕਾਰ(buf))
			errx(1, "hostname too long");
		r = ਲੜੀ_ਲੰਬਾਈ(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ਜੇ (cnt != (ਮਾਪ_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ਜੇ (authretry > 1) {
			ਅੱਖਰ resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, ਆਕਾਰ(buf), "%s:%s",
			    proxyuser, proxypass);
			ਜੇ (r == -1 || (ਮਾਪ_t)r >= ਆਕਾਰ(buf) ||
			    b64_ntop(buf, ਲੜੀ_ਲੰਬਾਈ(buf), resp,
			    ਆਕਾਰ(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, ਆਕਾਰ(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ਜੇ (r == -1 || (ਮਾਪ_t)r >= ਆਕਾਰ(buf))
				errx(1, "Proxy auth response too long");
			r = ਲੜੀ_ਲੰਬਾਈ(buf);
			ਜੇ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (ਮਾਪ_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ਜੇ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ਸਤਰ(proxyfd, buf, ਆਕਾਰ(buf));
		ਜੇ (proxyuser != ਨਿਰਾ &&
		    ਲੜੀ_ਤੁਲਨਾ(buf, "HTTP/1.0 407 ", 12) == 0) {
			ਜੇ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			ਜਾਓ again;
		} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    ਲੜੀ_ਤੁਲਨਾ(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ਲਈ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ਸਤਰ(proxyfd, buf, ਆਕਾਰ(buf));
			ਜੇ (*buf == '\0')
				ਰੋਕੋ;
		}
		ਜੇ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ਨਹੀਂਤਾਂ
		errx(1, "Unknown proxy protocol %d", socksv);

	ਵਾਪਸ (proxyfd);
}

