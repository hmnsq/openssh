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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/tcp.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ "atomicio.h"

#ಅನ್ತರ್ಭಾವ <poll.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ERR_H
# include <err.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#ಆದರೆ_ಅಂತ್ಯ

/* rename to avoid collision in libssh */
#ವ್ಯಾಖ್ಯಾನಿಸು timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#ವ್ಯಾಖ್ಯಾನಿಸು IAC	255
#ವ್ಯಾಖ್ಯಾನಿಸು DONT	254
#ವ್ಯಾಖ್ಯಾನಿಸು DO	253
#ವ್ಯಾಖ್ಯಾನಿಸು WONT	252
#ವ್ಯಾಖ್ಯಾನಿಸು WILL	251

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SUN_LEN
#ವ್ಯಾಖ್ಯಾನಿಸು SUN_LEN(su) \
	(ಗಾತ್ರ(*(su)) - ಗಾತ್ರ((su)->sun_ಮಾರ್ಗ) + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ((su)->sun_ಮಾರ್ಗ))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು ಪೋರ್ಟ್_MAX	65535
#ವ್ಯಾಖ್ಯಾನಿಸು ಪೋರ್ಟ್_MAX_LEN	6
#ವ್ಯಾಖ್ಯಾನಿಸು UNIX_DG_TMP_SOCKET_ಗಾತ್ರ	19

#ವ್ಯಾಖ್ಯಾನಿಸು POLL_STDIN 0
#ವ್ಯಾಖ್ಯಾನಿಸು POLL_NETOUT 1
#ವ್ಯಾಖ್ಯಾನಿಸು POLL_NETIN 2
#ವ್ಯಾಖ್ಯಾನಿಸು POLL_STDOUT 3
#ವ್ಯಾಖ್ಯಾನಿಸು BUFSIZE 16384

/* Command Line Options */
ಪೂರ್ಣಾಂಕ	dflag;					/* detached, no stdin */
ಪೂರ್ಣಾಂಕ	Fflag;					/* fdpass sock to stdout */
ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ iflag;				/* Interval Flag */
ಪೂರ್ಣಾಂಕ	kflag;					/* More than one connect */
ಪೂರ್ಣಾಂಕ	lflag;					/* Bind to local port */
ಪೂರ್ಣಾಂಕ	Nflag;					/* shutdown() network socket */
ಪೂರ್ಣಾಂಕ	nflag;					/* Don't do name look up */
ಅಕ್ಷರ   *Pflag;					/* Proxy username */
ಅಕ್ಷರ   *pflag;					/* Localport flag */
ಪೂರ್ಣಾಂಕ	rflag;					/* Random ports flag */
ಅಕ್ಷರ   *sflag;					/* Source Address */
ಪೂರ್ಣಾಂಕ	tflag;					/* Telnet Emulation */
ಪೂರ್ಣಾಂಕ	uflag;					/* UDP - Default to TCP */
ಪೂರ್ಣಾಂಕ	vflag;					/* Verbosity */
ಪೂರ್ಣಾಂಕ	xflag;					/* Socks proxy */
ಪೂರ್ಣಾಂಕ	zflag;					/* Port Scan Flag */
ಪೂರ್ಣಾಂಕ	Dflag;					/* sodebug */
ಪೂರ್ಣಾಂಕ	Iflag;					/* TCP receive buffer size */
ಪೂರ್ಣಾಂಕ	Oflag;					/* TCP send buffer size */
ಪೂರ್ಣಾಂಕ	Sflag;					/* TCP MD5 signature option */
ಪೂರ್ಣಾಂಕ	Tflag = -1;				/* IP Type of Service */
ಪೂರ್ಣಾಂಕ	rtableid = -1;

ಪೂರ್ಣಾಂಕ timeout = -1;
ಪೂರ್ಣಾಂಕ family = AF_UNSPEC;
ಅಕ್ಷರ *portlist[ಪೋರ್ಟ್_MAX+1];
ಅಕ್ಷರ *unix_dg_tmp_socket;

ಶೂನ್ಯ	atelnet(ಪೂರ್ಣಾಂಕ, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	build_ports(ಅಕ್ಷರ *);
ಶೂನ್ಯ	help(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	local_listen(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ರಚನೆ addrinfo);
ಶೂನ್ಯ	readwrite(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	fdpass(ಪೂರ್ಣಾಂಕ nfd) __attribute__((noreturn));
ಪೂರ್ಣಾಂಕ	remote_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo);
ಪೂರ್ಣಾಂಕ	timeout_connect(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *, socklen_t);
ಪೂರ್ಣಾಂಕ	socks_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	udptest(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	unix_bind(ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	unix_connect(ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	unix_listen(ಅಕ್ಷರ *);
ಶೂನ್ಯ	ಗಣ_common_sockopts(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	map_tos(ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *);
ಶೂನ್ಯ	report_connect(ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *, socklen_t);
ಶೂನ್ಯ	usage(ಪೂರ್ಣಾಂಕ);
ssize_t drainbuf(ಪೂರ್ಣಾಂಕ, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಗಾತ್ರ_t *);
ssize_t fillbuf(ಪೂರ್ಣಾಂಕ, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *, ಗಾತ್ರ_t *);


ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *argv[])
{
	ಪೂರ್ಣಾಂಕ ch, s, ret, socksv;
	ಅಕ್ಷರ *host, *uport;
	ರಚನೆ addrinfo hints;
	ರಚನೆ servent *sv;
	socklen_t len;
	ರಚನೆ sockaddr_storage cliaddr;
	ಅಕ್ಷರ *proxy = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr, *proxyhost = "", *proxyport = ಖಾಲಿ;
	ರಚನೆ addrinfo proxyhints;
	ಅಕ್ಷರ unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_ಗಾತ್ರ];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ಖಾಲಿ;
	uport = ಖಾಲಿ;
	sv = ಖಾಲಿ;

	ಸಂಕೇತ(SIGPIPE, SIG_IGN);

	ಆಗ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ '4':
			family = AF_INET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '6':
			family = AF_INET6;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'U':
			family = AF_UNIX;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'X':
			ಆದರೆ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ಇಲ್ಲದಿದ್ದರೆ
				errx(1, "unsupported proxy protocol");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			dflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'F':
			Fflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			help();
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ಆದರೆ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			kflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			lflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'N':
			Nflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'n':
			nflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			Pflag = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			pflag = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			rflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			sflag = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			tflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			uflag = 1;
			ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_RTABLE
		ಸ್ಥಿತಿ 'V':
			rtableid = (ಪೂರ್ಣಾಂಕ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ಆದರೆ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
		ಸ್ಥಿತಿ 'v':
			vflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'w':
			timeout = strtonum(optarg, 0, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / 1000, &errstr);
			ಆದರೆ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'x':
			xflag = 1;
			ಆದರೆ ((proxy = strdup(optarg)) == ಖಾಲಿ)
				errx(1, "strdup");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'z':
			zflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			Dflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ಆದರೆ (errstr != ಖಾಲಿ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ಆದರೆ (errstr != ಖಾಲಿ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			Sflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			errstr = ಖಾಲಿ;
			errno = 0;
			ಆದರೆ (map_tos(optarg, &Tflag))
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ಪೂರ್ಣಾಂಕ)strtol(optarg, ಖಾಲಿ, 16);
			ಇಲ್ಲದಿದ್ದರೆ
				Tflag = (ಪೂರ್ಣಾಂಕ)strtonum(optarg, 0, 255,
				    &errstr);
			ಆದರೆ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ಆದರೆ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argv[0] && !argv[1]) {
		ಆದರೆ  (!lflag)
			usage(1);
		uport = argv[0];
		host = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ಇಲ್ಲದಿದ್ದರೆ
		usage(1);

	ಆದರೆ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ಆದರೆ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ಆದರೆ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ಆದರೆ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ಆದರೆ ((family == AF_UNIX) && uflag && !lflag) {
		ಆದರೆ (sflag) {
			unix_dg_tmp_socket = sflag;
		} ಇಲ್ಲದಿದ್ದರೆ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_ಗಾತ್ರ);
			ಆದರೆ (mktemp(unix_dg_tmp_socket_buf) == ಖಾಲಿ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ಆದರೆ (family != AF_UNIX) {
		memset(&hints, 0, ಗಾತ್ರ(ರಚನೆ addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ಆದರೆ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ಆದರೆ (xflag) {
		ಆದರೆ (uflag)
			errx(1, "no proxy support for UDP mode");

		ಆದರೆ (lflag)
			errx(1, "no proxy support for listen");

		ಆದರೆ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ಆದರೆ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ಆದರೆ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, ಗಾತ್ರ(ರಚನೆ addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ಆದರೆ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ಆದರೆ (lflag) {
		ಪೂರ್ಣಾಂಕ connfd;
		ret = 0;

		ಆದರೆ (family == AF_UNIX) {
			ಆದರೆ (uflag)
				s = unix_bind(host);
			ಇಲ್ಲದಿದ್ದರೆ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ಗಾಗಿ (;;) {
			ಆದರೆ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ಆದರೆ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ಆದರೆ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (uflag && !kflag) {
				ಪೂರ್ಣಾಂಕ rv, plen;
				ಅಕ್ಷರ buf[16384];
				ರಚನೆ sockaddr_storage z;

				len = ಗಾತ್ರ(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ರಚನೆ sockaddr *)&z, &len);
				ಆದರೆ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ರಚನೆ sockaddr *)&z, len);
				ಆದರೆ (rv < 0)
					err(1, "connect");

				ಆದರೆ (vflag)
					report_connect((ರಚನೆ sockaddr *)&z, len);

				readwrite(s);
			} ಇಲ್ಲದಿದ್ದರೆ {
				len = ಗಾತ್ರ(cliaddr);
				connfd = accept(s, (ರಚನೆ sockaddr *)&cliaddr,
				    &len);
				ಆದರೆ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ಆದರೆ (vflag)
					report_connect((ರಚನೆ sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ಆದರೆ (family != AF_UNIX)
				close(s);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (uflag) {
				ಆದರೆ (connect(s, ಖಾಲಿ, 0) < 0)
					err(1, "connect");
			}

			ಆದರೆ (!kflag)
				ನಿಲ್ಲಿಸು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (family == AF_UNIX) {
		ret = 0;

		ಆದರೆ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ಇಲ್ಲದಿದ್ದರೆ
			ret = 1;

		ಆದರೆ (uflag)
			unlink(unix_dg_tmp_socket);
		ನಿರ್ಗಮಿಸು(ret);

	} ಇಲ್ಲದಿದ್ದರೆ {
		ಪೂರ್ಣಾಂಕ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ಗಾಗಿ (i = 0; portlist[i] != ಖಾಲಿ; i++) {
			ಆದರೆ (s)
				close(s);

			ಆದರೆ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ಇಲ್ಲದಿದ್ದರೆ
				s = remote_connect(host, portlist[i], hints);

			ಆದರೆ (s < 0)
				ಮುಂದುವರಿ;

			ret = 0;
			ಆದರೆ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ಆದರೆ (uflag) {
					ಆದರೆ (udptest(s) == -1) {
						ret = 1;
						ಮುಂದುವರಿ;
					}
				}

				/* Don't look up port if -n. */
				ಆದರೆ (nflag)
					sv = ಖಾಲಿ;
				ಇಲ್ಲದಿದ್ದರೆ {
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
			ಆದರೆ (Fflag)
				fdpass(s);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!zflag)
				readwrite(s);
		}
	}

	ಆದರೆ (s)
		close(s);

	ನಿರ್ಗಮಿಸು(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ಪೂರ್ಣಾಂಕ
unix_bind(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sockaddr_un sun_sa;
	ಪೂರ್ಣಾಂಕ s;

	/* Create unix domain socket. */
	ಆದರೆ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ಹಿಂತಿರುಗಿ (-1);

	memset(&sun_sa, 0, ಗಾತ್ರ(ರಚನೆ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ಆದರೆ (strlcpy(sun_sa.sun_ಮಾರ್ಗ, ಮಾರ್ಗ, ಗಾತ್ರ(sun_sa.sun_ಮಾರ್ಗ)) >=
	    ಗಾತ್ರ(sun_sa.sun_ಮಾರ್ಗ)) {
		close(s);
		errno = ENAMETOOLONG;
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಆದರೆ (bind(s, (ರಚನೆ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
unix_connect(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sockaddr_un sun_sa;
	ಪೂರ್ಣಾಂಕ s;

	ಆದರೆ (uflag) {
		ಆದರೆ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ಹಿಂತಿರುಗಿ (-1);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ಹಿಂತಿರುಗಿ (-1);
	}
	(ಶೂನ್ಯ)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, ಗಾತ್ರ(ರಚನೆ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ಆದರೆ (strlcpy(sun_sa.sun_ಮಾರ್ಗ, ಮಾರ್ಗ, ಗಾತ್ರ(sun_sa.sun_ಮಾರ್ಗ)) >=
	    ಗಾತ್ರ(sun_sa.sun_ಮಾರ್ಗ)) {
		close(s);
		errno = ENAMETOOLONG;
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (connect(s, (ರಚನೆ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ಪೂರ್ಣಾಂಕ
unix_listen(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಪೂರ್ಣಾಂಕ s;
	ಆದರೆ ((s = unix_bind(ಮಾರ್ಗ)) < 0)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ (listen(s, 5) < 0) {
		close(s);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಹಿಂತಿರುಗಿ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
remote_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪೋರ್ಟ್, ರಚನೆ addrinfo hints)
{
	ರಚನೆ addrinfo *res, *res0;
	ಪೂರ್ಣಾಂಕ s, error;
#ಆದರೆ defined(SO_RTABLE) || defined(SO_BINDANY)
	ಪೂರ್ಣಾಂಕ on = 1;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((error = getaddrinfo(host, ಪೋರ್ಟ್, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ಮಾಡು {
		ಆದರೆ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ಮುಂದುವರಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_RTABLE
		ಆದರೆ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ಗಾತ್ರ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#ಆದರೆ_ಅಂತ್ಯ
		/* Bind to a local port or source address if specified. */
		ಆದರೆ (sflag || pflag) {
			ರಚನೆ addrinfo ahints, *ares;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, ಗಾತ್ರ(on));
#ಆದರೆ_ಅಂತ್ಯ
			memset(&ahints, 0, ಗಾತ್ರ(ರಚನೆ addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ಆದರೆ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ಆದರೆ (bind(s, (ರಚನೆ sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		ಗಣ_common_sockopts(s, res0->ai_family);

		ಆದರೆ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ನಿಲ್ಲಿಸು;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (vflag)
			warn("connect to %s port %s (%s) failed", host, ಪೋರ್ಟ್,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ಆಗ ((res0 = res0->ai_next) != ಖಾಲಿ);

	freeaddrinfo(res);

	ಹಿಂತಿರುಗಿ (s);
}

ಪೂರ್ಣಾಂಕ
timeout_connect(ಪೂರ್ಣಾಂಕ s, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *name, socklen_t namelen)
{
	ರಚನೆ pollfd pfd;
	socklen_t optlen;
	ಪೂರ್ಣಾಂಕ flags = 0, optval;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ಆದರೆ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ಆದರೆ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ಆದರೆ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = ಗಾತ್ರ(optval);
			ಆದರೆ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ಇಲ್ಲದಿದ್ದರೆ
			err(1, "poll failed");
	}

	ಆದರೆ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ಹಿಂತಿರುಗಿ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
local_listen(ಅಕ್ಷರ *host, ಅಕ್ಷರ *ಪೋರ್ಟ್, ರಚನೆ addrinfo hints)
{
	ರಚನೆ addrinfo *res, *res0;
	ಪೂರ್ಣಾಂಕ s, ret, x = 1;
	ಪೂರ್ಣಾಂಕ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ಆದರೆ (host == ಖಾಲಿ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ಆದರೆ ((error = getaddrinfo(host, ಪೋರ್ಟ್, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ಮಾಡು {
		ಆದರೆ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ಮುಂದುವರಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_RTABLE
		ಆದರೆ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ಗಾತ್ರ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, ಗಾತ್ರ(x));
		ಆದರೆ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, ಗಾತ್ರ(x));
		ಆದರೆ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#ಆದರೆ_ಅಂತ್ಯ
		ಗಣ_common_sockopts(s, res0->ai_family);

		ಆದರೆ (bind(s, (ರಚನೆ sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ನಿಲ್ಲಿಸು;

		close(s);
		s = -1;
	} ಆಗ ((res0 = res0->ai_next) != ಖಾಲಿ);

	ಆದರೆ (!uflag && s != -1) {
		ಆದರೆ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ಹಿಂತಿರುಗಿ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
ಶೂನ್ಯ
readwrite(ಪೂರ್ಣಾಂಕ net_fd)
{
	ರಚನೆ pollfd pfd[4];
	ಪೂರ್ಣಾಂಕ stdin_fd = STDIN_FILENO;
	ಪೂರ್ಣಾಂಕ stdout_fd = STDOUT_FILENO;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ netinbuf[BUFSIZE];
	ಗಾತ್ರ_t netinbufpos = 0;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ stdinbuf[BUFSIZE];
	ಗಾತ್ರ_t stdinbufpos = 0;
	ಪೂರ್ಣಾಂಕ n, ಅಂಕೆ_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ಆದರೆ (dflag)
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

	ಆಗ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ಆದರೆ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ಹಿಂತಿರುಗಿ;
		}
		/* both outputs are gone, we can't continue */
		ಆದರೆ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ಹಿಂತಿರುಗಿ;
		}
		/* listen and net in gone, queues empty, done */
		ಆದರೆ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ಹಿಂತಿರುಗಿ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ಆದರೆ (iflag)
			sleep(iflag);

		/* poll */
		ಅಂಕೆ_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ಆದರೆ (ಅಂಕೆ_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ಆದರೆ (ಅಂಕೆ_fds == 0)
			ಹಿಂತಿರುಗಿ;

		/* treat socket error conditions */
		ಗಾಗಿ (n = 0; n < 4; n++) {
			ಆದರೆ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ಆದರೆ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ಆದರೆ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ಆದರೆ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ಆದರೆ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ಆದರೆ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ಆದರೆ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ಆದರೆ (pfd[POLL_STDOUT].fd == -1) {
			ಆದರೆ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ಆದರೆ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ಆದರೆ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ಆದರೆ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ಆದರೆ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ಆದರೆ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ಆದರೆ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ಆದರೆ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ಆದರೆ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ಆದರೆ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ಆದರೆ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ಆದರೆ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ಆದರೆ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ಆದರೆ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ಆದರೆ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ಆದರೆ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ಆದರೆ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ಆದರೆ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ಆದರೆ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ಆದರೆ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ಆದರೆ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ಆದರೆ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ಪೂರ್ಣಾಂಕ fd, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *buf, ಗಾತ್ರ_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ಲಿಖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ಆದರೆ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ಆದರೆ (n <= 0)
		ಹಿಂತಿರುಗಿ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ಆದರೆ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ಹಿಂತಿರುಗಿ n;
}


ssize_t
fillbuf(ಪೂರ್ಣಾಂಕ fd, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *buf, ಗಾತ್ರ_t *bufpos)
{
	ಗಾತ್ರ_t ಅಂಕೆ = BUFSIZE - *bufpos;
	ssize_t n;

	n = ಪಠ(fd, buf + *bufpos, ಅಂಕೆ);
	/* don't treat EAGAIN, EINTR as error */
	ಆದರೆ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ಆದರೆ (n <= 0)
		ಹಿಂತಿರುಗಿ n;
	*bufpos += n;
	ಹಿಂತಿರುಗಿ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
ಶೂನ್ಯ
fdpass(ಪೂರ್ಣಾಂಕ nfd)
{
#ಆದರೆ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_ಒಳ_MSGHDR) || defined(HAVE_CONTROL_ಒಳ_MSGHDR))
	ರಚನೆ msghdr ಸಂದೇಶ;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಒಕ್ಕೂಟ {
		ರಚನೆ cmsghdr hdr;
		ಅಕ್ಷರ buf[CMSG_SPACE(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ))];
	} cmsgbuf;
	ರಚನೆ cmsghdr *cmsg;
#ಆದರೆ_ಅಂತ್ಯ
	ರಚನೆ iovec vec;
	ಅಕ್ಷರ ch = '\0';
	ರಚನೆ pollfd pfd;
	ssize_t r;

	memset(&ಸಂದೇಶ, 0, ಗಾತ್ರ(ಸಂದೇಶ));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ACCRIGHTS_ಒಳ_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&nfd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಗಾತ್ರ(nfd);
#ಇಲ್ಲದಿದ್ದರೆ
	memset(&cmsgbuf, 0, ಗಾತ್ರ(cmsgbuf));
	ಸಂದೇಶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಗಾತ್ರ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	cmsg->cmsg_len = CMSG_LEN(ಗಾತ್ರ(ಪೂರ್ಣಾಂಕ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ಪೂರ್ಣಾಂಕ *)CMSG_DATA(cmsg) = nfd;
#ಆದರೆ_ಅಂತ್ಯ

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;

	bzero(&pfd, ಗಾತ್ರ(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ಗಾಗಿ (;;) {
		r = sendmsg(STDOUT_FILENO, &ಸಂದೇಶ, 0);
		ಆದರೆ (r == -1) {
			ಆದರೆ (errno == EAGAIN || errno == EINTR) {
				ಆದರೆ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ಮುಂದುವರಿ;
			}
			err(1, "sendmsg");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	ನಿರ್ಗಮಿಸು(0);
#ಇಲ್ಲದಿದ್ದರೆ
	errx(1, "%s: file descriptor passing not supported", __func__);
#ಆದರೆ_ಅಂತ್ಯ
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
ಶೂನ್ಯ
atelnet(ಪೂರ್ಣಾಂಕ nfd, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *buf, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_2)
{
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *p, *ಕೊನೆ;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ obuf[4];

	ಆದರೆ (ಗಾತ್ರ_2 < 3)
		ಹಿಂತಿರುಗಿ;
	ಕೊನೆ = buf + ಗಾತ್ರ_2 - 2;

	ಗಾಗಿ (p = buf; p < ಕೊನೆ; p++) {
		ಆದರೆ (*p != IAC)
			ಮುಂದುವರಿ;

		obuf[0] = IAC;
		p++;
		ಆದರೆ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ಇಲ್ಲದಿದ್ದರೆ
			ಮುಂದುವರಿ;

		p++;
		obuf[2] = *p;
		ಆದರೆ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
ಶೂನ್ಯ
build_ports(ಅಕ್ಷರ *p)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	ಅಕ್ಷರ *n;
	ಪೂರ್ಣಾಂಕ hi, lo, cp;
	ಪೂರ್ಣಾಂಕ x = 0;

	ಆದರೆ ((n = strchr(p, '-')) != ಖಾಲಿ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, ಪೋರ್ಟ್_MAX, &errstr);
		ಆದರೆ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, ಪೋರ್ಟ್_MAX, &errstr);
		ಆದರೆ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ಆದರೆ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ಗಾಗಿ (cp = lo; cp <= hi; cp++) {
			portlist[x] = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಪೋರ್ಟ್_MAX_LEN);
			ಆದರೆ (portlist[x] == ಖಾಲಿ)
				errx(1, "calloc");
			snprintf(portlist[x], ಪೋರ್ಟ್_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ಆದರೆ (rflag) {
			ಪೂರ್ಣಾಂಕ y;
			ಅಕ್ಷರ *c;

			ಗಾಗಿ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_ಏಕರೂಪ(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		hi = strtonum(p, 1, ಪೋರ್ಟ್_MAX, &errstr);
		ಆದರೆ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ಆದರೆ (portlist[0] == ಖಾಲಿ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ಪೂರ್ಣಾಂಕ
udptest(ಪೂರ್ಣಾಂಕ s)
{
	ಪೂರ್ಣಾಂಕ i, ret;

	ಗಾಗಿ (i = 0; i <= 3; i++) {
		ಆದರೆ (ಲಿಖ(s, "X", 1) == 1)
			ret = 1;
		ಇಲ್ಲದಿದ್ದರೆ
			ret = -1;
	}
	ಹಿಂತಿರುಗಿ (ret);
}

ಶೂನ್ಯ
ಗಣ_common_sockopts(ಪೂರ್ಣಾಂಕ s, ಪೂರ್ಣಾಂಕ af)
{
	ಪೂರ್ಣಾಂಕ x = 1;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TCP_MD5SIG
	ಆದರೆ (Sflag) {
		ಆದರೆ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, ಗಾತ್ರ(x)) == -1)
			err(1, "setsockopt");
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (Dflag) {
		ಆದರೆ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, ಗಾತ್ರ(x)) == -1)
			err(1, "setsockopt");
	}
#ಆದರೆ defined(IP_TOS) && defined(IPV6_TCLASS)
	ಆದರೆ (Tflag != -1) {
		ಪೂರ್ಣಾಂಕ proto, option;

		ಆದರೆ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ಇಲ್ಲದಿದ್ದರೆ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ಆದರೆ (setsockopt(s, proto, option, &Tflag, ಗಾತ್ರ(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (Iflag) {
		ಆದರೆ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, ಗಾತ್ರ(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ಆದರೆ (Oflag) {
		ಆದರೆ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, ಗಾತ್ರ(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ಪೂರ್ಣಾಂಕ
map_tos(ಅಕ್ಷರ *s, ಪೂರ್ಣಾಂಕ *val)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ಸ್ಥಿರಾಂಕ ರಚನೆ toskeywords {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*keyword;
		ಪೂರ್ಣಾಂಕ		 val;
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
		{ ಖಾಲಿ, 		-1 },
	};

	ಗಾಗಿ (t = toskeywords; t->keyword != ಖಾಲಿ; t++) {
		ಆದರೆ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ಹಿಂತಿರುಗಿ (1);
		}
	}
#ಆದರೆ_ಅಂತ್ಯ

	ಹಿಂತಿರುಗಿ (0);
}

ಶೂನ್ಯ
report_connect(ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa, socklen_t salen)
{
	ಅಕ್ಷರ remote_host[NI_MAXHOST];
	ಅಕ್ಷರ remote_ಪೋರ್ಟ್[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ herr;
	ಪೂರ್ಣಾಂಕ flags = NI_NUMERICSERV;
	
	ಆದರೆ (nflag)
		flags |= NI_NUMERICHOST;
	
	ಆದರೆ ((herr = getnameinfo(sa, salen,
	    remote_host, ಗಾತ್ರ(remote_host),
	    remote_ಪೋರ್ಟ್, ಗಾತ್ರ(remote_ಪೋರ್ಟ್),
	    flags)) != 0) {
		ಆದರೆ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ಇಲ್ಲದಿದ್ದರೆ
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_ಪೋರ್ಟ್);
}

ಶೂನ್ಯ
help(ಶೂನ್ಯ)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n\
	\t-F		Pass socket fd\n\
	\t-h		This help ಪಠ್ಯ\n\
	\t-I ಉದ್ದಳತೆ	TCP receive ಬಫರ್ ಉದ್ದಳತೆ\n\
	\t-i secs\t	Delay interval ಗಾಗಿ ಸಾಲುಗಳು ಕಳುಹಿಸಿದ, ports scanned\n\
	\t-k		Keep inbound sockets open ಗಾಗಿ ಅಪವರ್ತ್ಯ connects\n\
	\t-l		Listen ಬಹುಲಕ, ಗಾಗಿ inbound connects\n\
	\t-N		Shutdown the ಜಾಲ socket after EOF on stdin\n\
	\t-n		Suppress name/ಪೋರ್ಟ್ resolutions\n\
	\t-O ಉದ್ದಳತೆ	TCP send ಬಫರ್ ಉದ್ದಳತೆ\n\
	\t-P proxyuser\tUsername ಗಾಗಿ proxy authentication\n\
	\t-p ಪೋರ್ಟ್\t	Specify local ಪೋರ್ಟ್ ಗಾಗಿ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local ಮೂಲ ವಿಳಾಸ\n\
	\t-T toskeyword\t_ಗಣ IP Type ದ Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP ಬಹುಲಕ\n\
	\t-V rtable	Specify alternate routing ಕೋಷ್ಟಕ\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ಗಾಗಿ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:ಪೋರ್ಟ್]\tSpecify proxy ವಿಳಾಸ and ಪೋರ್ಟ್\n\
	\t-z		Zero-I/O ಬಹುಲಕ [ಬಳಸಿದ ಗಾಗಿ scanning]\n\
	ಪೋರ್ಟ್_2 numbers can be individual or ranges: lo-hi [inclusive]\n");
	ನಿರ್ಗಮಿಸು(1);
}

ಶೂನ್ಯ
usage(ಪೂರ್ಣಾಂಕ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ಆದರೆ (ret)
		ನಿರ್ಗಮಿಸು(1);
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

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <resolv.h>

#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_ಪೋರ್ಟ್	"1080"
#ವ್ಯಾಖ್ಯಾನಿಸು HTTP_PROXY_ಪೋರ್ಟ್	"3128"
#ವ್ಯಾಖ್ಯಾನಿಸು HTTP_MAXHDRS	64
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_V5	5
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_V4	4
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_NOAUTH	0
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_NOMETHOD	0xff
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_CONNECT	1
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_IPV4	1
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_DOMAIN	3
#ವ್ಯಾಖ್ಯಾನಿಸು SOCKS_IPV6	4

ಪೂರ್ಣಾಂಕ	remote_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo);
ಪೂರ್ಣಾಂಕ	socks_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ addrinfo, ಪೂರ್ಣಾಂಕ,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
decode_addrport(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *h, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, ರಚನೆ sockaddr *addr,
    socklen_t addrlen, ಪೂರ್ಣಾಂಕ v4only, ಪೂರ್ಣಾಂಕ numeric)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ addrinfo hints, *res;

	bzero(&hints, ಗಾತ್ರ(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ಆದರೆ (r != 0) {
		ಆದರೆ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	ಸ್ಮರಣೆ_ನಕಲು(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
proxy_read_ಸಾಲು(ಪೂರ್ಣಾಂಕ fd, ಅಕ್ಷರ *buf, ಗಾತ್ರ_t bufsz)
{
	ಗಾತ್ರ_t off;

	ಗಾಗಿ(off = 0;;) {
		ಆದರೆ (off >= bufsz)
			errx(1, "proxy read too long");
		ಆದರೆ (atomicio(ಪಠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ಆದರೆ (buf[off] == '\r')
			ಮುಂದುವರಿ;
		ಆದರೆ (buf[off] == '\n') {
			buf[off] = '\0';
			ನಿಲ್ಲಿಸು;
		}
		off++;
	}
	ಹಿಂತಿರುಗಿ (off);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
getproxypass(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxyuser, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxyhost)
{
	ಅಕ್ಷರ prompt[512];
	ಸ್ಥಿರ ಅಕ್ಷರ pw[256];

	snprintf(prompt, ಗಾತ್ರ(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ಆದರೆ (readpassphrase(prompt, pw, ಗಾತ್ರ(pw), RPP_REQUIRE_TTY) == ಖಾಲಿ)
		errx(1, "Unable to read proxy passphrase");
	ಹಿಂತಿರುಗಿ (pw);
}

ಪೂರ್ಣಾಂಕ
socks_connect(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪೋರ್ಟ್,
    ರಚನೆ addrinfo hints __attribute__ ((__unused__)),
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxyhost, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxyport, ರಚನೆ addrinfo proxyhints,
    ಪೂರ್ಣಾಂಕ socksv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxyuser)
{
	ಪೂರ್ಣಾಂಕ proxyfd, r, authretry = 0;
	ಗಾತ್ರ_t hlen, wlen = 0;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ buf[1024];
	ಗಾತ್ರ_t cnt;
	ರಚನೆ sockaddr_storage addr;
	ರಚನೆ sockaddr_in *in4 = (ರಚನೆ sockaddr_in *)&addr;
	ರಚನೆ sockaddr_in6 *in6 = (ರಚನೆ sockaddr_in6 *)&addr;
	in_port_t serverport;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxypass = ಖಾಲಿ;

	ಆದರೆ (proxyport == ಖಾಲಿ)
		proxyport = (socksv == -1) ? HTTP_PROXY_ಪೋರ್ಟ್ : SOCKS_ಪೋರ್ಟ್;

	/* Abuse API to lookup port */
	ಆದರೆ (decode_addrport("0.0.0.0", ಪೋರ್ಟ್, (ರಚನೆ sockaddr *)&addr,
	    ಗಾತ್ರ(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", ಪೋರ್ಟ್);
	serverport = in4->sin_port;

 again:
	ಆದರೆ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ಆದರೆ (proxyfd < 0)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ (socksv == 5) {
		ಆದರೆ (decode_addrport(host, ಪೋರ್ಟ್, (ರಚನೆ sockaddr *)&addr,
		    ಗಾತ್ರ(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ಆದರೆ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(ಪಠ, proxyfd, buf, 2);
		ಆದರೆ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ಆದರೆ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		ಆಯ್ಕೆ (addr.ss_family) {
		ಸ್ಥಿತಿ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host);
			ಆದರೆ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			ಸ್ಮರಣೆ_ನಕಲು(buf + 5, host, hlen);			
			ಸ್ಮರಣೆ_ನಕಲು(buf + 5 + hlen, &serverport, ಗಾತ್ರ serverport);
			wlen = 7 + hlen;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			ಸ್ಮರಣೆ_ನಕಲು(buf + 4, &in4->sin_addr, ಗಾತ್ರ in4->sin_addr);
			ಸ್ಮರಣೆ_ನಕಲು(buf + 8, &in4->sin_port, ಗಾತ್ರ in4->sin_port);
			wlen = 10;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			ಸ್ಮರಣೆ_ನಕಲು(buf + 4, &in6->sin6_addr, ಗಾತ್ರ in6->sin6_addr);
			ಸ್ಮರಣೆ_ನಕಲು(buf + 20, &in6->sin6_port,
			    ಗಾತ್ರ in6->sin6_port);
			wlen = 22;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ಆದರೆ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ಪಠ, proxyfd, buf, 4);
		ಆದರೆ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ಆದರೆ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		ಆಯ್ಕೆ (buf[3]) {
		ಸ್ಥಿತಿ SOCKS_IPV4:
			cnt = atomicio(ಪಠ, proxyfd, buf + 4, 6);
			ಆದರೆ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SOCKS_IPV6:
			cnt = atomicio(ಪಠ, proxyfd, buf + 4, 18);
			ಆದರೆ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			errx(1, "connection failed, unsupported address type");
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (socksv == 4 || socksv == 44) {
		ಆದರೆ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, ಪೋರ್ಟ್, (ರಚನೆ sockaddr *)&addr,
			    ಗಾತ್ರ(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		ಸ್ಮರಣೆ_ನಕಲು(buf + 2, &in4->sin_port, ಗಾತ್ರ in4->sin_port);
		ಆದರೆ (socksv == 4) {
			ಸ್ಮರಣೆ_ನಕಲು(buf + 4, &in4->sin_addr, ಗಾತ್ರ in4->sin_addr);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ಆದರೆ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ಆದರೆ (strlcpy(buf + 9, host,
			    ಗಾತ್ರ(buf) - 9) >= ಗಾತ್ರ(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ಆದರೆ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ಪಠ, proxyfd, buf, 8);
		ಆದರೆ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ಆದರೆ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ಆದರೆ (strcspn(host, "\r\n\t []:") != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ಆದರೆ (strchr(host, ':') != ಖಾಲಿ) {
			r = snprintf(buf, ಗಾತ್ರ(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ಇಲ್ಲದಿದ್ದರೆ {
			r = snprintf(buf, ಗಾತ್ರ(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ಆದರೆ (r == -1 || (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(buf))
			errx(1, "hostname too long");
		r = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ಆದರೆ (cnt != (ಗಾತ್ರ_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ಆದರೆ (authretry > 1) {
			ಅಕ್ಷರ resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, ಗಾತ್ರ(buf), "%s:%s",
			    proxyuser, proxypass);
			ಆದರೆ (r == -1 || (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(buf) ||
			    b64_ntop(buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf), resp,
			    ಗಾತ್ರ(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, ಗಾತ್ರ(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ಆದರೆ (r == -1 || (ಗಾತ್ರ_t)r >= ಗಾತ್ರ(buf))
				errx(1, "Proxy auth response too long");
			r = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf);
			ಆದರೆ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (ಗಾತ್ರ_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ಆದರೆ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ಸಾಲು(proxyfd, buf, ಗಾತ್ರ(buf));
		ಆದರೆ (proxyuser != ಖಾಲಿ &&
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(buf, "HTTP/1.0 407 ", 12) == 0) {
			ಆದರೆ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			ಹೋಗು again;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ಗಾಗಿ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ಸಾಲು(proxyfd, buf, ಗಾತ್ರ(buf));
			ಆದರೆ (*buf == '\0')
				ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ಇಲ್ಲದಿದ್ದರೆ
		errx(1, "Unknown proxy protocol %d", socksv);

	ಹಿಂತಿರುಗಿ (proxyfd);
}

