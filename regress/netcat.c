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
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#ifdef HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#endif

/* rename to avoid collision in libssh */
#define timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#define IAC	255
#define DONT	254
#define DO	253
#define WONT	252
#define WILL	251

#ifndef SUN_LEN
#define SUN_LEN(su) \
	(ಪರಿಮಾಣ(*(su)) - ಪರಿಮಾಣ((su)->sun_path) + strlen((su)->sun_path))
#endif

#define PORT_MAX	65535
#define PORT_MAX_LEN	6
#define UNIX_DG_TMP_SOCKET_SIZE	19

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3
#define BUFSIZE 16384

/* Command Line Options */
ಪೂರ್ಣಾಙ್ಕ	dflag;					/* detached, no stdin */
ಪೂರ್ಣಾಙ್ಕ	Fflag;					/* fdpass sock to stdout */
unsigned ಪೂರ್ಣಾಙ್ಕ iflag;				/* Interval Flag */
ಪೂರ್ಣಾಙ್ಕ	kflag;					/* More than one connect */
ಪೂರ್ಣಾಙ್ಕ	lflag;					/* Bind to local port */
ಪೂರ್ಣಾಙ್ಕ	Nflag;					/* shutdown() network socket */
ಪೂರ್ಣಾಙ್ಕ	nflag;					/* Don't do name look up */
ವರ್ಣ   *Pflag;					/* Proxy username */
ವರ್ಣ   *pflag;					/* Localport flag */
ಪೂರ್ಣಾಙ್ಕ	rflag;					/* Random ports flag */
ವರ್ಣ   *sflag;					/* Source Address */
ಪೂರ್ಣಾಙ್ಕ	tflag;					/* Telnet Emulation */
ಪೂರ್ಣಾಙ್ಕ	uflag;					/* UDP - Default to TCP */
ಪೂರ್ಣಾಙ್ಕ	vflag;					/* Verbosity */
ಪೂರ್ಣಾಙ್ಕ	xflag;					/* Socks proxy */
ಪೂರ್ಣಾಙ್ಕ	zflag;					/* Port Scan Flag */
ಪೂರ್ಣಾಙ್ಕ	Dflag;					/* sodebug */
ಪೂರ್ಣಾಙ್ಕ	Iflag;					/* TCP receive buffer size */
ಪೂರ್ಣಾಙ್ಕ	Oflag;					/* TCP send buffer size */
ಪೂರ್ಣಾಙ್ಕ	Sflag;					/* TCP MD5 signature option */
ಪೂರ್ಣಾಙ್ಕ	Tflag = -1;				/* IP Type of Service */
ಪೂರ್ಣಾಙ್ಕ	rtableid = -1;

ಪೂರ್ಣಾಙ್ಕ timeout = -1;
ಪೂರ್ಣಾಙ್ಕ family = AF_UNSPEC;
ವರ್ಣ *portlist[PORT_MAX+1];
ವರ್ಣ *unix_dg_tmp_socket;

ಶೂನ್ಯ	atelnet(ಪೂರ್ಣಾಙ್ಕ, unsigned ವರ್ಣ *, unsigned ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	build_ports(ವರ್ಣ *);
ಶೂನ್ಯ	help(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	local_listen(ವರ್ಣ *, ವರ್ಣ *, ಸಂರಚನಾ addrinfo);
ಶೂನ್ಯ	readwrite(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	fdpass(ಪೂರ್ಣಾಙ್ಕ nfd) __attribute__((noreturn));
ಪೂರ್ಣಾಙ್ಕ	remote_connect(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo);
ಪೂರ್ಣಾಙ್ಕ	timeout_connect(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ಸಂರಚನಾ sockaddr *, socklen_t);
ಪೂರ್ಣಾಙ್ಕ	socks_connect(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo,
	    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	udptest(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	unix_bind(ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	unix_connect(ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	unix_listen(ವರ್ಣ *);
ಶೂನ್ಯ	set_common_sockopts(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	map_tos(ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *);
ಶೂನ್ಯ	report_connect(ಧ್ರುವ ಸಂರಚನಾ sockaddr *, socklen_t);
ಶೂನ್ಯ	usage(ಪೂರ್ಣಾಙ್ಕ);
ssize_t drainbuf(ಪೂರ್ಣಾಙ್ಕ, unsigned ವರ್ಣ *, size_t *);
ssize_t fillbuf(ಪೂರ್ಣಾಙ್ಕ, unsigned ವರ್ಣ *, size_t *);


ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ *argv[])
{
	ಪೂರ್ಣಾಙ್ಕ ch, s, ret, socksv;
	ವರ್ಣ *host, *uport;
	ಸಂರಚನಾ addrinfo hints;
	ಸಂರಚನಾ servent *sv;
	socklen_t len;
	ಸಂರಚನಾ sockaddr_storage cliaddr;
	ವರ್ಣ *proxy = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *errstr, *proxyhost = "", *proxyport = ರಿಕ್ತ;
	ಸಂರಚನಾ addrinfo proxyhints;
	ವರ್ಣ unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ರಿಕ್ತ;
	uport = ರಿಕ್ತ;
	sv = ರಿಕ್ತ;

	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);

	ಯಾವತ್ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ '4':
			family = AF_INET;
			ಭಙ್ಗ;
		ಪಕ್ಷ '6':
			family = AF_INET6;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'U':
			family = AF_UNIX;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'X':
			ಯದಿ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ಅನ್ಯಥಾ ಯದಿ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ಅನ್ಯಥಾ
				errx(1, "unsupported proxy protocol");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			dflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'F':
			Fflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			help();
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ಯದಿ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			kflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			lflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'N':
			Nflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'n':
			nflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			Pflag = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			pflag = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			rflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			sflag = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			tflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			uflag = 1;
			ಭಙ್ಗ;
#ifdef SO_RTABLE
		ಪಕ್ಷ 'V':
			rtableid = (ಪೂರ್ಣಾಙ್ಕ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ಯದಿ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ಭಙ್ಗ;
#endif
		ಪಕ್ಷ 'v':
			vflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			ಯದಿ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'x':
			xflag = 1;
			ಯದಿ ((proxy = strdup(optarg)) == ರಿಕ್ತ)
				errx(1, "strdup");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'z':
			zflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			Dflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ಯದಿ (errstr != ರಿಕ್ತ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ಯದಿ (errstr != ರಿಕ್ತ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			Sflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			errstr = ರಿಕ್ತ;
			errno = 0;
			ಯದಿ (map_tos(optarg, &Tflag))
				ಭಙ್ಗ;
			ಯದಿ (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ಪೂರ್ಣಾಙ್ಕ)strtol(optarg, ರಿಕ್ತ, 16);
			ಅನ್ಯಥಾ
				Tflag = (ಪೂರ್ಣಾಙ್ಕ)strtonum(optarg, 0, 255,
				    &errstr);
			ಯದಿ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ಯದಿ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (argv[0] && !argv[1]) {
		ಯದಿ  (!lflag)
			usage(1);
		uport = argv[0];
		host = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ಅನ್ಯಥಾ
		usage(1);

	ಯದಿ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ಯದಿ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ಯದಿ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ಯದಿ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ಯದಿ ((family == AF_UNIX) && uflag && !lflag) {
		ಯದಿ (sflag) {
			unix_dg_tmp_socket = sflag;
		} ಅನ್ಯಥಾ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			ಯದಿ (mktemp(unix_dg_tmp_socket_buf) == ರಿಕ್ತ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ಯದಿ (family != AF_UNIX) {
		memset(&hints, 0, ಪರಿಮಾಣ(ಸಂರಚನಾ addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ಯದಿ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ಯದಿ (xflag) {
		ಯದಿ (uflag)
			errx(1, "no proxy support for UDP mode");

		ಯದಿ (lflag)
			errx(1, "no proxy support for listen");

		ಯದಿ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ಯದಿ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ಯದಿ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, ಪರಿಮಾಣ(ಸಂರಚನಾ addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ಯದಿ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ಯದಿ (lflag) {
		ಪೂರ್ಣಾಙ್ಕ connfd;
		ret = 0;

		ಯದಿ (family == AF_UNIX) {
			ಯದಿ (uflag)
				s = unix_bind(host);
			ಅನ್ಯಥಾ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ಪ್ರತಿ (;;) {
			ಯದಿ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ಯದಿ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ಯದಿ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ಅನ್ಯಥಾ ಯದಿ (uflag && !kflag) {
				ಪೂರ್ಣಾಙ್ಕ rv, plen;
				ವರ್ಣ buf[16384];
				ಸಂರಚನಾ sockaddr_storage z;

				len = ಪರಿಮಾಣ(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ಸಂರಚನಾ sockaddr *)&z, &len);
				ಯದಿ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ಸಂರಚನಾ sockaddr *)&z, len);
				ಯದಿ (rv < 0)
					err(1, "connect");

				ಯದಿ (vflag)
					report_connect((ಸಂರಚನಾ sockaddr *)&z, len);

				readwrite(s);
			} ಅನ್ಯಥಾ {
				len = ಪರಿಮಾಣ(cliaddr);
				connfd = accept(s, (ಸಂರಚನಾ sockaddr *)&cliaddr,
				    &len);
				ಯದಿ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ಯದಿ (vflag)
					report_connect((ಸಂರಚನಾ sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ಯದಿ (family != AF_UNIX)
				close(s);
			ಅನ್ಯಥಾ ಯದಿ (uflag) {
				ಯದಿ (connect(s, ರಿಕ್ತ, 0) < 0)
					err(1, "connect");
			}

			ಯದಿ (!kflag)
				ಭಙ್ಗ;
		}
	} ಅನ್ಯಥಾ ಯದಿ (family == AF_UNIX) {
		ret = 0;

		ಯದಿ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ಅನ್ಯಥಾ
			ret = 1;

		ಯದಿ (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} ಅನ್ಯಥಾ {
		ಪೂರ್ಣಾಙ್ಕ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ಪ್ರತಿ (i = 0; portlist[i] != ರಿಕ್ತ; i++) {
			ಯದಿ (s)
				close(s);

			ಯದಿ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ಅನ್ಯಥಾ
				s = remote_connect(host, portlist[i], hints);

			ಯದಿ (s < 0)
				ಅನುವರ್ತ;

			ret = 0;
			ಯದಿ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ಯದಿ (uflag) {
					ಯದಿ (udptest(s) == -1) {
						ret = 1;
						ಅನುವರ್ತ;
					}
				}

				/* Don't look up port if -n. */
				ಯದಿ (nflag)
					sv = ರಿಕ್ತ;
				ಅನ್ಯಥಾ {
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
			ಯದಿ (Fflag)
				fdpass(s);
			ಅನ್ಯಥಾ ಯದಿ (!zflag)
				readwrite(s);
		}
	}

	ಯದಿ (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ಪೂರ್ಣಾಙ್ಕ
unix_bind(ವರ್ಣ *path)
{
	ಸಂರಚನಾ sockaddr_un sun_sa;
	ಪೂರ್ಣಾಙ್ಕ s;

	/* Create unix domain socket. */
	ಯದಿ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	memset(&sun_sa, 0, ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ಯದಿ (strlcpy(sun_sa.sun_path, path, ಪರಿಮಾಣ(sun_sa.sun_path)) >=
	    ಪರಿಮಾಣ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಯದಿ (bind(s, (ಸಂರಚನಾ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
unix_connect(ವರ್ಣ *path)
{
	ಸಂರಚನಾ sockaddr_un sun_sa;
	ಪೂರ್ಣಾಙ್ಕ s;

	ಯದಿ (uflag) {
		ಯದಿ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ಪ್ರತ್ಯಾಗಮ (-1);
	} ಅನ್ಯಥಾ {
		ಯದಿ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ಪ್ರತ್ಯಾಗಮ (-1);
	}
	(ಶೂನ್ಯ)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ಯದಿ (strlcpy(sun_sa.sun_path, path, ಪರಿಮಾಣ(sun_sa.sun_path)) >=
	    ಪರಿಮಾಣ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (connect(s, (ಸಂರಚನಾ sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ಪೂರ್ಣಾಙ್ಕ
unix_listen(ವರ್ಣ *path)
{
	ಪೂರ್ಣಾಙ್ಕ s;
	ಯದಿ ((s = unix_bind(path)) < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ (listen(s, 5) < 0) {
		close(s);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಪ್ರತ್ಯಾಗಮ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
remote_connect(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *port, ಸಂರಚನಾ addrinfo hints)
{
	ಸಂರಚನಾ addrinfo *res, *res0;
	ಪೂರ್ಣಾಙ್ಕ s, error;
#ಯದಿ defined(SO_RTABLE) || defined(SO_BINDANY)
	ಪೂರ್ಣಾಙ್ಕ on = 1;
#endif

	ಯದಿ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ಕುರು {
		ಯದಿ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ಅನುವರ್ತ;

#ifdef SO_RTABLE
		ಯದಿ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ಪರಿಮಾಣ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		ಯದಿ (sflag || pflag) {
			ಸಂರಚನಾ addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, ಪರಿಮಾಣ(on));
#endif
			memset(&ahints, 0, ಪರಿಮಾಣ(ಸಂರಚನಾ addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ಯದಿ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ಯದಿ (bind(s, (ಸಂರಚನಾ sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		ಯದಿ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ಭಙ್ಗ;
		ಅನ್ಯಥಾ ಯದಿ (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ಯಾವತ್ ((res0 = res0->ai_next) != ರಿಕ್ತ);

	freeaddrinfo(res);

	ಪ್ರತ್ಯಾಗಮ (s);
}

ಪೂರ್ಣಾಙ್ಕ
timeout_connect(ಪೂರ್ಣಾಙ್ಕ s, ಧ್ರುವ ಸಂರಚನಾ sockaddr *name, socklen_t namelen)
{
	ಸಂರಚನಾ pollfd pfd;
	socklen_t optlen;
	ಪೂರ್ಣಾಙ್ಕ flags = 0, optval;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ಯದಿ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ಯದಿ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ಯದಿ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = ಪರಿಮಾಣ(optval);
			ಯದಿ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ಅನ್ಯಥಾ ಯದಿ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ಅನ್ಯಥಾ
			err(1, "poll failed");
	}

	ಯದಿ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ಪ್ರತ್ಯಾಗಮ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
local_listen(ವರ್ಣ *host, ವರ್ಣ *port, ಸಂರಚನಾ addrinfo hints)
{
	ಸಂರಚನಾ addrinfo *res, *res0;
	ಪೂರ್ಣಾಙ್ಕ s, ret, x = 1;
	ಪೂರ್ಣಾಙ್ಕ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ಯದಿ (host == ರಿಕ್ತ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ಯದಿ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	ಕುರು {
		ಯದಿ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ಅನುವರ್ತ;

#ifdef SO_RTABLE
		ಯದಿ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ಪರಿಮಾಣ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, ಪರಿಮಾಣ(x));
		ಯದಿ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, ಪರಿಮಾಣ(x));
		ಯದಿ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		ಯದಿ (bind(s, (ಸಂರಚನಾ sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ಭಙ್ಗ;

		close(s);
		s = -1;
	} ಯಾವತ್ ((res0 = res0->ai_next) != ರಿಕ್ತ);

	ಯದಿ (!uflag && s != -1) {
		ಯದಿ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ಪ್ರತ್ಯಾಗಮ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
ಶೂನ್ಯ
readwrite(ಪೂರ್ಣಾಙ್ಕ net_fd)
{
	ಸಂರಚನಾ pollfd pfd[4];
	ಪೂರ್ಣಾಙ್ಕ stdin_fd = STDIN_FILENO;
	ಪೂರ್ಣಾಙ್ಕ stdout_fd = STDOUT_FILENO;
	unsigned ವರ್ಣ netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned ವರ್ಣ stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	ಪೂರ್ಣಾಙ್ಕ n, ಅಂಕೆ_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ಯದಿ (dflag)
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

	ಯಾವತ್ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ಯದಿ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ಪ್ರತ್ಯಾಗಮ;
		}
		/* both outputs are gone, we can't continue */
		ಯದಿ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ಪ್ರತ್ಯಾಗಮ;
		}
		/* listen and net in gone, queues empty, done */
		ಯದಿ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ಪ್ರತ್ಯಾಗಮ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ಯದಿ (iflag)
			sleep(iflag);

		/* poll */
		ಅಂಕೆ_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ಯದಿ (ಅಂಕೆ_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ಯದಿ (ಅಂಕೆ_fds == 0)
			ಪ್ರತ್ಯಾಗಮ;

		/* treat socket error conditions */
		ಪ್ರತಿ (n = 0; n < 4; n++) {
			ಯದಿ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ಯದಿ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ಯದಿ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ಯದಿ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ಯದಿ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ಯದಿ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ಯದಿ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ಯದಿ (pfd[POLL_STDOUT].fd == -1) {
			ಯದಿ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ಯದಿ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ಯದಿ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ಯದಿ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ಯದಿ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ಯದಿ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ಯದಿ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ಯದಿ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ಯದಿ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ಯದಿ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ಯದಿ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ಯದಿ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ಯದಿ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ಯದಿ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ಯದಿ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ಯದಿ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ಯದಿ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ಯದಿ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ಯದಿ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ಯದಿ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ಯದಿ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ಯದಿ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ಪೂರ್ಣಾಙ್ಕ fd, unsigned ವರ್ಣ *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ಲಿಖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ಯದಿ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ಯದಿ (n <= 0)
		ಪ್ರತ್ಯಾಗಮ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ಯದಿ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ಪ್ರತ್ಯಾಗಮ n;
}


ssize_t
fillbuf(ಪೂರ್ಣಾಙ್ಕ fd, unsigned ವರ್ಣ *buf, size_t *bufpos)
{
	size_t ಅಂಕೆ = BUFSIZE - *bufpos;
	ssize_t n;

	n = ಪಠ(fd, buf + *bufpos, ಅಂಕೆ);
	/* don't treat EAGAIN, EINTR as error */
	ಯದಿ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ಯದಿ (n <= 0)
		ಪ್ರತ್ಯಾಗಮ n;
	*bufpos += n;
	ಪ್ರತ್ಯಾಗಮ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
ಶೂನ್ಯ
fdpass(ಪೂರ್ಣಾಙ್ಕ nfd)
{
#ಯದಿ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ಸಂರಚನಾ msghdr ಸಂದೇಶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಙ್ಘ {
		ಸಂರಚನಾ cmsghdr hdr;
		ವರ್ಣ buf[CMSG_SPACE(ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ))];
	} cmsgbuf;
	ಸಂರಚನಾ cmsghdr *cmsg;
#endif
	ಸಂರಚನಾ iovec vec;
	ವರ್ಣ ch = '\0';
	ಸಂರಚನಾ pollfd pfd;
	ssize_t r;

	memset(&ಸಂದೇಶ, 0, ಪರಿಮಾಣ(ಸಂದೇಶ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ಸಂದೇಶ.ಸಂದೇಶ_accrights = (caddr_t)&nfd;
	ಸಂದೇಶ.ಸಂದೇಶ_accrightslen = ಪರಿಮಾಣ(nfd);
#ಅನ್ಯಥಾ
	memset(&cmsgbuf, 0, ಪರಿಮಾಣ(cmsgbuf));
	ಸಂದೇಶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ಸಂದೇಶ.msg_controllen = ಪರಿಮಾಣ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ಸಂದೇಶ);
	cmsg->cmsg_len = CMSG_LEN(ಪರಿಮಾಣ(ಪೂರ್ಣಾಙ್ಕ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ಪೂರ್ಣಾಙ್ಕ *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ಸಂದೇಶ.msg_iov = &vec;
	ಸಂದೇಶ.msg_iovlen = 1;

	bzero(&pfd, ಪರಿಮಾಣ(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ಪ್ರತಿ (;;) {
		r = sendmsg(STDOUT_FILENO, &ಸಂದೇಶ, 0);
		ಯದಿ (r == -1) {
			ಯದಿ (errno == EAGAIN || errno == EINTR) {
				ಯದಿ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ಅನುವರ್ತ;
			}
			err(1, "sendmsg");
		} ಅನ್ಯಥಾ ಯದಿ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	exit(0);
#ಅನ್ಯಥಾ
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
ಶೂನ್ಯ
atelnet(ಪೂರ್ಣಾಙ್ಕ nfd, unsigned ವರ್ಣ *buf, unsigned ಪೂರ್ಣಾಙ್ಕ size)
{
	unsigned ವರ್ಣ *p, *end;
	unsigned ವರ್ಣ obuf[4];

	ಯದಿ (size < 3)
		ಪ್ರತ್ಯಾಗಮ;
	end = buf + size - 2;

	ಪ್ರತಿ (p = buf; p < end; p++) {
		ಯದಿ (*p != IAC)
			ಅನುವರ್ತ;

		obuf[0] = IAC;
		p++;
		ಯದಿ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ಅನ್ಯಥಾ ಯದಿ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ಅನ್ಯಥಾ
			ಅನುವರ್ತ;

		p++;
		obuf[2] = *p;
		ಯದಿ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
ಶೂನ್ಯ
build_ports(ವರ್ಣ *p)
{
	ಧ್ರುವ ವರ್ಣ *errstr;
	ವರ್ಣ *n;
	ಪೂರ್ಣಾಙ್ಕ hi, lo, cp;
	ಪೂರ್ಣಾಙ್ಕ x = 0;

	ಯದಿ ((n = strchr(p, '-')) != ರಿಕ್ತ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		ಯದಿ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		ಯದಿ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ಯದಿ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ಪ್ರತಿ (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			ಯದಿ (portlist[x] == ರಿಕ್ತ)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ಯದಿ (rflag) {
			ಪೂರ್ಣಾಙ್ಕ y;
			ವರ್ಣ *c;

			ಪ್ರತಿ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ಅನ್ಯಥಾ {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		ಯದಿ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ಯದಿ (portlist[0] == ರಿಕ್ತ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ಪೂರ್ಣಾಙ್ಕ
udptest(ಪೂರ್ಣಾಙ್ಕ s)
{
	ಪೂರ್ಣಾಙ್ಕ i, ret;

	ಪ್ರತಿ (i = 0; i <= 3; i++) {
		ಯದಿ (ಲಿಖ(s, "X", 1) == 1)
			ret = 1;
		ಅನ್ಯಥಾ
			ret = -1;
	}
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಶೂನ್ಯ
set_common_sockopts(ಪೂರ್ಣಾಙ್ಕ s, ಪೂರ್ಣಾಙ್ಕ af)
{
	ಪೂರ್ಣಾಙ್ಕ x = 1;

#ifdef TCP_MD5SIG
	ಯದಿ (Sflag) {
		ಯದಿ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, ಪರಿಮಾಣ(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	ಯದಿ (Dflag) {
		ಯದಿ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, ಪರಿಮಾಣ(x)) == -1)
			err(1, "setsockopt");
	}
#ಯದಿ defined(IP_TOS) && defined(IPV6_TCLASS)
	ಯದಿ (Tflag != -1) {
		ಪೂರ್ಣಾಙ್ಕ proto, option;

		ಯದಿ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ಅನ್ಯಥಾ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ಯದಿ (setsockopt(s, proto, option, &Tflag, ಪರಿಮಾಣ(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	ಯದಿ (Iflag) {
		ಯದಿ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, ಪರಿಮಾಣ(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ಯದಿ (Oflag) {
		ಯದಿ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, ಪರಿಮಾಣ(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ಪೂರ್ಣಾಙ್ಕ
map_tos(ವರ್ಣ *s, ಪೂರ್ಣಾಙ್ಕ *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ಧ್ರುವ ಸಂರಚನಾ toskeywords {
		ಧ್ರುವ ವರ್ಣ	*keyword;
		ಪೂರ್ಣಾಙ್ಕ		 val;
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
		{ ರಿಕ್ತ, 		-1 },
	};

	ಪ್ರತಿ (t = toskeywords; t->keyword != ರಿಕ್ತ; t++) {
		ಯದಿ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ಪ್ರತ್ಯಾಗಮ (1);
		}
	}
#endif

	ಪ್ರತ್ಯಾಗಮ (0);
}

ಶೂನ್ಯ
report_connect(ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa, socklen_t salen)
{
	ವರ್ಣ remote_host[NI_MAXHOST];
	ವರ್ಣ remote_port[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ herr;
	ಪೂರ್ಣಾಙ್ಕ flags = NI_NUMERICSERV;
	
	ಯದಿ (nflag)
		flags |= NI_NUMERICHOST;
	
	ಯದಿ ((herr = getnameinfo(sa, salen,
	    remote_host, ಪರಿಮಾಣ(remote_host),
	    remote_port, ಪರಿಮಾಣ(remote_port),
	    flags)) != 0) {
		ಯದಿ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ಅನ್ಯಥಾ
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
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
	\t-h		This help text\n\
	\t-I length	TCP receive buffer length\n\
	\t-i secs\t	Delay interval ಪ್ರತಿ ಸಾಲುಗಳು sent, ports scanned\n\
	\t-k		Keep inbound sockets open ಪ್ರತಿ multiple connects\n\
	\t-l		Listen mode, ಪ್ರತಿ inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername ಪ್ರತಿ proxy authentication\n\
	\t-p port\t	Specify local port ಪ್ರತಿ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ಪ್ರತಿ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used ಪ್ರತಿ scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

ಶೂನ್ಯ
usage(ಪೂರ್ಣಾಙ್ಕ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ಯದಿ (ret)
		exit(1);
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

#define SOCKS_PORT	"1080"
#define HTTP_PROXY_PORT	"3128"
#define HTTP_MAXHDRS	64
#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

ಪೂರ್ಣಾಙ್ಕ	remote_connect(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo);
ಪೂರ್ಣಾಙ್ಕ	socks_connect(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo,
	    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ addrinfo, ಪೂರ್ಣಾಙ್ಕ,
	    ಧ್ರುವ ವರ್ಣ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
decode_addrport(ಧ್ರುವ ವರ್ಣ *h, ಧ್ರುವ ವರ್ಣ *p, ಸಂರಚನಾ sockaddr *addr,
    socklen_t addrlen, ಪೂರ್ಣಾಙ್ಕ v4only, ಪೂರ್ಣಾಙ್ಕ numeric)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ addrinfo hints, *res;

	bzero(&hints, ಪರಿಮಾಣ(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ಯದಿ (r != 0) {
		ಯದಿ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
proxy_read_ಸಾಲು(ಪೂರ್ಣಾಙ್ಕ fd, ವರ್ಣ *buf, size_t bufsz)
{
	size_t off;

	ಪ್ರತಿ(off = 0;;) {
		ಯದಿ (off >= bufsz)
			errx(1, "proxy read too long");
		ಯದಿ (atomicio(ಪಠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ಯದಿ (buf[off] == '\r')
			ಅನುವರ್ತ;
		ಯದಿ (buf[off] == '\n') {
			buf[off] = '\0';
			ಭಙ್ಗ;
		}
		off++;
	}
	ಪ್ರತ್ಯಾಗಮ (off);
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
getproxypass(ಧ್ರುವ ವರ್ಣ *proxyuser, ಧ್ರುವ ವರ್ಣ *proxyhost)
{
	ವರ್ಣ prompt[512];
	ಸ್ಥಿರ ವರ್ಣ pw[256];

	snprintf(prompt, ಪರಿಮಾಣ(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ಯದಿ (readpassphrase(prompt, pw, ಪರಿಮಾಣ(pw), RPP_REQUIRE_TTY) == ರಿಕ್ತ)
		errx(1, "Unable to read proxy passphrase");
	ಪ್ರತ್ಯಾಗಮ (pw);
}

ಪೂರ್ಣಾಙ್ಕ
socks_connect(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *port,
    ಸಂರಚನಾ addrinfo hints __attribute__ ((__unused__)),
    ಧ್ರುವ ವರ್ಣ *proxyhost, ಧ್ರುವ ವರ್ಣ *proxyport, ಸಂರಚನಾ addrinfo proxyhints,
    ಪೂರ್ಣಾಙ್ಕ socksv, ಧ್ರುವ ವರ್ಣ *proxyuser)
{
	ಪೂರ್ಣಾಙ್ಕ proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned ವರ್ಣ buf[1024];
	size_t cnt;
	ಸಂರಚನಾ sockaddr_storage addr;
	ಸಂರಚನಾ sockaddr_in *in4 = (ಸಂರಚನಾ sockaddr_in *)&addr;
	ಸಂರಚನಾ sockaddr_in6 *in6 = (ಸಂರಚನಾ sockaddr_in6 *)&addr;
	in_port_t serverport;
	ಧ್ರುವ ವರ್ಣ *proxypass = ರಿಕ್ತ;

	ಯದಿ (proxyport == ರಿಕ್ತ)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	ಯದಿ (decode_addrport("0.0.0.0", port, (ಸಂರಚನಾ sockaddr *)&addr,
	    ಪರಿಮಾಣ(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	ಯದಿ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ಯದಿ (proxyfd < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ (socksv == 5) {
		ಯದಿ (decode_addrport(host, port, (ಸಂರಚನಾ sockaddr *)&addr,
		    ಪರಿಮಾಣ(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ಯದಿ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(ಪಠ, proxyfd, buf, 2);
		ಯದಿ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ಯದಿ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		ವಿಕಲ್ಪ (addr.ss_family) {
		ಪಕ್ಷ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			ಯದಿ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, ಪರಿಮಾಣ serverport);
			wlen = 7 + hlen;
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, ಪರಿಮಾಣ in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, ಪರಿಮಾಣ in4->sin_port);
			wlen = 10;
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, ಪರಿಮಾಣ in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    ಪರಿಮಾಣ in6->sin6_port);
			wlen = 22;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ಯದಿ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ಪಠ, proxyfd, buf, 4);
		ಯದಿ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ಯದಿ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		ವಿಕಲ್ಪ (buf[3]) {
		ಪಕ್ಷ SOCKS_IPV4:
			cnt = atomicio(ಪಠ, proxyfd, buf + 4, 6);
			ಯದಿ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ಭಙ್ಗ;
		ಪಕ್ಷ SOCKS_IPV6:
			cnt = atomicio(ಪಠ, proxyfd, buf + 4, 18);
			ಯದಿ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			errx(1, "connection failed, unsupported address type");
		}
	} ಅನ್ಯಥಾ ಯದಿ (socksv == 4 || socksv == 44) {
		ಯದಿ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (ಸಂರಚನಾ sockaddr *)&addr,
			    ಪರಿಮಾಣ(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, ಪರಿಮಾಣ in4->sin_port);
		ಯದಿ (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, ಪರಿಮಾಣ in4->sin_addr);
		} ಅನ್ಯಥಾ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ಯದಿ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ಯದಿ (strlcpy(buf + 9, host,
			    ಪರಿಮಾಣ(buf) - 9) >= ಪರಿಮಾಣ(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ಯದಿ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ಪಠ, proxyfd, buf, 8);
		ಯದಿ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ಯದಿ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ಅನ್ಯಥಾ ಯದಿ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ಯದಿ (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ಯದಿ (strchr(host, ':') != ರಿಕ್ತ) {
			r = snprintf(buf, ಪರಿಮಾಣ(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ಅನ್ಯಥಾ {
			r = snprintf(buf, ಪರಿಮಾಣ(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ಯದಿ (r == -1 || (size_t)r >= ಪರಿಮಾಣ(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ಯದಿ (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ಯದಿ (authretry > 1) {
			ವರ್ಣ resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, ಪರಿಮಾಣ(buf), "%s:%s",
			    proxyuser, proxypass);
			ಯದಿ (r == -1 || (size_t)r >= ಪರಿಮಾಣ(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    ಪರಿಮಾಣ(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, ಪರಿಮಾಣ(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ಯದಿ (r == -1 || (size_t)r >= ಪರಿಮಾಣ(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			ಯದಿ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ಯದಿ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ಸಾಲು(proxyfd, buf, ಪರಿಮಾಣ(buf));
		ಯದಿ (proxyuser != ರಿಕ್ತ &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			ಯದಿ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			ಗಚ್ಛ again;
		} ಅನ್ಯಥಾ ಯದಿ (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ಪ್ರತಿ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ಸಾಲು(proxyfd, buf, ಪರಿಮಾಣ(buf));
			ಯದಿ (*buf == '\0')
				ಭಙ್ಗ;
		}
		ಯದಿ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ಅನ್ಯಥಾ
		errx(1, "Unknown proxy protocol %d", socksv);

	ಪ್ರತ್ಯಾಗಮ (proxyfd);
}

