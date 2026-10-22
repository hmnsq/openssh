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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <netinet/tcp.h>
#ଅନ୍ତର୍ଭାଵ <netinet/ip.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ "atomicio.h"

#ଅନ୍ତର୍ଭାଵ <poll.h>
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
	(ଆକାର(*(su)) - ଆକାର((su)->sun_path) + strlen((su)->sun_path))
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	dflag;					/* detached, no stdin */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Fflag;					/* fdpass sock to stdout */
unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା iflag;				/* Interval Flag */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	kflag;					/* More than one connect */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	lflag;					/* Bind to local port */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Nflag;					/* shutdown() network socket */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	nflag;					/* Don't do name look up */
ଅକ୍ଷର   *Pflag;					/* Proxy username */
ଅକ୍ଷର   *pflag;					/* Localport flag */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	rflag;					/* Random ports flag */
ଅକ୍ଷର   *sflag;					/* Source Address */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	tflag;					/* Telnet Emulation */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	uflag;					/* UDP - Default to TCP */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	vflag;					/* Verbosity */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	xflag;					/* Socks proxy */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	zflag;					/* Port Scan Flag */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Dflag;					/* sodebug */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Iflag;					/* TCP receive buffer size */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Oflag;					/* TCP send buffer size */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Sflag;					/* TCP MD5 signature option */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Tflag = -1;				/* IP Type of Service */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	rtableid = -1;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout = -1;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା family = AF_UNSPEC;
ଅକ୍ଷର *portlist[PORT_MAX+1];
ଅକ୍ଷର *unix_dg_tmp_socket;

ଶୂନ୍ୟ	atelnet(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, unsigned ଅକ୍ଷର *, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	build_ports(ଅକ୍ଷର *);
ଶୂନ୍ୟ	help(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	local_listen(ଅକ୍ଷର *, ଅକ୍ଷର *, ସଂରଚନା addrinfo);
ଶୂନ୍ୟ	readwrite(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	fdpass(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nfd) __attribute__((noreturn));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	remote_connect(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	timeout_connect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା sockaddr *, socklen_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	socks_connect(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo,
	    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	udptest(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	unix_bind(ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	unix_connect(ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	unix_listen(ଅକ୍ଷର *);
ଶୂନ୍ୟ	set_common_sockopts(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	map_tos(ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ଶୂନ୍ୟ	report_connect(ଅଚଳ ସଂରଚନା sockaddr *, socklen_t);
ଶୂନ୍ୟ	usage(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ssize_t drainbuf(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, unsigned ଅକ୍ଷର *, size_t *);
ssize_t fillbuf(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, unsigned ଅକ୍ଷର *, size_t *);


ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *argv[])
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch, s, ret, socksv;
	ଅକ୍ଷର *host, *uport;
	ସଂରଚନା addrinfo hints;
	ସଂରଚନା servent *sv;
	socklen_t len;
	ସଂରଚନା sockaddr_storage cliaddr;
	ଅକ୍ଷର *proxy = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *errstr, *proxyhost = "", *proxyport = ଖାଲି;
	ସଂରଚନା addrinfo proxyhints;
	ଅକ୍ଷର unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ଖାଲି;
	uport = ଖାଲି;
	sv = ଖାଲି;

	ସଙ୍କେତ(SIGPIPE, SIG_IGN);

	ଯେତେବେଳେ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି '4':
			family = AF_INET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '6':
			family = AF_INET6;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'U':
			family = AF_UNIX;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'X':
			ଯଦି (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ଅନ୍ୟଥା ଯଦି (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ଅନ୍ୟଥା
				errx(1, "unsupported proxy protocol");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			dflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'F':
			Fflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
			help();
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ଯଦି (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			kflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			lflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'N':
			Nflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'n':
			nflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			Pflag = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			pflag = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			rflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			sflag = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			tflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			uflag = 1;
			ଭାଙ୍ଗ;
#ifdef SO_RTABLE
		ସ୍ଥିତି 'V':
			rtableid = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ଯଦି (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ଭାଙ୍ଗ;
#endif
		ସ୍ଥିତି 'v':
			vflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			ଯଦି (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'x':
			xflag = 1;
			ଯଦି ((proxy = strdup(optarg)) == ଖାଲି)
				errx(1, "strdup");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'z':
			zflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			Dflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ଯଦି (errstr != ଖାଲି)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ଯଦି (errstr != ଖାଲି)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			Sflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			errstr = ଖାଲି;
			errno = 0;
			ଯଦି (map_tos(optarg, &Tflag))
				ଭାଙ୍ଗ;
			ଯଦି (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtol(optarg, ଖାଲି, 16);
			ଅନ୍ୟଥା
				Tflag = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(optarg, 0, 255,
				    &errstr);
			ଯଦି (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ଯଦି (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (argv[0] && !argv[1]) {
		ଯଦି  (!lflag)
			usage(1);
		uport = argv[0];
		host = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ଅନ୍ୟଥା
		usage(1);

	ଯଦି (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ଯଦି (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ଯଦି (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ଯଦି (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ଯଦି ((family == AF_UNIX) && uflag && !lflag) {
		ଯଦି (sflag) {
			unix_dg_tmp_socket = sflag;
		} ଅନ୍ୟଥା {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			ଯଦି (mktemp(unix_dg_tmp_socket_buf) == ଖାଲି)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ଯଦି (family != AF_UNIX) {
		memset(&hints, 0, ଆକାର(ସଂରଚନା addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ଯଦି (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ଯଦି (xflag) {
		ଯଦି (uflag)
			errx(1, "no proxy support for UDP mode");

		ଯଦି (lflag)
			errx(1, "no proxy support for listen");

		ଯଦି (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ଯଦି (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ଯଦି (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, ଆକାର(ସଂରଚନା addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ଯଦି (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ଯଦି (lflag) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା connfd;
		ret = 0;

		ଯଦି (family == AF_UNIX) {
			ଯଦି (uflag)
				s = unix_bind(host);
			ଅନ୍ୟଥା
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ପାଇଁ (;;) {
			ଯଦି (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ଯଦି (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ଯଦି (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ଅନ୍ୟଥା ଯଦି (uflag && !kflag) {
				ପୂର୍ଣ୍ଣସଂଖ୍ୟା rv, plen;
				ଅକ୍ଷର buf[16384];
				ସଂରଚନା sockaddr_storage z;

				len = ଆକାର(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ସଂରଚନା sockaddr *)&z, &len);
				ଯଦି (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ସଂରଚନା sockaddr *)&z, len);
				ଯଦି (rv < 0)
					err(1, "connect");

				ଯଦି (vflag)
					report_connect((ସଂରଚନା sockaddr *)&z, len);

				readwrite(s);
			} ଅନ୍ୟଥା {
				len = ଆକାର(cliaddr);
				connfd = accept(s, (ସଂରଚନା sockaddr *)&cliaddr,
				    &len);
				ଯଦି (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ଯଦି (vflag)
					report_connect((ସଂରଚନା sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ଯଦି (family != AF_UNIX)
				close(s);
			ଅନ୍ୟଥା ଯଦି (uflag) {
				ଯଦି (connect(s, ଖାଲି, 0) < 0)
					err(1, "connect");
			}

			ଯଦି (!kflag)
				ଭାଙ୍ଗ;
		}
	} ଅନ୍ୟଥା ଯଦି (family == AF_UNIX) {
		ret = 0;

		ଯଦି ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ଅନ୍ୟଥା
			ret = 1;

		ଯଦି (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} ଅନ୍ୟଥା {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ପାଇଁ (i = 0; portlist[i] != ଖାଲି; i++) {
			ଯଦି (s)
				close(s);

			ଯଦି (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ଅନ୍ୟଥା
				s = remote_connect(host, portlist[i], hints);

			ଯଦି (s < 0)
				ଜାରି;

			ret = 0;
			ଯଦି (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ଯଦି (uflag) {
					ଯଦି (udptest(s) == -1) {
						ret = 1;
						ଜାରି;
					}
				}

				/* Don't look up port if -n. */
				ଯଦି (nflag)
					sv = ଖାଲି;
				ଅନ୍ୟଥା {
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
			ଯଦି (Fflag)
				fdpass(s);
			ଅନ୍ୟଥା ଯଦି (!zflag)
				readwrite(s);
		}
	}

	ଯଦି (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unix_bind(ଅକ୍ଷର *path)
{
	ସଂରଚନା sockaddr_un sun_sa;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s;

	/* Create unix domain socket. */
	ଯଦି ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ଫେରନ୍ତୁ (-1);

	memset(&sun_sa, 0, ଆକାର(ସଂରଚନା sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ଯଦି (strlcpy(sun_sa.sun_path, path, ଆକାର(sun_sa.sun_path)) >=
	    ଆକାର(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ଫେରନ୍ତୁ (-1);
	}

	ଯଦି (bind(s, (ସଂରଚନା sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unix_connect(ଅକ୍ଷର *path)
{
	ସଂରଚନା sockaddr_un sun_sa;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s;

	ଯଦି (uflag) {
		ଯଦି ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ଫେରନ୍ତୁ (-1);
	} ଅନ୍ୟଥା {
		ଯଦି ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ଫେରନ୍ତୁ (-1);
	}
	(ଶୂନ୍ୟ)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, ଆକାର(ସଂରଚନା sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ଯଦି (strlcpy(sun_sa.sun_path, path, ଆକାର(sun_sa.sun_path)) >=
	    ଆକାର(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (connect(s, (ସଂରଚନା sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unix_listen(ଅକ୍ଷର *path)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s;
	ଯଦି ((s = unix_bind(path)) < 0)
		ଫେରନ୍ତୁ (-1);

	ଯଦି (listen(s, 5) < 0) {
		close(s);
		ଫେରନ୍ତୁ (-1);
	}
	ଫେରନ୍ତୁ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
remote_connect(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *port, ସଂରଚନା addrinfo hints)
{
	ସଂରଚନା addrinfo *res, *res0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, error;
#ଯଦି defined(SO_RTABLE) || defined(SO_BINDANY)
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା on = 1;
#endif

	ଯଦି ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	କର {
		ଯଦି ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ଜାରି;

#ifdef SO_RTABLE
		ଯଦି (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ଆକାର(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		ଯଦି (sflag || pflag) {
			ସଂରଚନା addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, ଆକାର(on));
#endif
			memset(&ahints, 0, ଆକାର(ସଂରଚନା addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ଯଦି ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ଯଦି (bind(s, (ସଂରଚନା sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		ଯଦି (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ଭାଙ୍ଗ;
		ଅନ୍ୟଥା ଯଦି (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ଯେତେବେଳେ ((res0 = res0->ai_next) != ଖାଲି);

	freeaddrinfo(res);

	ଫେରନ୍ତୁ (s);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
timeout_connect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, ଅଚଳ ସଂରଚନା sockaddr *name, socklen_t namelen)
{
	ସଂରଚନା pollfd pfd;
	socklen_t optlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags = 0, optval;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ଯଦି (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ଯଦି ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ଯଦି ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = ଆକାର(optval);
			ଯଦି ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ଅନ୍ୟଥା ଯଦି (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ଅନ୍ୟଥା
			err(1, "poll failed");
	}

	ଯଦି (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ଫେରନ୍ତୁ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
local_listen(ଅକ୍ଷର *host, ଅକ୍ଷର *port, ସଂରଚନା addrinfo hints)
{
	ସଂରଚନା addrinfo *res, *res0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, ret, x = 1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ଯଦି (host == ଖାଲି && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ଯଦି ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	କର {
		ଯଦି ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ଜାରି;

#ifdef SO_RTABLE
		ଯଦି (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, ଆକାର(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, ଆକାର(x));
		ଯଦି (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, ଆକାର(x));
		ଯଦି (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		ଯଦି (bind(s, (ସଂରଚନା sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ଭାଙ୍ଗ;

		close(s);
		s = -1;
	} ଯେତେବେଳେ ((res0 = res0->ai_next) != ଖାଲି);

	ଯଦି (!uflag && s != -1) {
		ଯଦି (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ଫେରନ୍ତୁ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
ଶୂନ୍ୟ
readwrite(ପୂର୍ଣ୍ଣସଂଖ୍ୟା net_fd)
{
	ସଂରଚନା pollfd pfd[4];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା stdin_fd = STDIN_FILENO;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା stdout_fd = STDOUT_FILENO;
	unsigned ଅକ୍ଷର netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned ଅକ୍ଷର stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, ଅଙ୍କ_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ଯଦି (dflag)
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

	ଯେତେବେଳେ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ଯଦି (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ଫେରନ୍ତୁ;
		}
		/* both outputs are gone, we can't continue */
		ଯଦି (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ଫେରନ୍ତୁ;
		}
		/* listen and net in gone, queues empty, done */
		ଯଦି (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ଫେରନ୍ତୁ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ଯଦି (iflag)
			sleep(iflag);

		/* poll */
		ଅଙ୍କ_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ଯଦି (ଅଙ୍କ_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ଯଦି (ଅଙ୍କ_fds == 0)
			ଫେରନ୍ତୁ;

		/* treat socket error conditions */
		ପାଇଁ (n = 0; n < 4; n++) {
			ଯଦି (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ଯଦି (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ଯଦି (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ଯଦି (pfd[POLL_NETOUT].revents & POLLHUP) {
			ଯଦି (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ଯଦି (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ଯଦି (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ଯଦି (pfd[POLL_STDOUT].fd == -1) {
			ଯଦି (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ଯଦି (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ଯଦି (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ଯଦି (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ଯଦି (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ଯଦି (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ଯଦି (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ଯଦି (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ଯଦି (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ଯଦି (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ଯଦି (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ଯଦି (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ଯଦି (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ଯଦି (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ଯଦି (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ଯଦି (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ଯଦି (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ଯଦି (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ଯଦି (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ଯଦି (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ଯଦି (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ଯଦି (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, unsigned ଅକ୍ଷର *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ଲିଖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ଯଦି (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ଯଦି (n <= 0)
		ଫେରନ୍ତୁ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ଯଦି (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ଫେରନ୍ତୁ n;
}


ssize_t
fillbuf(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, unsigned ଅକ୍ଷର *buf, size_t *bufpos)
{
	size_t ଅଙ୍କ = BUFSIZE - *bufpos;
	ssize_t n;

	n = ପଠ(fd, buf + *bufpos, ଅଙ୍କ);
	/* don't treat EAGAIN, EINTR as error */
	ଯଦି (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ଯଦି (n <= 0)
		ଫେରନ୍ତୁ n;
	*bufpos += n;
	ଫେରନ୍ତୁ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
ଶୂନ୍ୟ
fdpass(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nfd)
{
#ଯଦି defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ସଂରଚନା msghdr ସନ୍ଦେଶ;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ସଂଘ {
		ସଂରଚନା cmsghdr hdr;
		ଅକ୍ଷର buf[CMSG_SPACE(ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା))];
	} cmsgbuf;
	ସଂରଚନା cmsghdr *cmsg;
#endif
	ସଂରଚନା iovec vec;
	ଅକ୍ଷର ch = '\0';
	ସଂରଚନା pollfd pfd;
	ssize_t r;

	memset(&ସନ୍ଦେଶ, 0, ଆକାର(ସନ୍ଦେଶ));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrights = (caddr_t)&nfd;
	ସନ୍ଦେଶ.ସନ୍ଦେଶ_accrightslen = ଆକାର(nfd);
#ଅନ୍ୟଥା
	memset(&cmsgbuf, 0, ଆକାର(cmsgbuf));
	ସନ୍ଦେଶ.msg_control = (caddr_t)&cmsgbuf.buf;
	ସନ୍ଦେଶ.msg_controllen = ଆକାର(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&ସନ୍ଦେଶ);
	cmsg->cmsg_len = CMSG_LEN(ଆକାର(ପୂର୍ଣ୍ଣସଂଖ୍ୟା));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	ସନ୍ଦେଶ.msg_iov = &vec;
	ସନ୍ଦେଶ.msg_iovlen = 1;

	bzero(&pfd, ଆକାର(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ପାଇଁ (;;) {
		r = sendmsg(STDOUT_FILENO, &ସନ୍ଦେଶ, 0);
		ଯଦି (r == -1) {
			ଯଦି (errno == EAGAIN || errno == EINTR) {
				ଯଦି (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ଜାରି;
			}
			err(1, "sendmsg");
		} ଅନ୍ୟଥା ଯଦି (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	exit(0);
#ଅନ୍ୟଥା
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
ଶୂନ୍ୟ
atelnet(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nfd, unsigned ଅକ୍ଷର *buf, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା size)
{
	unsigned ଅକ୍ଷର *p, *end;
	unsigned ଅକ୍ଷର obuf[4];

	ଯଦି (size < 3)
		ଫେରନ୍ତୁ;
	end = buf + size - 2;

	ପାଇଁ (p = buf; p < end; p++) {
		ଯଦି (*p != IAC)
			ଜାରି;

		obuf[0] = IAC;
		p++;
		ଯଦି ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ଅନ୍ୟଥା ଯଦି ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ଅନ୍ୟଥା
			ଜାରି;

		p++;
		obuf[2] = *p;
		ଯଦି (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
ଶୂନ୍ୟ
build_ports(ଅକ୍ଷର *p)
{
	ଅଚଳ ଅକ୍ଷର *errstr;
	ଅକ୍ଷର *n;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hi, lo, cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା x = 0;

	ଯଦି ((n = strchr(p, '-')) != ଖାଲି) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		ଯଦି (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		ଯଦି (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ଯଦି (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ପାଇଁ (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			ଯଦି (portlist[x] == ଖାଲି)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ଯଦି (rflag) {
			ପୂର୍ଣ୍ଣସଂଖ୍ୟା y;
			ଅକ୍ଷର *c;

			ପାଇଁ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ଅନ୍ୟଥା {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		ଯଦି (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ଯଦି (portlist[0] == ଖାଲି)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
udptest(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret;

	ପାଇଁ (i = 0; i <= 3; i++) {
		ଯଦି (ଲିଖ(s, "X", 1) == 1)
			ret = 1;
		ଅନ୍ୟଥା
			ret = -1;
	}
	ଫେରନ୍ତୁ (ret);
}

ଶୂନ୍ୟ
set_common_sockopts(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା af)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା x = 1;

#ifdef TCP_MD5SIG
	ଯଦି (Sflag) {
		ଯଦି (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, ଆକାର(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	ଯଦି (Dflag) {
		ଯଦି (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, ଆକାର(x)) == -1)
			err(1, "setsockopt");
	}
#ଯଦି defined(IP_TOS) && defined(IPV6_TCLASS)
	ଯଦି (Tflag != -1) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା proto, option;

		ଯଦି (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ଅନ୍ୟଥା {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ଯଦି (setsockopt(s, proto, option, &Tflag, ଆକାର(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	ଯଦି (Iflag) {
		ଯଦି (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, ଆକାର(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ଯଦି (Oflag) {
		ଯଦି (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, ଆକାର(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
map_tos(ଅକ୍ଷର *s, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ଅଚଳ ସଂରଚନା toskeywords {
		ଅଚଳ ଅକ୍ଷର	*keyword;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 val;
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
		{ ଖାଲି, 		-1 },
	};

	ପାଇଁ (t = toskeywords; t->keyword != ଖାଲି; t++) {
		ଯଦି (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ଫେରନ୍ତୁ (1);
		}
	}
#endif

	ଫେରନ୍ତୁ (0);
}

ଶୂନ୍ୟ
report_connect(ଅଚଳ ସଂରଚନା sockaddr *sa, socklen_t salen)
{
	ଅକ୍ଷର remote_host[NI_MAXHOST];
	ଅକ୍ଷର remote_port[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା herr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags = NI_NUMERICSERV;
	
	ଯଦି (nflag)
		flags |= NI_NUMERICHOST;
	
	ଯଦି ((herr = getnameinfo(sa, salen,
	    remote_host, ଆକାର(remote_host),
	    remote_port, ଆକାର(remote_port),
	    flags)) != 0) {
		ଯଦି (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ଅନ୍ୟଥା
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

ଶୂନ୍ୟ
help(ଶୂନ୍ୟ)
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
	\t-i secs\t	Delay interval ପାଇଁ ଧାଡ଼ିଗୁଡ଼ିକ sent, ports scanned\n\
	\t-k		Keep inbound sockets open ପାଇଁ multiple connects\n\
	\t-l		Listen mode, ପାଇଁ inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername ପାଇଁ proxy authentication\n\
	\t-p port\t	Specify local port ପାଇଁ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ପାଇଁ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used ପାଇଁ scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

ଶୂନ୍ୟ
usage(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ଯଦି (ret)
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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <resolv.h>

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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	remote_connect(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	socks_connect(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo,
	    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା addrinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    ଅଚଳ ଅକ୍ଷର *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
decode_addrport(ଅଚଳ ଅକ୍ଷର *h, ଅଚଳ ଅକ୍ଷର *p, ସଂରଚନା sockaddr *addr,
    socklen_t addrlen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା v4only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା numeric)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା addrinfo hints, *res;

	bzero(&hints, ଆକାର(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ଯଦି (r != 0) {
		ଯଦି (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
proxy_read_ଧାଡ଼ି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅକ୍ଷର *buf, size_t bufsz)
{
	size_t off;

	ପାଇଁ(off = 0;;) {
		ଯଦି (off >= bufsz)
			errx(1, "proxy read too long");
		ଯଦି (atomicio(ପଠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ଯଦି (buf[off] == '\r')
			ଜାରି;
		ଯଦି (buf[off] == '\n') {
			buf[off] = '\0';
			ଭାଙ୍ଗ;
		}
		off++;
	}
	ଫେରନ୍ତୁ (off);
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
getproxypass(ଅଚଳ ଅକ୍ଷର *proxyuser, ଅଚଳ ଅକ୍ଷର *proxyhost)
{
	ଅକ୍ଷର prompt[512];
	ସ୍ଥିର ଅକ୍ଷର pw[256];

	snprintf(prompt, ଆକାର(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ଯଦି (readpassphrase(prompt, pw, ଆକାର(pw), RPP_REQUIRE_TTY) == ଖାଲି)
		errx(1, "Unable to read proxy passphrase");
	ଫେରନ୍ତୁ (pw);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
socks_connect(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *port,
    ସଂରଚନା addrinfo hints __attribute__ ((__unused__)),
    ଅଚଳ ଅକ୍ଷର *proxyhost, ଅଚଳ ଅକ୍ଷର *proxyport, ସଂରଚନା addrinfo proxyhints,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା socksv, ଅଚଳ ଅକ୍ଷର *proxyuser)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned ଅକ୍ଷର buf[1024];
	size_t cnt;
	ସଂରଚନା sockaddr_storage addr;
	ସଂରଚନା sockaddr_in *in4 = (ସଂରଚନା sockaddr_in *)&addr;
	ସଂରଚନା sockaddr_in6 *in6 = (ସଂରଚନା sockaddr_in6 *)&addr;
	in_port_t serverport;
	ଅଚଳ ଅକ୍ଷର *proxypass = ଖାଲି;

	ଯଦି (proxyport == ଖାଲି)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	ଯଦି (decode_addrport("0.0.0.0", port, (ସଂରଚନା sockaddr *)&addr,
	    ଆକାର(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	ଯଦି (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ଯଦି (proxyfd < 0)
		ଫେରନ୍ତୁ (-1);

	ଯଦି (socksv == 5) {
		ଯଦି (decode_addrport(host, port, (ସଂରଚନା sockaddr *)&addr,
		    ଆକାର(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ଯଦି (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(ପଠ, proxyfd, buf, 2);
		ଯଦି (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ଯଦି (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		ବାଛ (addr.ss_family) {
		ସ୍ଥିତି 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			ଯଦି (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, ଆକାର serverport);
			wlen = 7 + hlen;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, ଆକାର in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, ଆକାର in4->sin_port);
			wlen = 10;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, ଆକାର in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    ଆକାର in6->sin6_port);
			wlen = 22;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ଯଦି (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ପଠ, proxyfd, buf, 4);
		ଯଦି (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ଯଦି (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		ବାଛ (buf[3]) {
		ସ୍ଥିତି SOCKS_IPV4:
			cnt = atomicio(ପଠ, proxyfd, buf + 4, 6);
			ଯଦି (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SOCKS_IPV6:
			cnt = atomicio(ପଠ, proxyfd, buf + 4, 18);
			ଯଦି (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			errx(1, "connection failed, unsupported address type");
		}
	} ଅନ୍ୟଥା ଯଦି (socksv == 4 || socksv == 44) {
		ଯଦି (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (ସଂରଚନା sockaddr *)&addr,
			    ଆକାର(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, ଆକାର in4->sin_port);
		ଯଦି (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, ଆକାର in4->sin_addr);
		} ଅନ୍ୟଥା {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ଯଦି (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ଯଦି (strlcpy(buf + 9, host,
			    ଆକାର(buf) - 9) >= ଆକାର(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ଯଦି (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(ପଠ, proxyfd, buf, 8);
		ଯଦି (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ଯଦି (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ଅନ୍ୟଥା ଯଦି (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ଯଦି (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ଯଦି (strchr(host, ':') != ଖାଲି) {
			r = snprintf(buf, ଆକାର(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ଅନ୍ୟଥା {
			r = snprintf(buf, ଆକାର(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ଯଦି (r == -1 || (size_t)r >= ଆକାର(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ଯଦି (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ଯଦି (authretry > 1) {
			ଅକ୍ଷର resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, ଆକାର(buf), "%s:%s",
			    proxyuser, proxypass);
			ଯଦି (r == -1 || (size_t)r >= ଆକାର(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    ଆକାର(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, ଆକାର(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ଯଦି (r == -1 || (size_t)r >= ଆକାର(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			ଯଦି ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ଯଦି ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ଧାଡ଼ି(proxyfd, buf, ଆକାର(buf));
		ଯଦି (proxyuser != ଖାଲି &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			ଯଦି (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			ଯାଅ again;
		} ଅନ୍ୟଥା ଯଦି (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ପାଇଁ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ଧାଡ଼ି(proxyfd, buf, ଆକାର(buf));
			ଯଦି (*buf == '\0')
				ଭାଙ୍ଗ;
		}
		ଯଦି (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ଅନ୍ୟଥା
		errx(1, "Unknown proxy protocol %d", socksv);

	ଫେରନ୍ତୁ (proxyfd);
}

