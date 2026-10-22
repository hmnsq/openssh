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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/uio.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <netinet/tcp.h>
#அந்தர்பாவ <netinet/ip.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ "atomicio.h"

#அந்தர்பாவ <poll.h>
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
	(அளவு(*(su)) - அளவு((su)->sun_path) + strlen((su)->sun_path))
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
முழு	dflag;					/* detached, no stdin */
முழு	Fflag;					/* fdpass sock to stdout */
unsigned முழு iflag;				/* Interval Flag */
முழு	kflag;					/* More than one connect */
முழு	lflag;					/* Bind to local port */
முழு	Nflag;					/* shutdown() network socket */
முழு	nflag;					/* Don't do name look up */
எழுத்து   *Pflag;					/* Proxy username */
எழுத்து   *pflag;					/* Localport flag */
முழு	rflag;					/* Random ports flag */
எழுத்து   *sflag;					/* Source Address */
முழு	tflag;					/* Telnet Emulation */
முழு	uflag;					/* UDP - Default to TCP */
முழு	vflag;					/* Verbosity */
முழு	xflag;					/* Socks proxy */
முழு	zflag;					/* Port Scan Flag */
முழு	Dflag;					/* sodebug */
முழு	Iflag;					/* TCP receive buffer size */
முழு	Oflag;					/* TCP send buffer size */
முழு	Sflag;					/* TCP MD5 signature option */
முழு	Tflag = -1;				/* IP Type of Service */
முழு	rtableid = -1;

முழு timeout = -1;
முழு family = AF_UNSPEC;
எழுத்து *portlist[PORT_MAX+1];
எழுத்து *unix_dg_tmp_socket;

வெறுமை	atelnet(முழு, unsigned எழுத்து *, unsigned முழு);
வெறுமை	build_ports(எழுத்து *);
வெறுமை	help(வெறுமை);
முழு	local_listen(எழுத்து *, எழுத்து *, கட்டமைப்பு addrinfo);
வெறுமை	readwrite(முழு);
வெறுமை	fdpass(முழு nfd) __attribute__((noreturn));
முழு	remote_connect(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo);
முழு	timeout_connect(முழு, மாறிலி கட்டமைப்பு sockaddr *, socklen_t);
முழு	socks_connect(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo,
	    மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo, முழு, மாறிலி எழுத்து *);
முழு	udptest(முழு);
முழு	unix_bind(எழுத்து *);
முழு	unix_connect(எழுத்து *);
முழு	unix_listen(எழுத்து *);
வெறுமை	set_common_sockopts(முழு, முழு);
முழு	map_tos(எழுத்து *, முழு *);
வெறுமை	report_connect(மாறிலி கட்டமைப்பு sockaddr *, socklen_t);
வெறுமை	usage(முழு);
ssize_t drainbuf(முழு, unsigned எழுத்து *, size_t *);
ssize_t fillbuf(முழு, unsigned எழுத்து *, size_t *);


முழு
முதன்மை(முழு argc, எழுத்து *argv[])
{
	முழு ch, s, ret, socksv;
	எழுத்து *host, *uport;
	கட்டமைப்பு addrinfo hints;
	கட்டமைப்பு servent *sv;
	socklen_t len;
	கட்டமைப்பு sockaddr_storage cliaddr;
	எழுத்து *proxy = வெற்று;
	மாறிலி எழுத்து *errstr, *proxyhost = "", *proxyport = வெற்று;
	கட்டமைப்பு addrinfo proxyhints;
	எழுத்து unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = வெற்று;
	uport = வெற்று;
	sv = வெற்று;

	சமிக்ஞை(SIGPIPE, SIG_IGN);

	போது ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		தேர்வு (ch) {
		நிலை '4':
			family = AF_INET;
			நிறுத்து;
		நிலை '6':
			family = AF_INET6;
			நிறுத்து;
		நிலை 'U':
			family = AF_UNIX;
			நிறுத்து;
		நிலை 'X':
			எனில் (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			இல்லையெனில் எனில் (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			இல்லையெனில் எனில் (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			இல்லையெனில் எனில் (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			இல்லையெனில்
				errx(1, "unsupported proxy protocol");
			நிறுத்து;
		நிலை 'd':
			dflag = 1;
			நிறுத்து;
		நிலை 'F':
			Fflag = 1;
			நிறுத்து;
		நிலை 'h':
			help();
			நிறுத்து;
		நிலை 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			எனில் (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			நிறுத்து;
		நிலை 'k':
			kflag = 1;
			நிறுத்து;
		நிலை 'l':
			lflag = 1;
			நிறுத்து;
		நிலை 'N':
			Nflag = 1;
			நிறுத்து;
		நிலை 'n':
			nflag = 1;
			நிறுத்து;
		நிலை 'P':
			Pflag = optarg;
			நிறுத்து;
		நிலை 'p':
			pflag = optarg;
			நிறுத்து;
		நிலை 'r':
			rflag = 1;
			நிறுத்து;
		நிலை 's':
			sflag = optarg;
			நிறுத்து;
		நிலை 't':
			tflag = 1;
			நிறுத்து;
		நிலை 'u':
			uflag = 1;
			நிறுத்து;
#ifdef SO_RTABLE
		நிலை 'V':
			rtableid = (முழு)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			எனில் (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			நிறுத்து;
#endif
		நிலை 'v':
			vflag = 1;
			நிறுத்து;
		நிலை 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			எனில் (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			நிறுத்து;
		நிலை 'x':
			xflag = 1;
			எனில் ((proxy = strdup(optarg)) == வெற்று)
				errx(1, "strdup");
			நிறுத்து;
		நிலை 'z':
			zflag = 1;
			நிறுத்து;
		நிலை 'D':
			Dflag = 1;
			நிறுத்து;
		நிலை 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			எனில் (errstr != வெற்று)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			நிறுத்து;
		நிலை 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			எனில் (errstr != வெற்று)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			நிறுத்து;
		நிலை 'S':
			Sflag = 1;
			நிறுத்து;
		நிலை 'T':
			errstr = வெற்று;
			errno = 0;
			எனில் (map_tos(optarg, &Tflag))
				நிறுத்து;
			எனில் (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (முழு)strtol(optarg, வெற்று, 16);
			இல்லையெனில்
				Tflag = (முழு)strtonum(optarg, 0, 255,
				    &errstr);
			எனில் (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			நிறுத்து;
		இயல்பு:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	எனில் (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = வெற்று;
	} இல்லையெனில் எனில் (argv[0] && !argv[1]) {
		எனில்  (!lflag)
			usage(1);
		uport = argv[0];
		host = வெற்று;
	} இல்லையெனில் எனில் (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} இல்லையெனில்
		usage(1);

	எனில் (lflag && sflag)
		errx(1, "cannot use -s and -l");
	எனில் (lflag && pflag)
		errx(1, "cannot use -p and -l");
	எனில் (lflag && zflag)
		errx(1, "cannot use -z and -l");
	எனில் (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	எனில் ((family == AF_UNIX) && uflag && !lflag) {
		எனில் (sflag) {
			unix_dg_tmp_socket = sflag;
		} இல்லையெனில் {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			எனில் (mktemp(unix_dg_tmp_socket_buf) == வெற்று)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	எனில் (family != AF_UNIX) {
		memset(&hints, 0, அளவு(கட்டமைப்பு addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		எனில் (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	எனில் (xflag) {
		எனில் (uflag)
			errx(1, "no proxy support for UDP mode");

		எனில் (lflag)
			errx(1, "no proxy support for listen");

		எனில் (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		எனில் (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		எனில் (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, அளவு(கட்டமைப்பு addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		எனில் (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	எனில் (lflag) {
		முழு connfd;
		ret = 0;

		எனில் (family == AF_UNIX) {
			எனில் (uflag)
				s = unix_bind(host);
			இல்லையெனில்
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		க்கு (;;) {
			எனில் (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			எனில் (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			எனில் (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			இல்லையெனில் எனில் (uflag && !kflag) {
				முழு rv, plen;
				எழுத்து buf[16384];
				கட்டமைப்பு sockaddr_storage z;

				len = அளவு(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (கட்டமைப்பு sockaddr *)&z, &len);
				எனில் (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (கட்டமைப்பு sockaddr *)&z, len);
				எனில் (rv < 0)
					err(1, "connect");

				எனில் (vflag)
					report_connect((கட்டமைப்பு sockaddr *)&z, len);

				readwrite(s);
			} இல்லையெனில் {
				len = அளவு(cliaddr);
				connfd = accept(s, (கட்டமைப்பு sockaddr *)&cliaddr,
				    &len);
				எனில் (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				எனில் (vflag)
					report_connect((கட்டமைப்பு sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			எனில் (family != AF_UNIX)
				close(s);
			இல்லையெனில் எனில் (uflag) {
				எனில் (connect(s, வெற்று, 0) < 0)
					err(1, "connect");
			}

			எனில் (!kflag)
				நிறுத்து;
		}
	} இல்லையெனில் எனில் (family == AF_UNIX) {
		ret = 0;

		எனில் ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} இல்லையெனில்
			ret = 1;

		எனில் (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} இல்லையெனில் {
		முழு i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		க்கு (i = 0; portlist[i] != வெற்று; i++) {
			எனில் (s)
				close(s);

			எனில் (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			இல்லையெனில்
				s = remote_connect(host, portlist[i], hints);

			எனில் (s < 0)
				தொடர்;

			ret = 0;
			எனில் (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				எனில் (uflag) {
					எனில் (udptest(s) == -1) {
						ret = 1;
						தொடர்;
					}
				}

				/* Don't look up port if -n. */
				எனில் (nflag)
					sv = வெற்று;
				இல்லையெனில் {
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
			எனில் (Fflag)
				fdpass(s);
			இல்லையெனில் எனில் (!zflag)
				readwrite(s);
		}
	}

	எனில் (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
முழு
unix_bind(எழுத்து *path)
{
	கட்டமைப்பு sockaddr_un sun_sa;
	முழு s;

	/* Create unix domain socket. */
	எனில் ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		திரும்பு (-1);

	memset(&sun_sa, 0, அளவு(கட்டமைப்பு sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	எனில் (strlcpy(sun_sa.sun_path, path, அளவு(sun_sa.sun_path)) >=
	    அளவு(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		திரும்பு (-1);
	}

	எனில் (bind(s, (கட்டமைப்பு sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		திரும்பு (-1);
	}
	திரும்பு (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
முழு
unix_connect(எழுத்து *path)
{
	கட்டமைப்பு sockaddr_un sun_sa;
	முழு s;

	எனில் (uflag) {
		எனில் ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			திரும்பு (-1);
	} இல்லையெனில் {
		எனில் ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			திரும்பு (-1);
	}
	(வெறுமை)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, அளவு(கட்டமைப்பு sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	எனில் (strlcpy(sun_sa.sun_path, path, அளவு(sun_sa.sun_path)) >=
	    அளவு(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		திரும்பு (-1);
	}
	எனில் (connect(s, (கட்டமைப்பு sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		திரும்பு (-1);
	}
	திரும்பு (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
முழு
unix_listen(எழுத்து *path)
{
	முழு s;
	எனில் ((s = unix_bind(path)) < 0)
		திரும்பு (-1);

	எனில் (listen(s, 5) < 0) {
		close(s);
		திரும்பு (-1);
	}
	திரும்பு (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
முழு
remote_connect(மாறிலி எழுத்து *host, மாறிலி எழுத்து *port, கட்டமைப்பு addrinfo hints)
{
	கட்டமைப்பு addrinfo *res, *res0;
	முழு s, error;
#எனில் defined(SO_RTABLE) || defined(SO_BINDANY)
	முழு on = 1;
#endif

	எனில் ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	செய் {
		எனில் ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			தொடர்;

#ifdef SO_RTABLE
		எனில் (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, அளவு(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		எனில் (sflag || pflag) {
			கட்டமைப்பு addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, அளவு(on));
#endif
			memset(&ahints, 0, அளவு(கட்டமைப்பு addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			எனில் ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			எனில் (bind(s, (கட்டமைப்பு sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		எனில் (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			நிறுத்து;
		இல்லையெனில் எனில் (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} போது ((res0 = res0->ai_next) != வெற்று);

	freeaddrinfo(res);

	திரும்பு (s);
}

முழு
timeout_connect(முழு s, மாறிலி கட்டமைப்பு sockaddr *name, socklen_t namelen)
{
	கட்டமைப்பு pollfd pfd;
	socklen_t optlen;
	முழு flags = 0, optval;
	முழு ret;

	எனில் (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		எனில் (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	எனில் ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		எனில் ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = அளவு(optval);
			எனில் ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} இல்லையெனில் எனில் (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} இல்லையெனில்
			err(1, "poll failed");
	}

	எனில் (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	திரும்பு (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
முழு
local_listen(எழுத்து *host, எழுத்து *port, கட்டமைப்பு addrinfo hints)
{
	கட்டமைப்பு addrinfo *res, *res0;
	முழு s, ret, x = 1;
	முழு error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	எனில் (host == வெற்று && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	எனில் ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	செய் {
		எனில் ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			தொடர்;

#ifdef SO_RTABLE
		எனில் (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, அளவு(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, அளவு(x));
		எனில் (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, அளவு(x));
		எனில் (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		எனில் (bind(s, (கட்டமைப்பு sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			நிறுத்து;

		close(s);
		s = -1;
	} போது ((res0 = res0->ai_next) != வெற்று);

	எனில் (!uflag && s != -1) {
		எனில் (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	திரும்பு (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
வெறுமை
readwrite(முழு net_fd)
{
	கட்டமைப்பு pollfd pfd[4];
	முழு stdin_fd = STDIN_FILENO;
	முழு stdout_fd = STDOUT_FILENO;
	unsigned எழுத்து netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned எழுத்து stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	முழு n, இலக்கம்_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	எனில் (dflag)
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

	போது (1) {
		/* both inputs are gone, buffers are empty, we are done */
		எனில் (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			திரும்பு;
		}
		/* both outputs are gone, we can't continue */
		எனில் (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			திரும்பு;
		}
		/* listen and net in gone, queues empty, done */
		எனில் (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			திரும்பு;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		எனில் (iflag)
			sleep(iflag);

		/* poll */
		இலக்கம்_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		எனில் (இலக்கம்_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		எனில் (இலக்கம்_fds == 0)
			திரும்பு;

		/* treat socket error conditions */
		க்கு (n = 0; n < 4; n++) {
			எனில் (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		எனில் (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		எனில் (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		எனில் (pfd[POLL_NETOUT].revents & POLLHUP) {
			எனில் (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		எனில் (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		எனில் (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		எனில் (pfd[POLL_STDOUT].fd == -1) {
			எனில் (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		எனில் (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			எனில் (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			எனில் (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			எனில் (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		எனில் (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			எனில் (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			எனில் (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			எனில் (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		எனில் (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			எனில் (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			எனில் (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			எனில் (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			எனில் (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			எனில் (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		எனில் (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			எனில் (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			எனில் (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			எனில் (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		எனில் (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			எனில் (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		எனில் (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(முழு fd, unsigned எழுத்து *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = லிக(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	எனில் (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	எனில் (n <= 0)
		திரும்பு n;
	/* adjust buffer */
	adjust = *bufpos - n;
	எனில் (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	திரும்பு n;
}


ssize_t
fillbuf(முழு fd, unsigned எழுத்து *buf, size_t *bufpos)
{
	size_t இலக்கம் = BUFSIZE - *bufpos;
	ssize_t n;

	n = பட(fd, buf + *bufpos, இலக்கம்);
	/* don't treat EAGAIN, EINTR as error */
	எனில் (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	எனில் (n <= 0)
		திரும்பு n;
	*bufpos += n;
	திரும்பு n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
வெறுமை
fdpass(முழு nfd)
{
#எனில் defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	கட்டமைப்பு msghdr செய்தி;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	ஒன்றிப்பு {
		கட்டமைப்பு cmsghdr hdr;
		எழுத்து buf[CMSG_SPACE(அளவு(முழு))];
	} cmsgbuf;
	கட்டமைப்பு cmsghdr *cmsg;
#endif
	கட்டமைப்பு iovec vec;
	எழுத்து ch = '\0';
	கட்டமைப்பு pollfd pfd;
	ssize_t r;

	memset(&செய்தி, 0, அளவு(செய்தி));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	செய்தி.செய்தி_accrights = (caddr_t)&nfd;
	செய்தி.செய்தி_accrightslen = அளவு(nfd);
#இல்லையெனில்
	memset(&cmsgbuf, 0, அளவு(cmsgbuf));
	செய்தி.msg_control = (caddr_t)&cmsgbuf.buf;
	செய்தி.msg_controllen = அளவு(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&செய்தி);
	cmsg->cmsg_len = CMSG_LEN(அளவு(முழு));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(முழு *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	செய்தி.msg_iov = &vec;
	செய்தி.msg_iovlen = 1;

	bzero(&pfd, அளவு(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	க்கு (;;) {
		r = sendmsg(STDOUT_FILENO, &செய்தி, 0);
		எனில் (r == -1) {
			எனில் (errno == EAGAIN || errno == EINTR) {
				எனில் (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				தொடர்;
			}
			err(1, "sendmsg");
		} இல்லையெனில் எனில் (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		இல்லையெனில்
			நிறுத்து;
	}
	exit(0);
#இல்லையெனில்
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
வெறுமை
atelnet(முழு nfd, unsigned எழுத்து *buf, unsigned முழு size)
{
	unsigned எழுத்து *p, *end;
	unsigned எழுத்து obuf[4];

	எனில் (size < 3)
		திரும்பு;
	end = buf + size - 2;

	க்கு (p = buf; p < end; p++) {
		எனில் (*p != IAC)
			தொடர்;

		obuf[0] = IAC;
		p++;
		எனில் ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		இல்லையெனில் எனில் ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		இல்லையெனில்
			தொடர்;

		p++;
		obuf[2] = *p;
		எனில் (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
வெறுமை
build_ports(எழுத்து *p)
{
	மாறிலி எழுத்து *errstr;
	எழுத்து *n;
	முழு hi, lo, cp;
	முழு x = 0;

	எனில் ((n = strchr(p, '-')) != வெற்று) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		எனில் (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		எனில் (errstr)
			errx(1, "port number %s: %s", errstr, p);

		எனில் (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		க்கு (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			எனில் (portlist[x] == வெற்று)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		எனில் (rflag) {
			முழு y;
			எழுத்து *c;

			க்கு (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} இல்லையெனில் {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		எனில் (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		எனில் (portlist[0] == வெற்று)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
முழு
udptest(முழு s)
{
	முழு i, ret;

	க்கு (i = 0; i <= 3; i++) {
		எனில் (லிக(s, "X", 1) == 1)
			ret = 1;
		இல்லையெனில்
			ret = -1;
	}
	திரும்பு (ret);
}

வெறுமை
set_common_sockopts(முழு s, முழு af)
{
	முழு x = 1;

#ifdef TCP_MD5SIG
	எனில் (Sflag) {
		எனில் (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, அளவு(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	எனில் (Dflag) {
		எனில் (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, அளவு(x)) == -1)
			err(1, "setsockopt");
	}
#எனில் defined(IP_TOS) && defined(IPV6_TCLASS)
	எனில் (Tflag != -1) {
		முழு proto, option;

		எனில் (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} இல்லையெனில் {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		எனில் (setsockopt(s, proto, option, &Tflag, அளவு(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	எனில் (Iflag) {
		எனில் (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, அளவு(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	எனில் (Oflag) {
		எனில் (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, அளவு(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

முழு
map_tos(எழுத்து *s, முழு *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	மாறிலி கட்டமைப்பு toskeywords {
		மாறிலி எழுத்து	*keyword;
		முழு		 val;
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
		{ வெற்று, 		-1 },
	};

	க்கு (t = toskeywords; t->keyword != வெற்று; t++) {
		எனில் (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			திரும்பு (1);
		}
	}
#endif

	திரும்பு (0);
}

வெறுமை
report_connect(மாறிலி கட்டமைப்பு sockaddr *sa, socklen_t salen)
{
	எழுத்து remote_host[NI_MAXHOST];
	எழுத்து remote_port[NI_MAXSERV];
	முழு herr;
	முழு flags = NI_NUMERICSERV;
	
	எனில் (nflag)
		flags |= NI_NUMERICHOST;
	
	எனில் ((herr = getnameinfo(sa, salen,
	    remote_host, அளவு(remote_host),
	    remote_port, அளவு(remote_port),
	    flags)) != 0) {
		எனில் (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		இல்லையெனில்
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

வெறுமை
help(வெறுமை)
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
	\t-i secs\t	Delay interval க்கு வரிகள் sent, ports scanned\n\
	\t-k		Keep inbound sockets open க்கு multiple connects\n\
	\t-l		Listen mode, க்கு inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername க்கு proxy authentication\n\
	\t-p port\t	Specify local port க்கு remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout க்கு connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used க்கு scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

வெறுமை
usage(முழு ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	எனில் (ret)
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

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <resolv.h>

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

முழு	remote_connect(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo);
முழு	socks_connect(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo,
	    மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு addrinfo, முழு,
	    மாறிலி எழுத்து *);

நிலையான முழு
decode_addrport(மாறிலி எழுத்து *h, மாறிலி எழுத்து *p, கட்டமைப்பு sockaddr *addr,
    socklen_t addrlen, முழு v4only, முழு numeric)
{
	முழு r;
	கட்டமைப்பு addrinfo hints, *res;

	bzero(&hints, அளவு(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	எனில் (r != 0) {
		எனில் (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		திரும்பு (-1);
	}
	எனில் (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	திரும்பு (0);
}

நிலையான முழு
proxy_read_வரி(முழு fd, எழுத்து *buf, size_t bufsz)
{
	size_t off;

	க்கு(off = 0;;) {
		எனில் (off >= bufsz)
			errx(1, "proxy read too long");
		எனில் (atomicio(பட, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		எனில் (buf[off] == '\r')
			தொடர்;
		எனில் (buf[off] == '\n') {
			buf[off] = '\0';
			நிறுத்து;
		}
		off++;
	}
	திரும்பு (off);
}

நிலையான மாறிலி எழுத்து *
getproxypass(மாறிலி எழுத்து *proxyuser, மாறிலி எழுத்து *proxyhost)
{
	எழுத்து prompt[512];
	நிலையான எழுத்து pw[256];

	snprintf(prompt, அளவு(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	எனில் (readpassphrase(prompt, pw, அளவு(pw), RPP_REQUIRE_TTY) == வெற்று)
		errx(1, "Unable to read proxy passphrase");
	திரும்பு (pw);
}

முழு
socks_connect(மாறிலி எழுத்து *host, மாறிலி எழுத்து *port,
    கட்டமைப்பு addrinfo hints __attribute__ ((__unused__)),
    மாறிலி எழுத்து *proxyhost, மாறிலி எழுத்து *proxyport, கட்டமைப்பு addrinfo proxyhints,
    முழு socksv, மாறிலி எழுத்து *proxyuser)
{
	முழு proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned எழுத்து buf[1024];
	size_t cnt;
	கட்டமைப்பு sockaddr_storage addr;
	கட்டமைப்பு sockaddr_in *in4 = (கட்டமைப்பு sockaddr_in *)&addr;
	கட்டமைப்பு sockaddr_in6 *in6 = (கட்டமைப்பு sockaddr_in6 *)&addr;
	in_port_t serverport;
	மாறிலி எழுத்து *proxypass = வெற்று;

	எனில் (proxyport == வெற்று)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	எனில் (decode_addrport("0.0.0.0", port, (கட்டமைப்பு sockaddr *)&addr,
	    அளவு(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	எனில் (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	எனில் (proxyfd < 0)
		திரும்பு (-1);

	எனில் (socksv == 5) {
		எனில் (decode_addrport(host, port, (கட்டமைப்பு sockaddr *)&addr,
		    அளவு(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		எனில் (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(பட, proxyfd, buf, 2);
		எனில் (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		எனில் (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		தேர்வு (addr.ss_family) {
		நிலை 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			எனில் (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, அளவு serverport);
			wlen = 7 + hlen;
			நிறுத்து;
		நிலை AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, அளவு in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, அளவு in4->sin_port);
			wlen = 10;
			நிறுத்து;
		நிலை AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, அளவு in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    அளவு in6->sin6_port);
			wlen = 22;
			நிறுத்து;
		இயல்பு:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		எனில் (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(பட, proxyfd, buf, 4);
		எனில் (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		எனில் (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		தேர்வு (buf[3]) {
		நிலை SOCKS_IPV4:
			cnt = atomicio(பட, proxyfd, buf + 4, 6);
			எனில் (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			நிறுத்து;
		நிலை SOCKS_IPV6:
			cnt = atomicio(பட, proxyfd, buf + 4, 18);
			எனில் (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			நிறுத்து;
		இயல்பு:
			errx(1, "connection failed, unsupported address type");
		}
	} இல்லையெனில் எனில் (socksv == 4 || socksv == 44) {
		எனில் (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (கட்டமைப்பு sockaddr *)&addr,
			    அளவு(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, அளவு in4->sin_port);
		எனில் (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, அளவு in4->sin_addr);
		} இல்லையெனில் {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		எனில் (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			எனில் (strlcpy(buf + 9, host,
			    அளவு(buf) - 9) >= அளவு(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		எனில் (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(பட, proxyfd, buf, 8);
		எனில் (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		எனில் (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} இல்லையெனில் எனில் (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		எனில் (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		எனில் (strchr(host, ':') != வெற்று) {
			r = snprintf(buf, அளவு(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} இல்லையெனில் {
			r = snprintf(buf, அளவு(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		எனில் (r == -1 || (size_t)r >= அளவு(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		எனில் (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		எனில் (authretry > 1) {
			எழுத்து resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, அளவு(buf), "%s:%s",
			    proxyuser, proxypass);
			எனில் (r == -1 || (size_t)r >= அளவு(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    அளவு(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, அளவு(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			எனில் (r == -1 || (size_t)r >= அளவு(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			எனில் ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		எனில் ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_வரி(proxyfd, buf, அளவு(buf));
		எனில் (proxyuser != வெற்று &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			எனில் (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			செல் again;
		} இல்லையெனில் எனில் (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		க்கு (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_வரி(proxyfd, buf, அளவு(buf));
			எனில் (*buf == '\0')
				நிறுத்து;
		}
		எனில் (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} இல்லையெனில்
		errx(1, "Unknown proxy protocol %d", socksv);

	திரும்பு (proxyfd);
}

