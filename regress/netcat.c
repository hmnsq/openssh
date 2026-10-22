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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/uio.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <netinet/tcp.h>
#অন্তর্ভাব <netinet/ip.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব "atomicio.h"

#অন্তর্ভাব <poll.h>
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
	(পরিমাণ(*(su)) - পরিমাণ((su)->sun_path) + strlen((su)->sun_path))
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
পূর্ণাঙ্ক	dflag;					/* detached, no stdin */
পূর্ণাঙ্ক	Fflag;					/* fdpass sock to stdout */
unsigned পূর্ণাঙ্ক iflag;				/* Interval Flag */
পূর্ণাঙ্ক	kflag;					/* More than one connect */
পূর্ণাঙ্ক	lflag;					/* Bind to local port */
পূর্ণাঙ্ক	Nflag;					/* shutdown() network socket */
পূর্ণাঙ্ক	nflag;					/* Don't do name look up */
বর্ণ   *Pflag;					/* Proxy username */
বর্ণ   *pflag;					/* Localport flag */
পূর্ণাঙ্ক	rflag;					/* Random ports flag */
বর্ণ   *sflag;					/* Source Address */
পূর্ণাঙ্ক	tflag;					/* Telnet Emulation */
পূর্ণাঙ্ক	uflag;					/* UDP - Default to TCP */
পূর্ণাঙ্ক	vflag;					/* Verbosity */
পূর্ণাঙ্ক	xflag;					/* Socks proxy */
পূর্ণাঙ্ক	zflag;					/* Port Scan Flag */
পূর্ণাঙ্ক	Dflag;					/* sodebug */
পূর্ণাঙ্ক	Iflag;					/* TCP receive buffer size */
পূর্ণাঙ্ক	Oflag;					/* TCP send buffer size */
পূর্ণাঙ্ক	Sflag;					/* TCP MD5 signature option */
পূর্ণাঙ্ক	Tflag = -1;				/* IP Type of Service */
পূর্ণাঙ্ক	rtableid = -1;

পূর্ণাঙ্ক timeout = -1;
পূর্ণাঙ্ক family = AF_UNSPEC;
বর্ণ *portlist[PORT_MAX+1];
বর্ণ *unix_dg_tmp_socket;

শূন্য	atelnet(পূর্ণাঙ্ক, unsigned বর্ণ *, unsigned পূর্ণাঙ্ক);
শূন্য	build_ports(বর্ণ *);
শূন্য	help(শূন্য);
পূর্ণাঙ্ক	local_listen(বর্ণ *, বর্ণ *, সংরচনা addrinfo);
শূন্য	readwrite(পূর্ণাঙ্ক);
শূন্য	fdpass(পূর্ণাঙ্ক nfd) __attribute__((noreturn));
পূর্ণাঙ্ক	remote_connect(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo);
পূর্ণাঙ্ক	timeout_connect(পূর্ণাঙ্ক, ধ্রুব সংরচনা sockaddr *, socklen_t);
পূর্ণাঙ্ক	socks_connect(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo,
	    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo, পূর্ণাঙ্ক, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক	udptest(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	unix_bind(বর্ণ *);
পূর্ণাঙ্ক	unix_connect(বর্ণ *);
পূর্ণাঙ্ক	unix_listen(বর্ণ *);
শূন্য	set_common_sockopts(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	map_tos(বর্ণ *, পূর্ণাঙ্ক *);
শূন্য	report_connect(ধ্রুব সংরচনা sockaddr *, socklen_t);
শূন্য	usage(পূর্ণাঙ্ক);
ssize_t drainbuf(পূর্ণাঙ্ক, unsigned বর্ণ *, size_t *);
ssize_t fillbuf(পূর্ণাঙ্ক, unsigned বর্ণ *, size_t *);


পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ *argv[])
{
	পূর্ণাঙ্ক ch, s, ret, socksv;
	বর্ণ *host, *uport;
	সংরচনা addrinfo hints;
	সংরচনা servent *sv;
	socklen_t len;
	সংরচনা sockaddr_storage cliaddr;
	বর্ণ *proxy = রিক্ত;
	ধ্রুব বর্ণ *errstr, *proxyhost = "", *proxyport = রিক্ত;
	সংরচনা addrinfo proxyhints;
	বর্ণ unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = রিক্ত;
	uport = রিক্ত;
	sv = রিক্ত;

	সঙ্কেত(SIGPIPE, SIG_IGN);

	যাবত্ ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		বিকল্প (ch) {
		পক্ষ '4':
			family = AF_INET;
			ভঙ্গ;
		পক্ষ '6':
			family = AF_INET6;
			ভঙ্গ;
		পক্ষ 'U':
			family = AF_UNIX;
			ভঙ্গ;
		পক্ষ 'X':
			যদি (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			অন্যথা যদি (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			অন্যথা যদি (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			অন্যথা যদি (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			অন্যথা
				errx(1, "unsupported proxy protocol");
			ভঙ্গ;
		পক্ষ 'd':
			dflag = 1;
			ভঙ্গ;
		পক্ষ 'F':
			Fflag = 1;
			ভঙ্গ;
		পক্ষ 'h':
			help();
			ভঙ্গ;
		পক্ষ 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			যদি (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ভঙ্গ;
		পক্ষ 'k':
			kflag = 1;
			ভঙ্গ;
		পক্ষ 'l':
			lflag = 1;
			ভঙ্গ;
		পক্ষ 'N':
			Nflag = 1;
			ভঙ্গ;
		পক্ষ 'n':
			nflag = 1;
			ভঙ্গ;
		পক্ষ 'P':
			Pflag = optarg;
			ভঙ্গ;
		পক্ষ 'p':
			pflag = optarg;
			ভঙ্গ;
		পক্ষ 'r':
			rflag = 1;
			ভঙ্গ;
		পক্ষ 's':
			sflag = optarg;
			ভঙ্গ;
		পক্ষ 't':
			tflag = 1;
			ভঙ্গ;
		পক্ষ 'u':
			uflag = 1;
			ভঙ্গ;
#ifdef SO_RTABLE
		পক্ষ 'V':
			rtableid = (পূর্ণাঙ্ক)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			যদি (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ভঙ্গ;
#endif
		পক্ষ 'v':
			vflag = 1;
			ভঙ্গ;
		পক্ষ 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			যদি (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ভঙ্গ;
		পক্ষ 'x':
			xflag = 1;
			যদি ((proxy = strdup(optarg)) == রিক্ত)
				errx(1, "strdup");
			ভঙ্গ;
		পক্ষ 'z':
			zflag = 1;
			ভঙ্গ;
		পক্ষ 'D':
			Dflag = 1;
			ভঙ্গ;
		পক্ষ 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			যদি (errstr != রিক্ত)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ভঙ্গ;
		পক্ষ 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			যদি (errstr != রিক্ত)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ভঙ্গ;
		পক্ষ 'S':
			Sflag = 1;
			ভঙ্গ;
		পক্ষ 'T':
			errstr = রিক্ত;
			errno = 0;
			যদি (map_tos(optarg, &Tflag))
				ভঙ্গ;
			যদি (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (পূর্ণাঙ্ক)strtol(optarg, রিক্ত, 16);
			অন্যথা
				Tflag = (পূর্ণাঙ্ক)strtonum(optarg, 0, 255,
				    &errstr);
			যদি (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ভঙ্গ;
		স্বভাব:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	যদি (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = রিক্ত;
	} অন্যথা যদি (argv[0] && !argv[1]) {
		যদি  (!lflag)
			usage(1);
		uport = argv[0];
		host = রিক্ত;
	} অন্যথা যদি (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} অন্যথা
		usage(1);

	যদি (lflag && sflag)
		errx(1, "cannot use -s and -l");
	যদি (lflag && pflag)
		errx(1, "cannot use -p and -l");
	যদি (lflag && zflag)
		errx(1, "cannot use -z and -l");
	যদি (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	যদি ((family == AF_UNIX) && uflag && !lflag) {
		যদি (sflag) {
			unix_dg_tmp_socket = sflag;
		} অন্যথা {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			যদি (mktemp(unix_dg_tmp_socket_buf) == রিক্ত)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	যদি (family != AF_UNIX) {
		memset(&hints, 0, পরিমাণ(সংরচনা addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		যদি (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	যদি (xflag) {
		যদি (uflag)
			errx(1, "no proxy support for UDP mode");

		যদি (lflag)
			errx(1, "no proxy support for listen");

		যদি (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		যদি (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		যদি (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, পরিমাণ(সংরচনা addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		যদি (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	যদি (lflag) {
		পূর্ণাঙ্ক connfd;
		ret = 0;

		যদি (family == AF_UNIX) {
			যদি (uflag)
				s = unix_bind(host);
			অন্যথা
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		প্রতি (;;) {
			যদি (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			যদি (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			যদি (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			অন্যথা যদি (uflag && !kflag) {
				পূর্ণাঙ্ক rv, plen;
				বর্ণ buf[16384];
				সংরচনা sockaddr_storage z;

				len = পরিমাণ(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (সংরচনা sockaddr *)&z, &len);
				যদি (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (সংরচনা sockaddr *)&z, len);
				যদি (rv < 0)
					err(1, "connect");

				যদি (vflag)
					report_connect((সংরচনা sockaddr *)&z, len);

				readwrite(s);
			} অন্যথা {
				len = পরিমাণ(cliaddr);
				connfd = accept(s, (সংরচনা sockaddr *)&cliaddr,
				    &len);
				যদি (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				যদি (vflag)
					report_connect((সংরচনা sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			যদি (family != AF_UNIX)
				close(s);
			অন্যথা যদি (uflag) {
				যদি (connect(s, রিক্ত, 0) < 0)
					err(1, "connect");
			}

			যদি (!kflag)
				ভঙ্গ;
		}
	} অন্যথা যদি (family == AF_UNIX) {
		ret = 0;

		যদি ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} অন্যথা
			ret = 1;

		যদি (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} অন্যথা {
		পূর্ণাঙ্ক i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		প্রতি (i = 0; portlist[i] != রিক্ত; i++) {
			যদি (s)
				close(s);

			যদি (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			অন্যথা
				s = remote_connect(host, portlist[i], hints);

			যদি (s < 0)
				অনুবর্ত;

			ret = 0;
			যদি (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				যদি (uflag) {
					যদি (udptest(s) == -1) {
						ret = 1;
						অনুবর্ত;
					}
				}

				/* Don't look up port if -n. */
				যদি (nflag)
					sv = রিক্ত;
				অন্যথা {
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
			যদি (Fflag)
				fdpass(s);
			অন্যথা যদি (!zflag)
				readwrite(s);
		}
	}

	যদি (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
পূর্ণাঙ্ক
unix_bind(বর্ণ *path)
{
	সংরচনা sockaddr_un sun_sa;
	পূর্ণাঙ্ক s;

	/* Create unix domain socket. */
	যদি ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		প্রত্যাগম (-1);

	memset(&sun_sa, 0, পরিমাণ(সংরচনা sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	যদি (strlcpy(sun_sa.sun_path, path, পরিমাণ(sun_sa.sun_path)) >=
	    পরিমাণ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		প্রত্যাগম (-1);
	}

	যদি (bind(s, (সংরচনা sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
পূর্ণাঙ্ক
unix_connect(বর্ণ *path)
{
	সংরচনা sockaddr_un sun_sa;
	পূর্ণাঙ্ক s;

	যদি (uflag) {
		যদি ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			প্রত্যাগম (-1);
	} অন্যথা {
		যদি ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			প্রত্যাগম (-1);
	}
	(শূন্য)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, পরিমাণ(সংরচনা sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	যদি (strlcpy(sun_sa.sun_path, path, পরিমাণ(sun_sa.sun_path)) >=
	    পরিমাণ(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		প্রত্যাগম (-1);
	}
	যদি (connect(s, (সংরচনা sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
পূর্ণাঙ্ক
unix_listen(বর্ণ *path)
{
	পূর্ণাঙ্ক s;
	যদি ((s = unix_bind(path)) < 0)
		প্রত্যাগম (-1);

	যদি (listen(s, 5) < 0) {
		close(s);
		প্রত্যাগম (-1);
	}
	প্রত্যাগম (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
পূর্ণাঙ্ক
remote_connect(ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *port, সংরচনা addrinfo hints)
{
	সংরচনা addrinfo *res, *res0;
	পূর্ণাঙ্ক s, error;
#যদি defined(SO_RTABLE) || defined(SO_BINDANY)
	পূর্ণাঙ্ক on = 1;
#endif

	যদি ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	কুরু {
		যদি ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			অনুবর্ত;

#ifdef SO_RTABLE
		যদি (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, পরিমাণ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		যদি (sflag || pflag) {
			সংরচনা addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, পরিমাণ(on));
#endif
			memset(&ahints, 0, পরিমাণ(সংরচনা addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			যদি ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			যদি (bind(s, (সংরচনা sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		যদি (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ভঙ্গ;
		অন্যথা যদি (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} যাবত্ ((res0 = res0->ai_next) != রিক্ত);

	freeaddrinfo(res);

	প্রত্যাগম (s);
}

পূর্ণাঙ্ক
timeout_connect(পূর্ণাঙ্ক s, ধ্রুব সংরচনা sockaddr *name, socklen_t namelen)
{
	সংরচনা pollfd pfd;
	socklen_t optlen;
	পূর্ণাঙ্ক flags = 0, optval;
	পূর্ণাঙ্ক ret;

	যদি (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		যদি (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	যদি ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		যদি ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = পরিমাণ(optval);
			যদি ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} অন্যথা যদি (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} অন্যথা
			err(1, "poll failed");
	}

	যদি (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	প্রত্যাগম (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
পূর্ণাঙ্ক
local_listen(বর্ণ *host, বর্ণ *port, সংরচনা addrinfo hints)
{
	সংরচনা addrinfo *res, *res0;
	পূর্ণাঙ্ক s, ret, x = 1;
	পূর্ণাঙ্ক error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	যদি (host == রিক্ত && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	যদি ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	কুরু {
		যদি ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			অনুবর্ত;

#ifdef SO_RTABLE
		যদি (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, পরিমাণ(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, পরিমাণ(x));
		যদি (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, পরিমাণ(x));
		যদি (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		যদি (bind(s, (সংরচনা sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ভঙ্গ;

		close(s);
		s = -1;
	} যাবত্ ((res0 = res0->ai_next) != রিক্ত);

	যদি (!uflag && s != -1) {
		যদি (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	প্রত্যাগম (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
শূন্য
readwrite(পূর্ণাঙ্ক net_fd)
{
	সংরচনা pollfd pfd[4];
	পূর্ণাঙ্ক stdin_fd = STDIN_FILENO;
	পূর্ণাঙ্ক stdout_fd = STDOUT_FILENO;
	unsigned বর্ণ netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned বর্ণ stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	পূর্ণাঙ্ক n, অঙ্ক_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	যদি (dflag)
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

	যাবত্ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		যদি (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			প্রত্যাগম;
		}
		/* both outputs are gone, we can't continue */
		যদি (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			প্রত্যাগম;
		}
		/* listen and net in gone, queues empty, done */
		যদি (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			প্রত্যাগম;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		যদি (iflag)
			sleep(iflag);

		/* poll */
		অঙ্ক_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		যদি (অঙ্ক_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		যদি (অঙ্ক_fds == 0)
			প্রত্যাগম;

		/* treat socket error conditions */
		প্রতি (n = 0; n < 4; n++) {
			যদি (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		যদি (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		যদি (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		যদি (pfd[POLL_NETOUT].revents & POLLHUP) {
			যদি (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		যদি (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		যদি (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		যদি (pfd[POLL_STDOUT].fd == -1) {
			যদি (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		যদি (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			যদি (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			যদি (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			যদি (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		যদি (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			যদি (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			যদি (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			যদি (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		যদি (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			যদি (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			যদি (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			যদি (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			যদি (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			যদি (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		যদি (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			যদি (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			যদি (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			যদি (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		যদি (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			যদি (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		যদি (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(পূর্ণাঙ্ক fd, unsigned বর্ণ *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = লিখ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	যদি (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	যদি (n <= 0)
		প্রত্যাগম n;
	/* adjust buffer */
	adjust = *bufpos - n;
	যদি (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	প্রত্যাগম n;
}


ssize_t
fillbuf(পূর্ণাঙ্ক fd, unsigned বর্ণ *buf, size_t *bufpos)
{
	size_t অঙ্ক = BUFSIZE - *bufpos;
	ssize_t n;

	n = পঠ(fd, buf + *bufpos, অঙ্ক);
	/* don't treat EAGAIN, EINTR as error */
	যদি (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	যদি (n <= 0)
		প্রত্যাগম n;
	*bufpos += n;
	প্রত্যাগম n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
শূন্য
fdpass(পূর্ণাঙ্ক nfd)
{
#যদি defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	সংরচনা msghdr বার্তা;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	সঙ্ঘ {
		সংরচনা cmsghdr hdr;
		বর্ণ buf[CMSG_SPACE(পরিমাণ(পূর্ণাঙ্ক))];
	} cmsgbuf;
	সংরচনা cmsghdr *cmsg;
#endif
	সংরচনা iovec vec;
	বর্ণ ch = '\0';
	সংরচনা pollfd pfd;
	ssize_t r;

	memset(&বার্তা, 0, পরিমাণ(বার্তা));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	বার্তা.বার্তা_accrights = (caddr_t)&nfd;
	বার্তা.বার্তা_accrightslen = পরিমাণ(nfd);
#অন্যথা
	memset(&cmsgbuf, 0, পরিমাণ(cmsgbuf));
	বার্তা.msg_control = (caddr_t)&cmsgbuf.buf;
	বার্তা.msg_controllen = পরিমাণ(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&বার্তা);
	cmsg->cmsg_len = CMSG_LEN(পরিমাণ(পূর্ণাঙ্ক));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(পূর্ণাঙ্ক *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	বার্তা.msg_iov = &vec;
	বার্তা.msg_iovlen = 1;

	bzero(&pfd, পরিমাণ(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	প্রতি (;;) {
		r = sendmsg(STDOUT_FILENO, &বার্তা, 0);
		যদি (r == -1) {
			যদি (errno == EAGAIN || errno == EINTR) {
				যদি (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				অনুবর্ত;
			}
			err(1, "sendmsg");
		} অন্যথা যদি (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		অন্যথা
			ভঙ্গ;
	}
	exit(0);
#অন্যথা
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
শূন্য
atelnet(পূর্ণাঙ্ক nfd, unsigned বর্ণ *buf, unsigned পূর্ণাঙ্ক size)
{
	unsigned বর্ণ *p, *end;
	unsigned বর্ণ obuf[4];

	যদি (size < 3)
		প্রত্যাগম;
	end = buf + size - 2;

	প্রতি (p = buf; p < end; p++) {
		যদি (*p != IAC)
			অনুবর্ত;

		obuf[0] = IAC;
		p++;
		যদি ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		অন্যথা যদি ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		অন্যথা
			অনুবর্ত;

		p++;
		obuf[2] = *p;
		যদি (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
শূন্য
build_ports(বর্ণ *p)
{
	ধ্রুব বর্ণ *errstr;
	বর্ণ *n;
	পূর্ণাঙ্ক hi, lo, cp;
	পূর্ণাঙ্ক x = 0;

	যদি ((n = strchr(p, '-')) != রিক্ত) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		যদি (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		যদি (errstr)
			errx(1, "port number %s: %s", errstr, p);

		যদি (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		প্রতি (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			যদি (portlist[x] == রিক্ত)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		যদি (rflag) {
			পূর্ণাঙ্ক y;
			বর্ণ *c;

			প্রতি (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} অন্যথা {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		যদি (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		যদি (portlist[0] == রিক্ত)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
পূর্ণাঙ্ক
udptest(পূর্ণাঙ্ক s)
{
	পূর্ণাঙ্ক i, ret;

	প্রতি (i = 0; i <= 3; i++) {
		যদি (লিখ(s, "X", 1) == 1)
			ret = 1;
		অন্যথা
			ret = -1;
	}
	প্রত্যাগম (ret);
}

শূন্য
set_common_sockopts(পূর্ণাঙ্ক s, পূর্ণাঙ্ক af)
{
	পূর্ণাঙ্ক x = 1;

#ifdef TCP_MD5SIG
	যদি (Sflag) {
		যদি (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, পরিমাণ(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	যদি (Dflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, পরিমাণ(x)) == -1)
			err(1, "setsockopt");
	}
#যদি defined(IP_TOS) && defined(IPV6_TCLASS)
	যদি (Tflag != -1) {
		পূর্ণাঙ্ক proto, option;

		যদি (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} অন্যথা {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		যদি (setsockopt(s, proto, option, &Tflag, পরিমাণ(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	যদি (Iflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, পরিমাণ(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	যদি (Oflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, পরিমাণ(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

পূর্ণাঙ্ক
map_tos(বর্ণ *s, পূর্ণাঙ্ক *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ধ্রুব সংরচনা toskeywords {
		ধ্রুব বর্ণ	*keyword;
		পূর্ণাঙ্ক		 val;
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
		{ রিক্ত, 		-1 },
	};

	প্রতি (t = toskeywords; t->keyword != রিক্ত; t++) {
		যদি (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			প্রত্যাগম (1);
		}
	}
#endif

	প্রত্যাগম (0);
}

শূন্য
report_connect(ধ্রুব সংরচনা sockaddr *sa, socklen_t salen)
{
	বর্ণ remote_host[NI_MAXHOST];
	বর্ণ remote_port[NI_MAXSERV];
	পূর্ণাঙ্ক herr;
	পূর্ণাঙ্ক flags = NI_NUMERICSERV;
	
	যদি (nflag)
		flags |= NI_NUMERICHOST;
	
	যদি ((herr = getnameinfo(sa, salen,
	    remote_host, পরিমাণ(remote_host),
	    remote_port, পরিমাণ(remote_port),
	    flags)) != 0) {
		যদি (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		অন্যথা
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

শূন্য
help(শূন্য)
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
	\t-i secs\t	Delay interval প্রতি সারিগুলি sent, ports scanned\n\
	\t-k		Keep inbound sockets open প্রতি multiple connects\n\
	\t-l		Listen mode, প্রতি inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername প্রতি proxy authentication\n\
	\t-p port\t	Specify local port প্রতি remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout প্রতি connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used প্রতি scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

শূন্য
usage(পূর্ণাঙ্ক ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	যদি (ret)
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

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <resolv.h>

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

পূর্ণাঙ্ক	remote_connect(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo);
পূর্ণাঙ্ক	socks_connect(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo,
	    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা addrinfo, পূর্ণাঙ্ক,
	    ধ্রুব বর্ণ *);

স্থির পূর্ণাঙ্ক
decode_addrport(ধ্রুব বর্ণ *h, ধ্রুব বর্ণ *p, সংরচনা sockaddr *addr,
    socklen_t addrlen, পূর্ণাঙ্ক v4only, পূর্ণাঙ্ক numeric)
{
	পূর্ণাঙ্ক r;
	সংরচনা addrinfo hints, *res;

	bzero(&hints, পরিমাণ(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	যদি (r != 0) {
		যদি (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		প্রত্যাগম (-1);
	}
	যদি (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
proxy_read_সারি(পূর্ণাঙ্ক fd, বর্ণ *buf, size_t bufsz)
{
	size_t off;

	প্রতি(off = 0;;) {
		যদি (off >= bufsz)
			errx(1, "proxy read too long");
		যদি (atomicio(পঠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		যদি (buf[off] == '\r')
			অনুবর্ত;
		যদি (buf[off] == '\n') {
			buf[off] = '\0';
			ভঙ্গ;
		}
		off++;
	}
	প্রত্যাগম (off);
}

স্থির ধ্রুব বর্ণ *
getproxypass(ধ্রুব বর্ণ *proxyuser, ধ্রুব বর্ণ *proxyhost)
{
	বর্ণ prompt[512];
	স্থির বর্ণ pw[256];

	snprintf(prompt, পরিমাণ(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	যদি (readpassphrase(prompt, pw, পরিমাণ(pw), RPP_REQUIRE_TTY) == রিক্ত)
		errx(1, "Unable to read proxy passphrase");
	প্রত্যাগম (pw);
}

পূর্ণাঙ্ক
socks_connect(ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *port,
    সংরচনা addrinfo hints __attribute__ ((__unused__)),
    ধ্রুব বর্ণ *proxyhost, ধ্রুব বর্ণ *proxyport, সংরচনা addrinfo proxyhints,
    পূর্ণাঙ্ক socksv, ধ্রুব বর্ণ *proxyuser)
{
	পূর্ণাঙ্ক proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned বর্ণ buf[1024];
	size_t cnt;
	সংরচনা sockaddr_storage addr;
	সংরচনা sockaddr_in *in4 = (সংরচনা sockaddr_in *)&addr;
	সংরচনা sockaddr_in6 *in6 = (সংরচনা sockaddr_in6 *)&addr;
	in_port_t serverport;
	ধ্রুব বর্ণ *proxypass = রিক্ত;

	যদি (proxyport == রিক্ত)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	যদি (decode_addrport("0.0.0.0", port, (সংরচনা sockaddr *)&addr,
	    পরিমাণ(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	যদি (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	যদি (proxyfd < 0)
		প্রত্যাগম (-1);

	যদি (socksv == 5) {
		যদি (decode_addrport(host, port, (সংরচনা sockaddr *)&addr,
		    পরিমাণ(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		যদি (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(পঠ, proxyfd, buf, 2);
		যদি (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		যদি (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		বিকল্প (addr.ss_family) {
		পক্ষ 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			যদি (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, পরিমাণ serverport);
			wlen = 7 + hlen;
			ভঙ্গ;
		পক্ষ AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, পরিমাণ in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, পরিমাণ in4->sin_port);
			wlen = 10;
			ভঙ্গ;
		পক্ষ AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, পরিমাণ in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    পরিমাণ in6->sin6_port);
			wlen = 22;
			ভঙ্গ;
		স্বভাব:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		যদি (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(পঠ, proxyfd, buf, 4);
		যদি (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		যদি (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		বিকল্প (buf[3]) {
		পক্ষ SOCKS_IPV4:
			cnt = atomicio(পঠ, proxyfd, buf + 4, 6);
			যদি (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ভঙ্গ;
		পক্ষ SOCKS_IPV6:
			cnt = atomicio(পঠ, proxyfd, buf + 4, 18);
			যদি (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ভঙ্গ;
		স্বভাব:
			errx(1, "connection failed, unsupported address type");
		}
	} অন্যথা যদি (socksv == 4 || socksv == 44) {
		যদি (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (সংরচনা sockaddr *)&addr,
			    পরিমাণ(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, পরিমাণ in4->sin_port);
		যদি (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, পরিমাণ in4->sin_addr);
		} অন্যথা {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		যদি (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			যদি (strlcpy(buf + 9, host,
			    পরিমাণ(buf) - 9) >= পরিমাণ(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		যদি (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(পঠ, proxyfd, buf, 8);
		যদি (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		যদি (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} অন্যথা যদি (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		যদি (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		যদি (strchr(host, ':') != রিক্ত) {
			r = snprintf(buf, পরিমাণ(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} অন্যথা {
			r = snprintf(buf, পরিমাণ(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		যদি (r == -1 || (size_t)r >= পরিমাণ(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		যদি (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		যদি (authretry > 1) {
			বর্ণ resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, পরিমাণ(buf), "%s:%s",
			    proxyuser, proxypass);
			যদি (r == -1 || (size_t)r >= পরিমাণ(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    পরিমাণ(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, পরিমাণ(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			যদি (r == -1 || (size_t)r >= পরিমাণ(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			যদি ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		যদি ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_সারি(proxyfd, buf, পরিমাণ(buf));
		যদি (proxyuser != রিক্ত &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			যদি (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			গচ্ছ again;
		} অন্যথা যদি (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		প্রতি (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_সারি(proxyfd, buf, পরিমাণ(buf));
			যদি (*buf == '\0')
				ভঙ্গ;
		}
		যদি (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} অন্যথা
		errx(1, "Unknown proxy protocol %d", socksv);

	প্রত্যাগম (proxyfd);
}

