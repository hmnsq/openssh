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
	(আকার(*(su)) - আকার((su)->sun_path) + strlen((su)->sun_path))
#endif

#define PORT_MAX	65535
#define PORT_MAX_LEN	6
#define UNIX_DG_TMP_SOCKET_আকার	19

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3
#define BUFSIZE 16384

/* Command Line Options */
পূর্ণসংখ্যা	dflag;					/* detached, no stdin */
পূর্ণসংখ্যা	Fflag;					/* fdpass sock to stdout */
unsigned পূর্ণসংখ্যা iflag;				/* Interval Flag */
পূর্ণসংখ্যা	kflag;					/* More than one connect */
পূর্ণসংখ্যা	lflag;					/* Bind to local port */
পূর্ণসংখ্যা	Nflag;					/* shutdown() network socket */
পূর্ণসংখ্যা	nflag;					/* Don't do name look up */
অক্ষর   *Pflag;					/* Proxy username */
অক্ষর   *pflag;					/* Localport flag */
পূর্ণসংখ্যা	rflag;					/* Random ports flag */
অক্ষর   *sflag;					/* Source Address */
পূর্ণসংখ্যা	tflag;					/* Telnet Emulation */
পূর্ণসংখ্যা	uflag;					/* UDP - Default to TCP */
পূর্ণসংখ্যা	vflag;					/* Verbosity */
পূর্ণসংখ্যা	xflag;					/* Socks proxy */
পূর্ণসংখ্যা	zflag;					/* Port Scan Flag */
পূর্ণসংখ্যা	Dflag;					/* sodebug */
পূর্ণসংখ্যা	Iflag;					/* TCP receive buffer size */
পূর্ণসংখ্যা	Oflag;					/* TCP send buffer size */
পূর্ণসংখ্যা	Sflag;					/* TCP MD5 signature option */
পূর্ণসংখ্যা	Tflag = -1;				/* IP Type of Service */
পূর্ণসংখ্যা	rtableid = -1;

পূর্ণসংখ্যা timeout = -1;
পূর্ণসংখ্যা family = AF_UNSPEC;
অক্ষর *portlist[PORT_MAX+1];
অক্ষর *unix_dg_tmp_socket;

শূন্য	atelnet(পূর্ণসংখ্যা, unsigned অক্ষর *, unsigned পূর্ণসংখ্যা);
শূন্য	build_ports(অক্ষর *);
শূন্য	help(শূন্য);
পূর্ণসংখ্যা	local_listen(অক্ষর *, অক্ষর *, কাঠামো addrinfo);
শূন্য	readwrite(পূর্ণসংখ্যা);
শূন্য	fdpass(পূর্ণসংখ্যা nfd) __attribute__((noreturn));
পূর্ণসংখ্যা	remote_connect(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo);
পূর্ণসংখ্যা	timeout_connect(পূর্ণসংখ্যা, ধ্রুবক কাঠামো sockaddr *, socklen_t);
পূর্ণসংখ্যা	socks_connect(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo,
	    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	udptest(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	unix_bind(অক্ষর *);
পূর্ণসংখ্যা	unix_connect(অক্ষর *);
পূর্ণসংখ্যা	unix_listen(অক্ষর *);
শূন্য	set_common_sockopts(পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	map_tos(অক্ষর *, পূর্ণসংখ্যা *);
শূন্য	report_connect(ধ্রুবক কাঠামো sockaddr *, socklen_t);
শূন্য	usage(পূর্ণসংখ্যা);
ssize_t drainbuf(পূর্ণসংখ্যা, unsigned অক্ষর *, আকার_t *);
ssize_t fillbuf(পূর্ণসংখ্যা, unsigned অক্ষর *, আকার_t *);


পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর *argv[])
{
	পূর্ণসংখ্যা ch, s, ret, socksv;
	অক্ষর *host, *uport;
	কাঠামো addrinfo hints;
	কাঠামো servent *sv;
	socklen_t len;
	কাঠামো sockaddr_storage cliaddr;
	অক্ষর *proxy = ফাঁকা;
	ধ্রুবক অক্ষর *errstr, *proxyhost = "", *proxyport = ফাঁকা;
	কাঠামো addrinfo proxyhints;
	অক্ষর unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_আকার];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ফাঁকা;
	uport = ফাঁকা;
	sv = ফাঁকা;

	সংকেত(SIGPIPE, SIG_IGN);

	যখন ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র '4':
			family = AF_INET;
			বিরতি;
		ক্ষেত্র '6':
			family = AF_INET6;
			বিরতি;
		ক্ষেত্র 'U':
			family = AF_UNIX;
			বিরতি;
		ক্ষেত্র 'X':
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
			বিরতি;
		ক্ষেত্র 'd':
			dflag = 1;
			বিরতি;
		ক্ষেত্র 'F':
			Fflag = 1;
			বিরতি;
		ক্ষেত্র 'h':
			help();
			বিরতি;
		ক্ষেত্র 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			যদি (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			বিরতি;
		ক্ষেত্র 'k':
			kflag = 1;
			বিরতি;
		ক্ষেত্র 'l':
			lflag = 1;
			বিরতি;
		ক্ষেত্র 'N':
			Nflag = 1;
			বিরতি;
		ক্ষেত্র 'n':
			nflag = 1;
			বিরতি;
		ক্ষেত্র 'P':
			Pflag = optarg;
			বিরতি;
		ক্ষেত্র 'p':
			pflag = optarg;
			বিরতি;
		ক্ষেত্র 'r':
			rflag = 1;
			বিরতি;
		ক্ষেত্র 's':
			sflag = optarg;
			বিরতি;
		ক্ষেত্র 't':
			tflag = 1;
			বিরতি;
		ক্ষেত্র 'u':
			uflag = 1;
			বিরতি;
#ifdef SO_RTABLE
		ক্ষেত্র 'V':
			rtableid = (পূর্ণসংখ্যা)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			যদি (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			বিরতি;
#endif
		ক্ষেত্র 'v':
			vflag = 1;
			বিরতি;
		ক্ষেত্র 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			যদি (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			বিরতি;
		ক্ষেত্র 'x':
			xflag = 1;
			যদি ((proxy = strdup(optarg)) == ফাঁকা)
				errx(1, "strdup");
			বিরতি;
		ক্ষেত্র 'z':
			zflag = 1;
			বিরতি;
		ক্ষেত্র 'D':
			Dflag = 1;
			বিরতি;
		ক্ষেত্র 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			যদি (errstr != ফাঁকা)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			বিরতি;
		ক্ষেত্র 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			যদি (errstr != ফাঁকা)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			বিরতি;
		ক্ষেত্র 'S':
			Sflag = 1;
			বিরতি;
		ক্ষেত্র 'T':
			errstr = ফাঁকা;
			errno = 0;
			যদি (map_tos(optarg, &Tflag))
				বিরতি;
			যদি (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (পূর্ণসংখ্যা)strtol(optarg, ফাঁকা, 16);
			অন্যথা
				Tflag = (পূর্ণসংখ্যা)strtonum(optarg, 0, 255,
				    &errstr);
			যদি (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			বিরতি;
		পূর্বনির্ধারিত:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	যদি (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ফাঁকা;
	} অন্যথা যদি (argv[0] && !argv[1]) {
		যদি  (!lflag)
			usage(1);
		uport = argv[0];
		host = ফাঁকা;
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
				UNIX_DG_TMP_SOCKET_আকার);
			যদি (mktemp(unix_dg_tmp_socket_buf) == ফাঁকা)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	যদি (family != AF_UNIX) {
		memset(&hints, 0, আকার(কাঠামো addrinfo));
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

		memset(&proxyhints, 0, আকার(কাঠামো addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		যদি (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	যদি (lflag) {
		পূর্ণসংখ্যা connfd;
		ret = 0;

		যদি (family == AF_UNIX) {
			যদি (uflag)
				s = unix_bind(host);
			অন্যথা
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		জন্য (;;) {
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
				পূর্ণসংখ্যা rv, plen;
				অক্ষর buf[16384];
				কাঠামো sockaddr_storage z;

				len = আকার(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (কাঠামো sockaddr *)&z, &len);
				যদি (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (কাঠামো sockaddr *)&z, len);
				যদি (rv < 0)
					err(1, "connect");

				যদি (vflag)
					report_connect((কাঠামো sockaddr *)&z, len);

				readwrite(s);
			} অন্যথা {
				len = আকার(cliaddr);
				connfd = accept(s, (কাঠামো sockaddr *)&cliaddr,
				    &len);
				যদি (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				যদি (vflag)
					report_connect((কাঠামো sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			যদি (family != AF_UNIX)
				close(s);
			অন্যথা যদি (uflag) {
				যদি (connect(s, ফাঁকা, 0) < 0)
					err(1, "connect");
			}

			যদি (!kflag)
				বিরতি;
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
		পূর্ণসংখ্যা i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		জন্য (i = 0; portlist[i] != ফাঁকা; i++) {
			যদি (s)
				close(s);

			যদি (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			অন্যথা
				s = remote_connect(host, portlist[i], hints);

			যদি (s < 0)
				চালু;

			ret = 0;
			যদি (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				যদি (uflag) {
					যদি (udptest(s) == -1) {
						ret = 1;
						চালু;
					}
				}

				/* Don't look up port if -n. */
				যদি (nflag)
					sv = ফাঁকা;
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
পূর্ণসংখ্যা
unix_bind(অক্ষর *path)
{
	কাঠামো sockaddr_un sun_sa;
	পূর্ণসংখ্যা s;

	/* Create unix domain socket. */
	যদি ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ফেরত (-1);

	memset(&sun_sa, 0, আকার(কাঠামো sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	যদি (strlcpy(sun_sa.sun_path, path, আকার(sun_sa.sun_path)) >=
	    আকার(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ফেরত (-1);
	}

	যদি (bind(s, (কাঠামো sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ফেরত (-1);
	}
	ফেরত (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
পূর্ণসংখ্যা
unix_connect(অক্ষর *path)
{
	কাঠামো sockaddr_un sun_sa;
	পূর্ণসংখ্যা s;

	যদি (uflag) {
		যদি ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ফেরত (-1);
	} অন্যথা {
		যদি ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ফেরত (-1);
	}
	(শূন্য)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, আকার(কাঠামো sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	যদি (strlcpy(sun_sa.sun_path, path, আকার(sun_sa.sun_path)) >=
	    আকার(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ফেরত (-1);
	}
	যদি (connect(s, (কাঠামো sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ফেরত (-1);
	}
	ফেরত (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
পূর্ণসংখ্যা
unix_listen(অক্ষর *path)
{
	পূর্ণসংখ্যা s;
	যদি ((s = unix_bind(path)) < 0)
		ফেরত (-1);

	যদি (listen(s, 5) < 0) {
		close(s);
		ফেরত (-1);
	}
	ফেরত (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
পূর্ণসংখ্যা
remote_connect(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *port, কাঠামো addrinfo hints)
{
	কাঠামো addrinfo *res, *res0;
	পূর্ণসংখ্যা s, error;
#যদি defined(SO_RTABLE) || defined(SO_BINDANY)
	পূর্ণসংখ্যা on = 1;
#endif

	যদি ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	করো {
		যদি ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			চালু;

#ifdef SO_RTABLE
		যদি (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, আকার(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		যদি (sflag || pflag) {
			কাঠামো addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, আকার(on));
#endif
			memset(&ahints, 0, আকার(কাঠামো addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			যদি ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			যদি (bind(s, (কাঠামো sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		যদি (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			বিরতি;
		অন্যথা যদি (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} যখন ((res0 = res0->ai_next) != ফাঁকা);

	freeaddrinfo(res);

	ফেরত (s);
}

পূর্ণসংখ্যা
timeout_connect(পূর্ণসংখ্যা s, ধ্রুবক কাঠামো sockaddr *name, socklen_t namelen)
{
	কাঠামো pollfd pfd;
	socklen_t optlen;
	পূর্ণসংখ্যা flags = 0, optval;
	পূর্ণসংখ্যা ret;

	যদি (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		যদি (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	যদি ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		যদি ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = আকার(optval);
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

	ফেরত (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
পূর্ণসংখ্যা
local_listen(অক্ষর *host, অক্ষর *port, কাঠামো addrinfo hints)
{
	কাঠামো addrinfo *res, *res0;
	পূর্ণসংখ্যা s, ret, x = 1;
	পূর্ণসংখ্যা error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	যদি (host == ফাঁকা && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	যদি ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	করো {
		যদি ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			চালু;

#ifdef SO_RTABLE
		যদি (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, আকার(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, আকার(x));
		যদি (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, আকার(x));
		যদি (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		যদি (bind(s, (কাঠামো sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			বিরতি;

		close(s);
		s = -1;
	} যখন ((res0 = res0->ai_next) != ফাঁকা);

	যদি (!uflag && s != -1) {
		যদি (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ফেরত (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
শূন্য
readwrite(পূর্ণসংখ্যা net_fd)
{
	কাঠামো pollfd pfd[4];
	পূর্ণসংখ্যা stdin_fd = STDIN_FILENO;
	পূর্ণসংখ্যা stdout_fd = STDOUT_FILENO;
	unsigned অক্ষর netinbuf[BUFSIZE];
	আকার_t netinbufpos = 0;
	unsigned অক্ষর stdinbuf[BUFSIZE];
	আকার_t stdinbufpos = 0;
	পূর্ণসংখ্যা n, অঙ্ক_fds;
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

	যখন (1) {
		/* both inputs are gone, buffers are empty, we are done */
		যদি (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ফেরত;
		}
		/* both outputs are gone, we can't continue */
		যদি (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ফেরত;
		}
		/* listen and net in gone, queues empty, done */
		যদি (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ফেরত;
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
			ফেরত;

		/* treat socket error conditions */
		জন্য (n = 0; n < 4; n++) {
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
drainbuf(পূর্ণসংখ্যা fd, unsigned অক্ষর *buf, আকার_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = লিখ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	যদি (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	যদি (n <= 0)
		ফেরত n;
	/* adjust buffer */
	adjust = *bufpos - n;
	যদি (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ফেরত n;
}


ssize_t
fillbuf(পূর্ণসংখ্যা fd, unsigned অক্ষর *buf, আকার_t *bufpos)
{
	আকার_t অঙ্ক = BUFSIZE - *bufpos;
	ssize_t n;

	n = পঠ(fd, buf + *bufpos, অঙ্ক);
	/* don't treat EAGAIN, EINTR as error */
	যদি (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	যদি (n <= 0)
		ফেরত n;
	*bufpos += n;
	ফেরত n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
শূন্য
fdpass(পূর্ণসংখ্যা nfd)
{
#যদি defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	কাঠামো msghdr বার্তা;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	সংঘ {
		কাঠামো cmsghdr hdr;
		অক্ষর buf[CMSG_SPACE(আকার(পূর্ণসংখ্যা))];
	} cmsgbuf;
	কাঠামো cmsghdr *cmsg;
#endif
	কাঠামো iovec vec;
	অক্ষর ch = '\0';
	কাঠামো pollfd pfd;
	ssize_t r;

	memset(&বার্তা, 0, আকার(বার্তা));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	বার্তা.বার্তা_accrights = (caddr_t)&nfd;
	বার্তা.বার্তা_accrightslen = আকার(nfd);
#অন্যথা
	memset(&cmsgbuf, 0, আকার(cmsgbuf));
	বার্তা.msg_control = (caddr_t)&cmsgbuf.buf;
	বার্তা.msg_controllen = আকার(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&বার্তা);
	cmsg->cmsg_len = CMSG_LEN(আকার(পূর্ণসংখ্যা));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(পূর্ণসংখ্যা *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	বার্তা.msg_iov = &vec;
	বার্তা.msg_iovlen = 1;

	bzero(&pfd, আকার(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	জন্য (;;) {
		r = sendmsg(STDOUT_FILENO, &বার্তা, 0);
		যদি (r == -1) {
			যদি (errno == EAGAIN || errno == EINTR) {
				যদি (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				চালু;
			}
			err(1, "sendmsg");
		} অন্যথা যদি (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		অন্যথা
			বিরতি;
	}
	exit(0);
#অন্যথা
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
শূন্য
atelnet(পূর্ণসংখ্যা nfd, unsigned অক্ষর *buf, unsigned পূর্ণসংখ্যা আকার_2)
{
	unsigned অক্ষর *p, *end;
	unsigned অক্ষর obuf[4];

	যদি (আকার_2 < 3)
		ফেরত;
	end = buf + আকার_2 - 2;

	জন্য (p = buf; p < end; p++) {
		যদি (*p != IAC)
			চালু;

		obuf[0] = IAC;
		p++;
		যদি ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		অন্যথা যদি ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		অন্যথা
			চালু;

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
build_ports(অক্ষর *p)
{
	ধ্রুবক অক্ষর *errstr;
	অক্ষর *n;
	পূর্ণসংখ্যা hi, lo, cp;
	পূর্ণসংখ্যা x = 0;

	যদি ((n = strchr(p, '-')) != ফাঁকা) {
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
		জন্য (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			যদি (portlist[x] == ফাঁকা)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		যদি (rflag) {
			পূর্ণসংখ্যা y;
			অক্ষর *c;

			জন্য (x = 0; x <= (hi - lo); x++) {
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
		যদি (portlist[0] == ফাঁকা)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
পূর্ণসংখ্যা
udptest(পূর্ণসংখ্যা s)
{
	পূর্ণসংখ্যা i, ret;

	জন্য (i = 0; i <= 3; i++) {
		যদি (লিখ(s, "X", 1) == 1)
			ret = 1;
		অন্যথা
			ret = -1;
	}
	ফেরত (ret);
}

শূন্য
set_common_sockopts(পূর্ণসংখ্যা s, পূর্ণসংখ্যা af)
{
	পূর্ণসংখ্যা x = 1;

#ifdef TCP_MD5SIG
	যদি (Sflag) {
		যদি (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, আকার(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	যদি (Dflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, আকার(x)) == -1)
			err(1, "setsockopt");
	}
#যদি defined(IP_TOS) && defined(IPV6_TCLASS)
	যদি (Tflag != -1) {
		পূর্ণসংখ্যা proto, option;

		যদি (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} অন্যথা {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		যদি (setsockopt(s, proto, option, &Tflag, আকার(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	যদি (Iflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, আকার(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	যদি (Oflag) {
		যদি (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, আকার(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

পূর্ণসংখ্যা
map_tos(অক্ষর *s, পূর্ণসংখ্যা *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ধ্রুবক কাঠামো toskeywords {
		ধ্রুবক অক্ষর	*keyword;
		পূর্ণসংখ্যা		 val;
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
		{ ফাঁকা, 		-1 },
	};

	জন্য (t = toskeywords; t->keyword != ফাঁকা; t++) {
		যদি (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ফেরত (1);
		}
	}
#endif

	ফেরত (0);
}

শূন্য
report_connect(ধ্রুবক কাঠামো sockaddr *sa, socklen_t salen)
{
	অক্ষর remote_host[NI_MAXHOST];
	অক্ষর remote_port[NI_MAXSERV];
	পূর্ণসংখ্যা herr;
	পূর্ণসংখ্যা flags = NI_NUMERICSERV;
	
	যদি (nflag)
		flags |= NI_NUMERICHOST;
	
	যদি ((herr = getnameinfo(sa, salen,
	    remote_host, আকার(remote_host),
	    remote_port, আকার(remote_port),
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
	\t-I দৈর্ঘ্য	TCP receive বাফার দৈর্ঘ্য\n\
	\t-i secs\t	Delay interval জন্য সারিগুলি sent, ports scanned\n\
	\t-k		Keep inbound sockets open জন্য multiple connects\n\
	\t-l		Listen mode, জন্য inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O দৈর্ঘ্য	TCP send বাফার দৈর্ঘ্য\n\
	\t-P proxyuser\tUsername জন্য proxy authentication\n\
	\t-p port\t	Specify local port জন্য remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout জন্য connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used জন্য scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

শূন্য
usage(পূর্ণসংখ্যা ret)
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

পূর্ণসংখ্যা	remote_connect(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo);
পূর্ণসংখ্যা	socks_connect(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo,
	    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো addrinfo, পূর্ণসংখ্যা,
	    ধ্রুবক অক্ষর *);

স্থির পূর্ণসংখ্যা
decode_addrport(ধ্রুবক অক্ষর *h, ধ্রুবক অক্ষর *p, কাঠামো sockaddr *addr,
    socklen_t addrlen, পূর্ণসংখ্যা v4only, পূর্ণসংখ্যা numeric)
{
	পূর্ণসংখ্যা r;
	কাঠামো addrinfo hints, *res;

	bzero(&hints, আকার(hints));
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
		ফেরত (-1);
	}
	যদি (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
proxy_read_সারি(পূর্ণসংখ্যা fd, অক্ষর *buf, আকার_t bufsz)
{
	আকার_t off;

	জন্য(off = 0;;) {
		যদি (off >= bufsz)
			errx(1, "proxy read too long");
		যদি (atomicio(পঠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		যদি (buf[off] == '\r')
			চালু;
		যদি (buf[off] == '\n') {
			buf[off] = '\0';
			বিরতি;
		}
		off++;
	}
	ফেরত (off);
}

স্থির ধ্রুবক অক্ষর *
getproxypass(ধ্রুবক অক্ষর *proxyuser, ধ্রুবক অক্ষর *proxyhost)
{
	অক্ষর prompt[512];
	স্থির অক্ষর pw[256];

	snprintf(prompt, আকার(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	যদি (readpassphrase(prompt, pw, আকার(pw), RPP_REQUIRE_TTY) == ফাঁকা)
		errx(1, "Unable to read proxy passphrase");
	ফেরত (pw);
}

পূর্ণসংখ্যা
socks_connect(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *port,
    কাঠামো addrinfo hints __attribute__ ((__unused__)),
    ধ্রুবক অক্ষর *proxyhost, ধ্রুবক অক্ষর *proxyport, কাঠামো addrinfo proxyhints,
    পূর্ণসংখ্যা socksv, ধ্রুবক অক্ষর *proxyuser)
{
	পূর্ণসংখ্যা proxyfd, r, authretry = 0;
	আকার_t hlen, wlen = 0;
	unsigned অক্ষর buf[1024];
	আকার_t cnt;
	কাঠামো sockaddr_storage addr;
	কাঠামো sockaddr_in *in4 = (কাঠামো sockaddr_in *)&addr;
	কাঠামো sockaddr_in6 *in6 = (কাঠামো sockaddr_in6 *)&addr;
	in_port_t serverport;
	ধ্রুবক অক্ষর *proxypass = ফাঁকা;

	যদি (proxyport == ফাঁকা)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	যদি (decode_addrport("0.0.0.0", port, (কাঠামো sockaddr *)&addr,
	    আকার(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	যদি (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	যদি (proxyfd < 0)
		ফেরত (-1);

	যদি (socksv == 5) {
		যদি (decode_addrport(host, port, (কাঠামো sockaddr *)&addr,
		    আকার(addr), 0, 1) == -1)
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

		নির্বাচন (addr.ss_family) {
		ক্ষেত্র 0:
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
			memcpy(buf + 5 + hlen, &serverport, আকার serverport);
			wlen = 7 + hlen;
			বিরতি;
		ক্ষেত্র AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, আকার in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, আকার in4->sin_port);
			wlen = 10;
			বিরতি;
		ক্ষেত্র AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, আকার in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    আকার in6->sin6_port);
			wlen = 22;
			বিরতি;
		পূর্বনির্ধারিত:
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
		নির্বাচন (buf[3]) {
		ক্ষেত্র SOCKS_IPV4:
			cnt = atomicio(পঠ, proxyfd, buf + 4, 6);
			যদি (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			বিরতি;
		ক্ষেত্র SOCKS_IPV6:
			cnt = atomicio(পঠ, proxyfd, buf + 4, 18);
			যদি (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			বিরতি;
		পূর্বনির্ধারিত:
			errx(1, "connection failed, unsupported address type");
		}
	} অন্যথা যদি (socksv == 4 || socksv == 44) {
		যদি (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (কাঠামো sockaddr *)&addr,
			    আকার(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, আকার in4->sin_port);
		যদি (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, আকার in4->sin_addr);
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
			    আকার(buf) - 9) >= আকার(buf) - 9)
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
		যদি (strchr(host, ':') != ফাঁকা) {
			r = snprintf(buf, আকার(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} অন্যথা {
			r = snprintf(buf, আকার(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		যদি (r == -1 || (আকার_t)r >= আকার(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		যদি (cnt != (আকার_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		যদি (authretry > 1) {
			অক্ষর resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, আকার(buf), "%s:%s",
			    proxyuser, proxypass);
			যদি (r == -1 || (আকার_t)r >= আকার(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    আকার(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, আকার(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			যদি (r == -1 || (আকার_t)r >= আকার(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			যদি ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (আকার_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		যদি ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_সারি(proxyfd, buf, আকার(buf));
		যদি (proxyuser != ফাঁকা &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			যদি (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			যাও again;
		} অন্যথা যদি (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		জন্য (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_সারি(proxyfd, buf, আকার(buf));
			যদি (*buf == '\0')
				বিরতি;
		}
		যদি (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} অন্যথা
		errx(1, "Unknown proxy protocol %d", socksv);

	ফেরত (proxyfd);
}

