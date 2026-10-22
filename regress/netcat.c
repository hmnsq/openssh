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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/time.h>
#ضمن <sys/uio.h>
#ضمن <sys/un.h>

#ضمن <netinet/in.h>
#ضمن <netinet/tcp.h>
#ضمن <netinet/ip.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن "atomicio.h"

#ضمن <poll.h>
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
	(حجم(*(su)) - حجم((su)->sun_path) + strlen((su)->sun_path))
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
صحيح	dflag;					/* detached, no stdin */
صحيح	Fflag;					/* fdpass sock to stdout */
unsigned صحيح iflag;				/* Interval Flag */
صحيح	kflag;					/* More than one connect */
صحيح	lflag;					/* Bind to local port */
صحيح	Nflag;					/* shutdown() network socket */
صحيح	nflag;					/* Don't do name look up */
حرف   *Pflag;					/* Proxy username */
حرف   *pflag;					/* Localport flag */
صحيح	rflag;					/* Random ports flag */
حرف   *sflag;					/* Source Address */
صحيح	tflag;					/* Telnet Emulation */
صحيح	uflag;					/* UDP - Default to TCP */
صحيح	vflag;					/* Verbosity */
صحيح	xflag;					/* Socks proxy */
صحيح	zflag;					/* Port Scan Flag */
صحيح	Dflag;					/* sodebug */
صحيح	Iflag;					/* TCP receive buffer size */
صحيح	Oflag;					/* TCP send buffer size */
صحيح	Sflag;					/* TCP MD5 signature option */
صحيح	Tflag = -1;				/* IP Type of Service */
صحيح	rtableid = -1;

صحيح timeout = -1;
صحيح family = AF_UNSPEC;
حرف *portlist[PORT_MAX+1];
حرف *unix_dg_tmp_socket;

فراغ	atelnet(صحيح, unsigned حرف *, unsigned صحيح);
فراغ	build_ports(حرف *);
فراغ	help(فراغ);
صحيح	local_listen(حرف *, حرف *, بنية addrinfo);
فراغ	readwrite(صحيح);
فراغ	fdpass(صحيح nfd) __attribute__((noreturn));
صحيح	remote_connect(ثابت حرف *, ثابت حرف *, بنية addrinfo);
صحيح	timeout_connect(صحيح, ثابت بنية sockaddr *, socklen_t);
صحيح	socks_connect(ثابت حرف *, ثابت حرف *, بنية addrinfo,
	    ثابت حرف *, ثابت حرف *, بنية addrinfo, صحيح, ثابت حرف *);
صحيح	udptest(صحيح);
صحيح	unix_bind(حرف *);
صحيح	unix_connect(حرف *);
صحيح	unix_listen(حرف *);
فراغ	set_common_sockopts(صحيح, صحيح);
صحيح	map_tos(حرف *, صحيح *);
فراغ	report_connect(ثابت بنية sockaddr *, socklen_t);
فراغ	usage(صحيح);
ssize_t drainbuf(صحيح, unsigned حرف *, size_t *);
ssize_t fillbuf(صحيح, unsigned حرف *, size_t *);


صحيح
main(صحيح argc, حرف *argv[])
{
	صحيح ch, s, ret, socksv;
	حرف *host, *uport;
	بنية addrinfo hints;
	بنية servent *sv;
	socklen_t len;
	بنية sockaddr_storage cliaddr;
	حرف *proxy = عدم;
	ثابت حرف *errstr, *proxyhost = "", *proxyport = عدم;
	بنية addrinfo proxyhints;
	حرف unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = عدم;
	uport = عدم;
	sv = عدم;

	إشارة(SIGPIPE, SIG_IGN);

	כלעוד ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		بدل (ch) {
		حالة '4':
			family = AF_INET;
			اكسر;
		حالة '6':
			family = AF_INET6;
			اكسر;
		حالة 'U':
			family = AF_UNIX;
			اكسر;
		حالة 'X':
			אם (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			אחרת אם (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			אחרת אם (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			אחרת אם (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			אחרת
				errx(1, "unsupported proxy protocol");
			اكسر;
		حالة 'd':
			dflag = 1;
			اكسر;
		حالة 'F':
			Fflag = 1;
			اكسر;
		حالة 'h':
			help();
			اكسر;
		حالة 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			אם (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			اكسر;
		حالة 'k':
			kflag = 1;
			اكسر;
		حالة 'l':
			lflag = 1;
			اكسر;
		حالة 'N':
			Nflag = 1;
			اكسر;
		حالة 'n':
			nflag = 1;
			اكسر;
		حالة 'P':
			Pflag = optarg;
			اكسر;
		حالة 'p':
			pflag = optarg;
			اكسر;
		حالة 'r':
			rflag = 1;
			اكسر;
		حالة 's':
			sflag = optarg;
			اكسر;
		حالة 't':
			tflag = 1;
			اكسر;
		حالة 'u':
			uflag = 1;
			اكسر;
#ifdef SO_RTABLE
		حالة 'V':
			rtableid = (صحيح)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			אם (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			اكسر;
#endif
		حالة 'v':
			vflag = 1;
			اكسر;
		حالة 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			אם (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			اكسر;
		حالة 'x':
			xflag = 1;
			אם ((proxy = strdup(optarg)) == عدم)
				errx(1, "strdup");
			اكسر;
		حالة 'z':
			zflag = 1;
			اكسر;
		حالة 'D':
			Dflag = 1;
			اكسر;
		حالة 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			אם (errstr != عدم)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			اكسر;
		حالة 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			אם (errstr != عدم)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			اكسر;
		حالة 'S':
			Sflag = 1;
			اكسر;
		حالة 'T':
			errstr = عدم;
			errno = 0;
			אם (map_tos(optarg, &Tflag))
				اكسر;
			אם (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (صحيح)strtol(optarg, عدم, 16);
			אחרת
				Tflag = (صحيح)strtonum(optarg, 0, 255,
				    &errstr);
			אם (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			اكسر;
		افتراضي:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	אם (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = عدم;
	} אחרת אם (argv[0] && !argv[1]) {
		אם  (!lflag)
			usage(1);
		uport = argv[0];
		host = عدم;
	} אחרת אם (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} אחרת
		usage(1);

	אם (lflag && sflag)
		errx(1, "cannot use -s and -l");
	אם (lflag && pflag)
		errx(1, "cannot use -p and -l");
	אם (lflag && zflag)
		errx(1, "cannot use -z and -l");
	אם (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	אם ((family == AF_UNIX) && uflag && !lflag) {
		אם (sflag) {
			unix_dg_tmp_socket = sflag;
		} אחרת {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			אם (mktemp(unix_dg_tmp_socket_buf) == عدم)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	אם (family != AF_UNIX) {
		memset(&hints, 0, حجم(بنية addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		אם (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	אם (xflag) {
		אם (uflag)
			errx(1, "no proxy support for UDP mode");

		אם (lflag)
			errx(1, "no proxy support for listen");

		אם (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		אם (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		אם (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, حجم(بنية addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		אם (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	אם (lflag) {
		صحيح connfd;
		ret = 0;

		אם (family == AF_UNIX) {
			אם (uflag)
				s = unix_bind(host);
			אחרת
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		עבור (;;) {
			אם (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			אם (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			אם (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			אחרת אם (uflag && !kflag) {
				صحيح rv, plen;
				حرف buf[16384];
				بنية sockaddr_storage z;

				len = حجم(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (بنية sockaddr *)&z, &len);
				אם (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (بنية sockaddr *)&z, len);
				אם (rv < 0)
					err(1, "connect");

				אם (vflag)
					report_connect((بنية sockaddr *)&z, len);

				readwrite(s);
			} אחרת {
				len = حجم(cliaddr);
				connfd = accept(s, (بنية sockaddr *)&cliaddr,
				    &len);
				אם (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				אם (vflag)
					report_connect((بنية sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			אם (family != AF_UNIX)
				close(s);
			אחרת אם (uflag) {
				אם (connect(s, عدم, 0) < 0)
					err(1, "connect");
			}

			אם (!kflag)
				اكسر;
		}
	} אחרת אם (family == AF_UNIX) {
		ret = 0;

		אם ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} אחרת
			ret = 1;

		אם (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} אחרת {
		صحيح i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		עבור (i = 0; portlist[i] != عدم; i++) {
			אם (s)
				close(s);

			אם (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			אחרת
				s = remote_connect(host, portlist[i], hints);

			אם (s < 0)
				استمر;

			ret = 0;
			אם (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				אם (uflag) {
					אם (udptest(s) == -1) {
						ret = 1;
						استمر;
					}
				}

				/* Don't look up port if -n. */
				אם (nflag)
					sv = عدم;
				אחרת {
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
			אם (Fflag)
				fdpass(s);
			אחרת אם (!zflag)
				readwrite(s);
		}
	}

	אם (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
صحيح
unix_bind(حرف *path)
{
	بنية sockaddr_un sun_sa;
	صحيح s;

	/* Create unix domain socket. */
	אם ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		החזר (-1);

	memset(&sun_sa, 0, حجم(بنية sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	אם (strlcpy(sun_sa.sun_path, path, حجم(sun_sa.sun_path)) >=
	    حجم(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		החזר (-1);
	}

	אם (bind(s, (بنية sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		החזר (-1);
	}
	החזר (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
صحيح
unix_connect(حرف *path)
{
	بنية sockaddr_un sun_sa;
	صحيح s;

	אם (uflag) {
		אם ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			החזר (-1);
	} אחרת {
		אם ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			החזר (-1);
	}
	(فراغ)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, حجم(بنية sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	אם (strlcpy(sun_sa.sun_path, path, حجم(sun_sa.sun_path)) >=
	    حجم(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		החזר (-1);
	}
	אם (connect(s, (بنية sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		החזר (-1);
	}
	החזר (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
صحيح
unix_listen(حرف *path)
{
	صحيح s;
	אם ((s = unix_bind(path)) < 0)
		החזר (-1);

	אם (listen(s, 5) < 0) {
		close(s);
		החזר (-1);
	}
	החזר (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
صحيح
remote_connect(ثابت حرف *host, ثابت حرف *port, بنية addrinfo hints)
{
	بنية addrinfo *res, *res0;
	صحيح s, error;
#אם defined(SO_RTABLE) || defined(SO_BINDANY)
	صحيح on = 1;
#endif

	אם ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	עשה {
		אם ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			استمر;

#ifdef SO_RTABLE
		אם (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, حجم(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		אם (sflag || pflag) {
			بنية addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, حجم(on));
#endif
			memset(&ahints, 0, حجم(بنية addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			אם ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			אם (bind(s, (بنية sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		אם (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			اكسر;
		אחרת אם (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} כלעוד ((res0 = res0->ai_next) != عدم);

	freeaddrinfo(res);

	החזר (s);
}

صحيح
timeout_connect(صحيح s, ثابت بنية sockaddr *name, socklen_t namelen)
{
	بنية pollfd pfd;
	socklen_t optlen;
	صحيح flags = 0, optval;
	صحيح ret;

	אם (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		אם (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	אם ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		אם ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = حجم(optval);
			אם ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} אחרת אם (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} אחרת
			err(1, "poll failed");
	}

	אם (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	החזר (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
صحيح
local_listen(حرف *host, حرف *port, بنية addrinfo hints)
{
	بنية addrinfo *res, *res0;
	صحيح s, ret, x = 1;
	صحيح error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	אם (host == عدم && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	אם ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	עשה {
		אם ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			استمر;

#ifdef SO_RTABLE
		אם (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, حجم(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, حجم(x));
		אם (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, حجم(x));
		אם (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		אם (bind(s, (بنية sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			اكسر;

		close(s);
		s = -1;
	} כלעוד ((res0 = res0->ai_next) != عدم);

	אם (!uflag && s != -1) {
		אם (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	החזר (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
فراغ
readwrite(صحيح net_fd)
{
	بنية pollfd pfd[4];
	صحيح stdin_fd = STDIN_FILENO;
	صحيح stdout_fd = STDOUT_FILENO;
	unsigned حرف netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned حرف stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	صحيح n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	אם (dflag)
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

	כלעוד (1) {
		/* both inputs are gone, buffers are empty, we are done */
		אם (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			החזר;
		}
		/* both outputs are gone, we can't continue */
		אם (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			החזר;
		}
		/* listen and net in gone, queues empty, done */
		אם (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			החזר;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		אם (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		אם (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		אם (num_fds == 0)
			החזר;

		/* treat socket error conditions */
		עבור (n = 0; n < 4; n++) {
			אם (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		אם (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		אם (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		אם (pfd[POLL_NETOUT].revents & POLLHUP) {
			אם (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		אם (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		אם (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		אם (pfd[POLL_STDOUT].fd == -1) {
			אם (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		אם (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			אם (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			אם (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			אם (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		אם (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			אם (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			אם (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			אם (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		אם (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			אם (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			אם (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			אם (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			אם (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			אם (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		אם (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			אם (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			אם (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			אם (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		אם (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			אם (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		אם (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(صحيح fd, unsigned حرف *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = اكتب(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	אם (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	אם (n <= 0)
		החזר n;
	/* adjust buffer */
	adjust = *bufpos - n;
	אם (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	החזר n;
}


ssize_t
fillbuf(صحيح fd, unsigned حرف *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = اقرأ(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	אם (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	אם (n <= 0)
		החזר n;
	*bufpos += n;
	החזר n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
فراغ
fdpass(صحيح nfd)
{
#אם defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	بنية msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اتحاد {
		بنية cmsghdr hdr;
		حرف buf[CMSG_SPACE(حجم(صحيح))];
	} cmsgbuf;
	بنية cmsghdr *cmsg;
#endif
	بنية iovec vec;
	حرف ch = '\0';
	بنية pollfd pfd;
	ssize_t r;

	memset(&msg, 0, حجم(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&nfd;
	msg.msg_accrightslen = حجم(nfd);
#אחרת
	memset(&cmsgbuf, 0, حجم(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = حجم(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(حجم(صحيح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحيح *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, حجم(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	עבור (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		אם (r == -1) {
			אם (errno == EAGAIN || errno == EINTR) {
				אם (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				استمر;
			}
			err(1, "sendmsg");
		} אחרת אם (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		אחרת
			اكسر;
	}
	exit(0);
#אחרת
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
فراغ
atelnet(صحيح nfd, unsigned حرف *buf, unsigned صحيح size)
{
	unsigned حرف *p, *end;
	unsigned حرف obuf[4];

	אם (size < 3)
		החזר;
	end = buf + size - 2;

	עבור (p = buf; p < end; p++) {
		אם (*p != IAC)
			استمر;

		obuf[0] = IAC;
		p++;
		אם ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		אחרת אם ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		אחרת
			استمر;

		p++;
		obuf[2] = *p;
		אם (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
فراغ
build_ports(حرف *p)
{
	ثابت حرف *errstr;
	حرف *n;
	صحيح hi, lo, cp;
	صحيح x = 0;

	אם ((n = strchr(p, '-')) != عدم) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		אם (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		אם (errstr)
			errx(1, "port number %s: %s", errstr, p);

		אם (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		עבור (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			אם (portlist[x] == عدم)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		אם (rflag) {
			صحيح y;
			حرف *c;

			עבור (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} אחרת {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		אם (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		אם (portlist[0] == عدم)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
صحيح
udptest(صحيح s)
{
	صحيح i, ret;

	עבור (i = 0; i <= 3; i++) {
		אם (اكتب(s, "X", 1) == 1)
			ret = 1;
		אחרת
			ret = -1;
	}
	החזר (ret);
}

فراغ
set_common_sockopts(صحيح s, صحيح af)
{
	صحيح x = 1;

#ifdef TCP_MD5SIG
	אם (Sflag) {
		אם (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, حجم(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	אם (Dflag) {
		אם (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, حجم(x)) == -1)
			err(1, "setsockopt");
	}
#אם defined(IP_TOS) && defined(IPV6_TCLASS)
	אם (Tflag != -1) {
		صحيح proto, option;

		אם (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} אחרת {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		אם (setsockopt(s, proto, option, &Tflag, حجم(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	אם (Iflag) {
		אם (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, حجم(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	אם (Oflag) {
		אם (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, حجم(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

صحيح
map_tos(حرف *s, صحيح *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ثابت بنية toskeywords {
		ثابت حرف	*keyword;
		صحيح		 val;
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
		{ عدم, 		-1 },
	};

	עבור (t = toskeywords; t->keyword != عدم; t++) {
		אם (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			החזר (1);
		}
	}
#endif

	החזר (0);
}

فراغ
report_connect(ثابت بنية sockaddr *sa, socklen_t salen)
{
	حرف remote_host[NI_MAXHOST];
	حرف remote_port[NI_MAXSERV];
	صحيح herr;
	صحيح flags = NI_NUMERICSERV;
	
	אם (nflag)
		flags |= NI_NUMERICHOST;
	
	אם ((herr = getnameinfo(sa, salen,
	    remote_host, حجم(remote_host),
	    remote_port, حجم(remote_port),
	    flags)) != 0) {
		אם (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		אחרת
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

فراغ
help(فراغ)
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
	\t-i secs\t	Delay interval עבור lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open עבור multiple connects\n\
	\t-l		Listen mode, עבור inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername עבור proxy authentication\n\
	\t-p port\t	Specify local port עבור remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout עבור connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used עבור scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

فراغ
usage(صحيح ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	אם (ret)
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

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <netdb.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <resolv.h>

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

صحيح	remote_connect(ثابت حرف *, ثابت حرف *, بنية addrinfo);
صحيح	socks_connect(ثابت حرف *, ثابت حرف *, بنية addrinfo,
	    ثابت حرف *, ثابت حرف *, بنية addrinfo, صحيح,
	    ثابت حرف *);

ساكن صحيح
decode_addrport(ثابت حرف *h, ثابت حرف *p, بنية sockaddr *addr,
    socklen_t addrlen, صحيح v4only, صحيح numeric)
{
	صحيح r;
	بنية addrinfo hints, *res;

	bzero(&hints, حجم(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	אם (r != 0) {
		אם (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		החזר (-1);
	}
	אם (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	החזר (0);
}

ساكن صحيح
proxy_read_line(صحيح fd, حرف *buf, size_t bufsz)
{
	size_t off;

	עבור(off = 0;;) {
		אם (off >= bufsz)
			errx(1, "proxy read too long");
		אם (atomicio(اقرأ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		אם (buf[off] == '\r')
			استمر;
		אם (buf[off] == '\n') {
			buf[off] = '\0';
			اكسر;
		}
		off++;
	}
	החזר (off);
}

ساكن ثابت حرف *
getproxypass(ثابت حرف *proxyuser, ثابت حرف *proxyhost)
{
	حرف prompt[512];
	ساكن حرف pw[256];

	snprintf(prompt, حجم(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	אם (readpassphrase(prompt, pw, حجم(pw), RPP_REQUIRE_TTY) == عدم)
		errx(1, "Unable to read proxy passphrase");
	החזר (pw);
}

صحيح
socks_connect(ثابت حرف *host, ثابت حرف *port,
    بنية addrinfo hints __attribute__ ((__unused__)),
    ثابت حرف *proxyhost, ثابت حرف *proxyport, بنية addrinfo proxyhints,
    صحيح socksv, ثابت حرف *proxyuser)
{
	صحيح proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned حرف buf[1024];
	size_t cnt;
	بنية sockaddr_storage addr;
	بنية sockaddr_in *in4 = (بنية sockaddr_in *)&addr;
	بنية sockaddr_in6 *in6 = (بنية sockaddr_in6 *)&addr;
	in_port_t serverport;
	ثابت حرف *proxypass = عدم;

	אם (proxyport == عدم)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	אם (decode_addrport("0.0.0.0", port, (بنية sockaddr *)&addr,
	    حجم(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	אם (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	אם (proxyfd < 0)
		החזר (-1);

	אם (socksv == 5) {
		אם (decode_addrport(host, port, (بنية sockaddr *)&addr,
		    حجم(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		אם (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(اقرأ, proxyfd, buf, 2);
		אם (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		אם (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		بدل (addr.ss_family) {
		حالة 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			אם (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, حجم serverport);
			wlen = 7 + hlen;
			اكسر;
		حالة AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, حجم in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, حجم in4->sin_port);
			wlen = 10;
			اكسر;
		حالة AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, حجم in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    حجم in6->sin6_port);
			wlen = 22;
			اكسر;
		افتراضي:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		אם (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(اقرأ, proxyfd, buf, 4);
		אם (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		אם (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		بدل (buf[3]) {
		حالة SOCKS_IPV4:
			cnt = atomicio(اقرأ, proxyfd, buf + 4, 6);
			אם (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			اكسر;
		حالة SOCKS_IPV6:
			cnt = atomicio(اقرأ, proxyfd, buf + 4, 18);
			אם (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			اكسر;
		افتراضي:
			errx(1, "connection failed, unsupported address type");
		}
	} אחרת אם (socksv == 4 || socksv == 44) {
		אם (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (بنية sockaddr *)&addr,
			    حجم(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, حجم in4->sin_port);
		אם (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, حجم in4->sin_addr);
		} אחרת {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		אם (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			אם (strlcpy(buf + 9, host,
			    حجم(buf) - 9) >= حجم(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		אם (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(اقرأ, proxyfd, buf, 8);
		אם (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		אם (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} אחרת אם (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		אם (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		אם (strchr(host, ':') != عدم) {
			r = snprintf(buf, حجم(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} אחרת {
			r = snprintf(buf, حجم(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		אם (r == -1 || (size_t)r >= حجم(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		אם (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		אם (authretry > 1) {
			حرف resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, حجم(buf), "%s:%s",
			    proxyuser, proxypass);
			אם (r == -1 || (size_t)r >= حجم(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    حجم(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, حجم(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			אם (r == -1 || (size_t)r >= حجم(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			אם ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		אם ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, حجم(buf));
		אם (proxyuser != عدم &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			אם (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			اذهب again;
		} אחרת אם (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		עבור (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, حجم(buf));
			אם (*buf == '\0')
				اكسر;
		}
		אם (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} אחרת
		errx(1, "Unknown proxy protocol %d", socksv);

	החזר (proxyfd);
}

