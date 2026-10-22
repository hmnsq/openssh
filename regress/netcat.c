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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/time.h>
#شامل <sys/uio.h>
#شامل <sys/un.h>

#شامل <netinet/in.h>
#شامل <netinet/tcp.h>
#شامل <netinet/ip.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل "atomicio.h"

#شامل <poll.h>
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
	(اندازه(*(su)) - اندازه((su)->sun_path) + strlen((su)->sun_path))
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
صحیح	dflag;					/* detached, no stdin */
صحیح	Fflag;					/* fdpass sock to stdout */
unsigned صحیح iflag;				/* Interval Flag */
صحیح	kflag;					/* More than one connect */
صحیح	lflag;					/* Bind to local port */
صحیح	Nflag;					/* shutdown() network socket */
صحیح	nflag;					/* Don't do name look up */
نویسه   *Pflag;					/* Proxy username */
نویسه   *pflag;					/* Localport flag */
صحیح	rflag;					/* Random ports flag */
نویسه   *sflag;					/* Source Address */
صحیح	tflag;					/* Telnet Emulation */
صحیح	uflag;					/* UDP - Default to TCP */
صحیح	vflag;					/* Verbosity */
صحیح	xflag;					/* Socks proxy */
صحیح	zflag;					/* Port Scan Flag */
صحیح	Dflag;					/* sodebug */
صحیح	Iflag;					/* TCP receive buffer size */
صحیح	Oflag;					/* TCP send buffer size */
صحیح	Sflag;					/* TCP MD5 signature option */
صحیح	Tflag = -1;				/* IP Type of Service */
صحیح	rtableid = -1;

صحیح timeout = -1;
صحیح family = AF_UNSPEC;
نویسه *portlist[PORT_MAX+1];
نویسه *unix_dg_tmp_socket;

تهی	atelnet(صحیح, unsigned نویسه *, unsigned صحیح);
تهی	build_ports(نویسه *);
تهی	help(تهی);
صحیح	local_listen(نویسه *, نویسه *, ساختار addrinfo);
تهی	readwrite(صحیح);
تهی	fdpass(صحیح nfd) __attribute__((noreturn));
صحیح	remote_connect(ثابت نویسه *, ثابت نویسه *, ساختار addrinfo);
صحیح	timeout_connect(صحیح, ثابت ساختار sockaddr *, socklen_t);
صحیح	socks_connect(ثابت نویسه *, ثابت نویسه *, ساختار addrinfo,
	    ثابت نویسه *, ثابت نویسه *, ساختار addrinfo, صحیح, ثابت نویسه *);
صحیح	udptest(صحیح);
صحیح	unix_bind(نویسه *);
صحیح	unix_connect(نویسه *);
صحیح	unix_listen(نویسه *);
تهی	set_common_sockopts(صحیح, صحیح);
صحیح	map_tos(نویسه *, صحیح *);
تهی	report_connect(ثابت ساختار sockaddr *, socklen_t);
تهی	usage(صحیح);
ssize_t drainbuf(صحیح, unsigned نویسه *, size_t *);
ssize_t fillbuf(صحیح, unsigned نویسه *, size_t *);


صحیح
اصلی(صحیح argc, نویسه *argv[])
{
	صحیح ch, s, ret, socksv;
	نویسه *host, *uport;
	ساختار addrinfo hints;
	ساختار servent *sv;
	socklen_t len;
	ساختار sockaddr_storage cliaddr;
	نویسه *proxy = پوچ;
	ثابت نویسه *errstr, *proxyhost = "", *proxyport = پوچ;
	ساختار addrinfo proxyhints;
	نویسه unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = پوچ;
	uport = پوچ;
	sv = پوچ;

	سیگنال(SIGPIPE, SIG_IGN);

	وقتی ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		انتخاب (ch) {
		حالت '4':
			family = AF_INET;
			بشکن;
		حالت '6':
			family = AF_INET6;
			بشکن;
		حالت 'U':
			family = AF_UNIX;
			بشکن;
		حالت 'X':
			اگر (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			وگرنه اگر (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			وگرنه اگر (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			وگرنه اگر (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			وگرنه
				errx(1, "unsupported proxy protocol");
			بشکن;
		حالت 'd':
			dflag = 1;
			بشکن;
		حالت 'F':
			Fflag = 1;
			بشکن;
		حالت 'h':
			help();
			بشکن;
		حالت 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			اگر (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			بشکن;
		حالت 'k':
			kflag = 1;
			بشکن;
		حالت 'l':
			lflag = 1;
			بشکن;
		حالت 'N':
			Nflag = 1;
			بشکن;
		حالت 'n':
			nflag = 1;
			بشکن;
		حالت 'P':
			Pflag = optarg;
			بشکن;
		حالت 'p':
			pflag = optarg;
			بشکن;
		حالت 'r':
			rflag = 1;
			بشکن;
		حالت 's':
			sflag = optarg;
			بشکن;
		حالت 't':
			tflag = 1;
			بشکن;
		حالت 'u':
			uflag = 1;
			بشکن;
#ifdef SO_RTABLE
		حالت 'V':
			rtableid = (صحیح)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			اگر (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			بشکن;
#endif
		حالت 'v':
			vflag = 1;
			بشکن;
		حالت 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			اگر (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			بشکن;
		حالت 'x':
			xflag = 1;
			اگر ((proxy = strdup(optarg)) == پوچ)
				errx(1, "strdup");
			بشکن;
		حالت 'z':
			zflag = 1;
			بشکن;
		حالت 'D':
			Dflag = 1;
			بشکن;
		حالت 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			اگر (errstr != پوچ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			بشکن;
		حالت 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			اگر (errstr != پوچ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			بشکن;
		حالت 'S':
			Sflag = 1;
			بشکن;
		حالت 'T':
			errstr = پوچ;
			errno = 0;
			اگر (map_tos(optarg, &Tflag))
				بشکن;
			اگر (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (صحیح)strtol(optarg, پوچ, 16);
			وگرنه
				Tflag = (صحیح)strtonum(optarg, 0, 255,
				    &errstr);
			اگر (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			بشکن;
		پیشفرض:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	اگر (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = پوچ;
	} وگرنه اگر (argv[0] && !argv[1]) {
		اگر  (!lflag)
			usage(1);
		uport = argv[0];
		host = پوچ;
	} وگرنه اگر (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} وگرنه
		usage(1);

	اگر (lflag && sflag)
		errx(1, "cannot use -s and -l");
	اگر (lflag && pflag)
		errx(1, "cannot use -p and -l");
	اگر (lflag && zflag)
		errx(1, "cannot use -z and -l");
	اگر (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	اگر ((family == AF_UNIX) && uflag && !lflag) {
		اگر (sflag) {
			unix_dg_tmp_socket = sflag;
		} وگرنه {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			اگر (mktemp(unix_dg_tmp_socket_buf) == پوچ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	اگر (family != AF_UNIX) {
		memset(&hints, 0, اندازه(ساختار addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		اگر (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	اگر (xflag) {
		اگر (uflag)
			errx(1, "no proxy support for UDP mode");

		اگر (lflag)
			errx(1, "no proxy support for listen");

		اگر (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		اگر (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		اگر (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, اندازه(ساختار addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		اگر (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	اگر (lflag) {
		صحیح connfd;
		ret = 0;

		اگر (family == AF_UNIX) {
			اگر (uflag)
				s = unix_bind(host);
			وگرنه
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		برای (;;) {
			اگر (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			اگر (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			اگر (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			وگرنه اگر (uflag && !kflag) {
				صحیح rv, plen;
				نویسه buf[16384];
				ساختار sockaddr_storage z;

				len = اندازه(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (ساختار sockaddr *)&z, &len);
				اگر (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (ساختار sockaddr *)&z, len);
				اگر (rv < 0)
					err(1, "connect");

				اگر (vflag)
					report_connect((ساختار sockaddr *)&z, len);

				readwrite(s);
			} وگرنه {
				len = اندازه(cliaddr);
				connfd = accept(s, (ساختار sockaddr *)&cliaddr,
				    &len);
				اگر (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				اگر (vflag)
					report_connect((ساختار sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			اگر (family != AF_UNIX)
				close(s);
			وگرنه اگر (uflag) {
				اگر (connect(s, پوچ, 0) < 0)
					err(1, "connect");
			}

			اگر (!kflag)
				بشکن;
		}
	} وگرنه اگر (family == AF_UNIX) {
		ret = 0;

		اگر ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} وگرنه
			ret = 1;

		اگر (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} وگرنه {
		صحیح i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		برای (i = 0; portlist[i] != پوچ; i++) {
			اگر (s)
				close(s);

			اگر (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			وگرنه
				s = remote_connect(host, portlist[i], hints);

			اگر (s < 0)
				ادامه;

			ret = 0;
			اگر (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				اگر (uflag) {
					اگر (udptest(s) == -1) {
						ret = 1;
						ادامه;
					}
				}

				/* Don't look up port if -n. */
				اگر (nflag)
					sv = پوچ;
				وگرنه {
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
			اگر (Fflag)
				fdpass(s);
			وگرنه اگر (!zflag)
				readwrite(s);
		}
	}

	اگر (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
صحیح
unix_bind(نویسه *path)
{
	ساختار sockaddr_un sun_sa;
	صحیح s;

	/* Create unix domain socket. */
	اگر ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		بازگشت (-1);

	memset(&sun_sa, 0, اندازه(ساختار sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	اگر (strlcpy(sun_sa.sun_path, path, اندازه(sun_sa.sun_path)) >=
	    اندازه(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		بازگشت (-1);
	}

	اگر (bind(s, (ساختار sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		بازگشت (-1);
	}
	بازگشت (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
صحیح
unix_connect(نویسه *path)
{
	ساختار sockaddr_un sun_sa;
	صحیح s;

	اگر (uflag) {
		اگر ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			بازگشت (-1);
	} وگرنه {
		اگر ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			بازگشت (-1);
	}
	(تهی)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, اندازه(ساختار sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	اگر (strlcpy(sun_sa.sun_path, path, اندازه(sun_sa.sun_path)) >=
	    اندازه(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		بازگشت (-1);
	}
	اگر (connect(s, (ساختار sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		بازگشت (-1);
	}
	بازگشت (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
صحیح
unix_listen(نویسه *path)
{
	صحیح s;
	اگر ((s = unix_bind(path)) < 0)
		بازگشت (-1);

	اگر (listen(s, 5) < 0) {
		close(s);
		بازگشت (-1);
	}
	بازگشت (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
صحیح
remote_connect(ثابت نویسه *host, ثابت نویسه *port, ساختار addrinfo hints)
{
	ساختار addrinfo *res, *res0;
	صحیح s, error;
#اگر defined(SO_RTABLE) || defined(SO_BINDANY)
	صحیح on = 1;
#endif

	اگر ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	انجامبده {
		اگر ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ادامه;

#ifdef SO_RTABLE
		اگر (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, اندازه(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		اگر (sflag || pflag) {
			ساختار addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, اندازه(on));
#endif
			memset(&ahints, 0, اندازه(ساختار addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			اگر ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			اگر (bind(s, (ساختار sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		اگر (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			بشکن;
		وگرنه اگر (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} وقتی ((res0 = res0->ai_next) != پوچ);

	freeaddrinfo(res);

	بازگشت (s);
}

صحیح
timeout_connect(صحیح s, ثابت ساختار sockaddr *name, socklen_t namelen)
{
	ساختار pollfd pfd;
	socklen_t optlen;
	صحیح flags = 0, optval;
	صحیح ret;

	اگر (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		اگر (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	اگر ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		اگر ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = اندازه(optval);
			اگر ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} وگرنه اگر (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} وگرنه
			err(1, "poll failed");
	}

	اگر (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	بازگشت (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
صحیح
local_listen(نویسه *host, نویسه *port, ساختار addrinfo hints)
{
	ساختار addrinfo *res, *res0;
	صحیح s, ret, x = 1;
	صحیح error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	اگر (host == پوچ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	اگر ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	انجامبده {
		اگر ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			ادامه;

#ifdef SO_RTABLE
		اگر (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, اندازه(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, اندازه(x));
		اگر (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, اندازه(x));
		اگر (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		اگر (bind(s, (ساختار sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			بشکن;

		close(s);
		s = -1;
	} وقتی ((res0 = res0->ai_next) != پوچ);

	اگر (!uflag && s != -1) {
		اگر (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	بازگشت (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
تهی
readwrite(صحیح net_fd)
{
	ساختار pollfd pfd[4];
	صحیح stdin_fd = STDIN_FILENO;
	صحیح stdout_fd = STDOUT_FILENO;
	unsigned نویسه netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned نویسه stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	صحیح n, رقم_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	اگر (dflag)
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

	وقتی (1) {
		/* both inputs are gone, buffers are empty, we are done */
		اگر (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			بازگشت;
		}
		/* both outputs are gone, we can't continue */
		اگر (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			بازگشت;
		}
		/* listen and net in gone, queues empty, done */
		اگر (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			بازگشت;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		اگر (iflag)
			sleep(iflag);

		/* poll */
		رقم_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		اگر (رقم_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		اگر (رقم_fds == 0)
			بازگشت;

		/* treat socket error conditions */
		برای (n = 0; n < 4; n++) {
			اگر (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		اگر (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		اگر (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		اگر (pfd[POLL_NETOUT].revents & POLLHUP) {
			اگر (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		اگر (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		اگر (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		اگر (pfd[POLL_STDOUT].fd == -1) {
			اگر (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		اگر (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			اگر (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			اگر (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			اگر (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		اگر (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			اگر (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			اگر (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			اگر (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		اگر (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			اگر (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			اگر (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			اگر (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			اگر (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			اگر (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		اگر (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			اگر (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			اگر (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			اگر (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		اگر (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			اگر (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		اگر (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(صحیح fd, unsigned نویسه *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = اكتب(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	اگر (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	اگر (n <= 0)
		بازگشت n;
	/* adjust buffer */
	adjust = *bufpos - n;
	اگر (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	بازگشت n;
}


ssize_t
fillbuf(صحیح fd, unsigned نویسه *buf, size_t *bufpos)
{
	size_t رقم = BUFSIZE - *bufpos;
	ssize_t n;

	n = اقرأ(fd, buf + *bufpos, رقم);
	/* don't treat EAGAIN, EINTR as error */
	اگر (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	اگر (n <= 0)
		بازگشت n;
	*bufpos += n;
	بازگشت n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
تهی
fdpass(صحیح nfd)
{
#اگر defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	ساختار msghdr پیام;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	اجتماع {
		ساختار cmsghdr hdr;
		نویسه buf[CMSG_SPACE(اندازه(صحیح))];
	} cmsgbuf;
	ساختار cmsghdr *cmsg;
#endif
	ساختار iovec vec;
	نویسه ch = '\0';
	ساختار pollfd pfd;
	ssize_t r;

	memset(&پیام, 0, اندازه(پیام));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	پیام.پیام_accrights = (caddr_t)&nfd;
	پیام.پیام_accrightslen = اندازه(nfd);
#وگرنه
	memset(&cmsgbuf, 0, اندازه(cmsgbuf));
	پیام.msg_control = (caddr_t)&cmsgbuf.buf;
	پیام.msg_controllen = اندازه(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&پیام);
	cmsg->cmsg_len = CMSG_LEN(اندازه(صحیح));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(صحیح *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	پیام.msg_iov = &vec;
	پیام.msg_iovlen = 1;

	bzero(&pfd, اندازه(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	برای (;;) {
		r = sendmsg(STDOUT_FILENO, &پیام, 0);
		اگر (r == -1) {
			اگر (errno == EAGAIN || errno == EINTR) {
				اگر (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				ادامه;
			}
			err(1, "sendmsg");
		} وگرنه اگر (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		وگرنه
			بشکن;
	}
	exit(0);
#وگرنه
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
تهی
atelnet(صحیح nfd, unsigned نویسه *buf, unsigned صحیح size)
{
	unsigned نویسه *p, *end;
	unsigned نویسه obuf[4];

	اگر (size < 3)
		بازگشت;
	end = buf + size - 2;

	برای (p = buf; p < end; p++) {
		اگر (*p != IAC)
			ادامه;

		obuf[0] = IAC;
		p++;
		اگر ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		وگرنه اگر ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		وگرنه
			ادامه;

		p++;
		obuf[2] = *p;
		اگر (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
تهی
build_ports(نویسه *p)
{
	ثابت نویسه *errstr;
	نویسه *n;
	صحیح hi, lo, cp;
	صحیح x = 0;

	اگر ((n = strchr(p, '-')) != پوچ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		اگر (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		اگر (errstr)
			errx(1, "port number %s: %s", errstr, p);

		اگر (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		برای (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			اگر (portlist[x] == پوچ)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		اگر (rflag) {
			صحیح y;
			نویسه *c;

			برای (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} وگرنه {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		اگر (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		اگر (portlist[0] == پوچ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
صحیح
udptest(صحیح s)
{
	صحیح i, ret;

	برای (i = 0; i <= 3; i++) {
		اگر (اكتب(s, "X", 1) == 1)
			ret = 1;
		وگرنه
			ret = -1;
	}
	بازگشت (ret);
}

تهی
set_common_sockopts(صحیح s, صحیح af)
{
	صحیح x = 1;

#ifdef TCP_MD5SIG
	اگر (Sflag) {
		اگر (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, اندازه(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	اگر (Dflag) {
		اگر (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, اندازه(x)) == -1)
			err(1, "setsockopt");
	}
#اگر defined(IP_TOS) && defined(IPV6_TCLASS)
	اگر (Tflag != -1) {
		صحیح proto, option;

		اگر (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} وگرنه {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		اگر (setsockopt(s, proto, option, &Tflag, اندازه(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	اگر (Iflag) {
		اگر (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, اندازه(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	اگر (Oflag) {
		اگر (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, اندازه(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

صحیح
map_tos(نویسه *s, صحیح *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	ثابت ساختار toskeywords {
		ثابت نویسه	*keyword;
		صحیح		 val;
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
		{ پوچ, 		-1 },
	};

	برای (t = toskeywords; t->keyword != پوچ; t++) {
		اگر (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			بازگشت (1);
		}
	}
#endif

	بازگشت (0);
}

تهی
report_connect(ثابت ساختار sockaddr *sa, socklen_t salen)
{
	نویسه remote_host[NI_MAXHOST];
	نویسه remote_port[NI_MAXSERV];
	صحیح herr;
	صحیح flags = NI_NUMERICSERV;
	
	اگر (nflag)
		flags |= NI_NUMERICHOST;
	
	اگر ((herr = getnameinfo(sa, salen,
	    remote_host, اندازه(remote_host),
	    remote_port, اندازه(remote_port),
	    flags)) != 0) {
		اگر (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		وگرنه
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

تهی
help(تهی)
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
	\t-i secs\t	Delay interval برای سطرها sent, ports scanned\n\
	\t-k		Keep inbound sockets open برای multiple connects\n\
	\t-l		Listen mode, برای inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername برای proxy authentication\n\
	\t-p port\t	Specify local port برای remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout برای connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used برای scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

تهی
usage(صحیح ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	اگر (ret)
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

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <netdb.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <resolv.h>

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

صحیح	remote_connect(ثابت نویسه *, ثابت نویسه *, ساختار addrinfo);
صحیح	socks_connect(ثابت نویسه *, ثابت نویسه *, ساختار addrinfo,
	    ثابت نویسه *, ثابت نویسه *, ساختار addrinfo, صحیح,
	    ثابت نویسه *);

ایستا صحیح
decode_addrport(ثابت نویسه *h, ثابت نویسه *p, ساختار sockaddr *addr,
    socklen_t addrlen, صحیح v4only, صحیح numeric)
{
	صحیح r;
	ساختار addrinfo hints, *res;

	bzero(&hints, اندازه(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	اگر (r != 0) {
		اگر (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		بازگشت (-1);
	}
	اگر (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	بازگشت (0);
}

ایستا صحیح
proxy_read_سطر(صحیح fd, نویسه *buf, size_t bufsz)
{
	size_t off;

	برای(off = 0;;) {
		اگر (off >= bufsz)
			errx(1, "proxy read too long");
		اگر (atomicio(اقرأ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		اگر (buf[off] == '\r')
			ادامه;
		اگر (buf[off] == '\n') {
			buf[off] = '\0';
			بشکن;
		}
		off++;
	}
	بازگشت (off);
}

ایستا ثابت نویسه *
getproxypass(ثابت نویسه *proxyuser, ثابت نویسه *proxyhost)
{
	نویسه prompt[512];
	ایستا نویسه pw[256];

	snprintf(prompt, اندازه(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	اگر (readpassphrase(prompt, pw, اندازه(pw), RPP_REQUIRE_TTY) == پوچ)
		errx(1, "Unable to read proxy passphrase");
	بازگشت (pw);
}

صحیح
socks_connect(ثابت نویسه *host, ثابت نویسه *port,
    ساختار addrinfo hints __attribute__ ((__unused__)),
    ثابت نویسه *proxyhost, ثابت نویسه *proxyport, ساختار addrinfo proxyhints,
    صحیح socksv, ثابت نویسه *proxyuser)
{
	صحیح proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned نویسه buf[1024];
	size_t cnt;
	ساختار sockaddr_storage addr;
	ساختار sockaddr_in *in4 = (ساختار sockaddr_in *)&addr;
	ساختار sockaddr_in6 *in6 = (ساختار sockaddr_in6 *)&addr;
	in_port_t serverport;
	ثابت نویسه *proxypass = پوچ;

	اگر (proxyport == پوچ)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	اگر (decode_addrport("0.0.0.0", port, (ساختار sockaddr *)&addr,
	    اندازه(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	اگر (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	اگر (proxyfd < 0)
		بازگشت (-1);

	اگر (socksv == 5) {
		اگر (decode_addrport(host, port, (ساختار sockaddr *)&addr,
		    اندازه(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		اگر (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(اقرأ, proxyfd, buf, 2);
		اگر (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		اگر (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		انتخاب (addr.ss_family) {
		حالت 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			اگر (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, اندازه serverport);
			wlen = 7 + hlen;
			بشکن;
		حالت AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, اندازه in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, اندازه in4->sin_port);
			wlen = 10;
			بشکن;
		حالت AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, اندازه in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    اندازه in6->sin6_port);
			wlen = 22;
			بشکن;
		پیشفرض:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		اگر (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(اقرأ, proxyfd, buf, 4);
		اگر (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		اگر (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		انتخاب (buf[3]) {
		حالت SOCKS_IPV4:
			cnt = atomicio(اقرأ, proxyfd, buf + 4, 6);
			اگر (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			بشکن;
		حالت SOCKS_IPV6:
			cnt = atomicio(اقرأ, proxyfd, buf + 4, 18);
			اگر (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			بشکن;
		پیشفرض:
			errx(1, "connection failed, unsupported address type");
		}
	} وگرنه اگر (socksv == 4 || socksv == 44) {
		اگر (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (ساختار sockaddr *)&addr,
			    اندازه(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, اندازه in4->sin_port);
		اگر (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, اندازه in4->sin_addr);
		} وگرنه {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		اگر (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			اگر (strlcpy(buf + 9, host,
			    اندازه(buf) - 9) >= اندازه(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		اگر (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(اقرأ, proxyfd, buf, 8);
		اگر (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		اگر (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} وگرنه اگر (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		اگر (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		اگر (strchr(host, ':') != پوچ) {
			r = snprintf(buf, اندازه(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} وگرنه {
			r = snprintf(buf, اندازه(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		اگر (r == -1 || (size_t)r >= اندازه(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		اگر (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		اگر (authretry > 1) {
			نویسه resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, اندازه(buf), "%s:%s",
			    proxyuser, proxypass);
			اگر (r == -1 || (size_t)r >= اندازه(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    اندازه(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, اندازه(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			اگر (r == -1 || (size_t)r >= اندازه(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			اگر ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		اگر ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_سطر(proxyfd, buf, اندازه(buf));
		اگر (proxyuser != پوچ &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			اگر (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			برو again;
		} وگرنه اگر (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		برای (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_سطر(proxyfd, buf, اندازه(buf));
			اگر (*buf == '\0')
				بشکن;
		}
		اگر (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} وگرنه
		errx(1, "Unknown proxy protocol %d", socksv);

	بازگشت (proxyfd);
}

