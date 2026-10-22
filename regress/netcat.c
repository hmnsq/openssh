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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "atomicio.h"

#include <poll.h>
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
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
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
ціле	dflag;					/* detached, no stdin */
ціле	Fflag;					/* fdpass sock to stdout */
unsigned ціле iflag;				/* Interval Flag */
ціле	kflag;					/* More than one connect */
ціле	lflag;					/* Bind to local port */
ціле	Nflag;					/* shutdown() network socket */
ціле	nflag;					/* Don't do name look up */
char   *Pflag;					/* Proxy username */
char   *pflag;					/* Localport flag */
ціле	rflag;					/* Random ports flag */
char   *sflag;					/* Source Address */
ціле	tflag;					/* Telnet Emulation */
ціле	uflag;					/* UDP - Default to TCP */
ціле	vflag;					/* Verbosity */
ціле	xflag;					/* Socks proxy */
ціле	zflag;					/* Port Scan Flag */
ціле	Dflag;					/* sodebug */
ціле	Iflag;					/* TCP receive buffer size */
ціле	Oflag;					/* TCP send buffer size */
ціле	Sflag;					/* TCP MD5 signature option */
ціле	Tflag = -1;				/* IP Type of Service */
ціле	rtableid = -1;

ціле timeout = -1;
ціле family = AF_UNSPEC;
char *portlist[PORT_MAX+1];
char *unix_dg_tmp_socket;

void	atelnet(ціле, unsigned char *, unsigned ціле);
void	build_ports(char *);
void	help(void);
ціле	local_listen(char *, char *, struct addrinfo);
void	readwrite(ціле);
void	fdpass(ціле nfd) __attribute__((noreturn));
ціле	remote_connect(const char *, const char *, struct addrinfo);
ціле	timeout_connect(ціле, const struct sockaddr *, socklen_t);
ціле	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, ціле, const char *);
ціле	udptest(ціле);
ціле	unix_bind(char *);
ціле	unix_connect(char *);
ціле	unix_listen(char *);
void	set_common_sockopts(ціле, ціле);
ціле	map_tos(char *, ціле *);
void	report_connect(const struct sockaddr *, socklen_t);
void	usage(ціле);
ssize_t drainbuf(ціле, unsigned char *, size_t *);
ssize_t fillbuf(ціле, unsigned char *, size_t *);


ціле
main(ціле argc, char *argv[])
{
	ціле ch, s, ret, socksv;
	char *host, *uport;
	struct addrinfo hints;
	struct servent *sv;
	socklen_t len;
	struct sockaddr_storage cliaddr;
	char *proxy = NULL;
	const char *errstr, *proxyhost = "", *proxyport = NULL;
	struct addrinfo proxyhints;
	char unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = NULL;
	uport = NULL;
	sv = NULL;

	signal(SIGPIPE, SIG_IGN);

	поки ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'U':
			family = AF_UNIX;
			break;
		case 'X':
			якщо (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			інакше якщо (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			інакше якщо (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			інакше якщо (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			інакше
				errx(1, "unsupported proxy protocol");
			break;
		case 'd':
			dflag = 1;
			break;
		case 'F':
			Fflag = 1;
			break;
		case 'h':
			help();
			break;
		case 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			якщо (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			break;
		case 'k':
			kflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'P':
			Pflag = optarg;
			break;
		case 'p':
			pflag = optarg;
			break;
		case 'r':
			rflag = 1;
			break;
		case 's':
			sflag = optarg;
			break;
		case 't':
			tflag = 1;
			break;
		case 'u':
			uflag = 1;
			break;
#ifdef SO_RTABLE
		case 'V':
			rtableid = (ціле)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			якщо (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			break;
#endif
		case 'v':
			vflag = 1;
			break;
		case 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			якщо (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			break;
		case 'x':
			xflag = 1;
			якщо ((proxy = strdup(optarg)) == NULL)
				errx(1, "strdup");
			break;
		case 'z':
			zflag = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		case 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			якщо (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			break;
		case 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			якщо (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			break;
		case 'S':
			Sflag = 1;
			break;
		case 'T':
			errstr = NULL;
			errno = 0;
			якщо (map_tos(optarg, &Tflag))
				break;
			якщо (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ціле)strtol(optarg, NULL, 16);
			інакше
				Tflag = (ціле)strtonum(optarg, 0, 255,
				    &errstr);
			якщо (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	якщо (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = NULL;
	} інакше якщо (argv[0] && !argv[1]) {
		якщо  (!lflag)
			usage(1);
		uport = argv[0];
		host = NULL;
	} інакше якщо (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} інакше
		usage(1);

	якщо (lflag && sflag)
		errx(1, "cannot use -s and -l");
	якщо (lflag && pflag)
		errx(1, "cannot use -p and -l");
	якщо (lflag && zflag)
		errx(1, "cannot use -z and -l");
	якщо (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	якщо ((family == AF_UNIX) && uflag && !lflag) {
		якщо (sflag) {
			unix_dg_tmp_socket = sflag;
		} інакше {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			якщо (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	якщо (family != AF_UNIX) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		якщо (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	якщо (xflag) {
		якщо (uflag)
			errx(1, "no proxy support for UDP mode");

		якщо (lflag)
			errx(1, "no proxy support for listen");

		якщо (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		якщо (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		якщо (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, sizeof(struct addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		якщо (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	якщо (lflag) {
		ціле connfd;
		ret = 0;

		якщо (family == AF_UNIX) {
			якщо (uflag)
				s = unix_bind(host);
			інакше
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		для (;;) {
			якщо (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			якщо (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			якщо (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			інакше якщо (uflag && !kflag) {
				ціле rv, plen;
				char buf[16384];
				struct sockaddr_storage z;

				len = sizeof(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (struct sockaddr *)&z, &len);
				якщо (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (struct sockaddr *)&z, len);
				якщо (rv < 0)
					err(1, "connect");

				якщо (vflag)
					report_connect((struct sockaddr *)&z, len);

				readwrite(s);
			} інакше {
				len = sizeof(cliaddr);
				connfd = accept(s, (struct sockaddr *)&cliaddr,
				    &len);
				якщо (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				якщо (vflag)
					report_connect((struct sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			якщо (family != AF_UNIX)
				close(s);
			інакше якщо (uflag) {
				якщо (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}

			якщо (!kflag)
				break;
		}
	} інакше якщо (family == AF_UNIX) {
		ret = 0;

		якщо ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} інакше
			ret = 1;

		якщо (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} інакше {
		ціле i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		для (i = 0; portlist[i] != NULL; i++) {
			якщо (s)
				close(s);

			якщо (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			інакше
				s = remote_connect(host, portlist[i], hints);

			якщо (s < 0)
				continue;

			ret = 0;
			якщо (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				якщо (uflag) {
					якщо (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				/* Don't look up port if -n. */
				якщо (nflag)
					sv = NULL;
				інакше {
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
			якщо (Fflag)
				fdpass(s);
			інакше якщо (!zflag)
				readwrite(s);
		}
	}

	якщо (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ціле
unix_bind(char *path)
{
	struct sockaddr_un sun_sa;
	ціле s;

	/* Create unix domain socket. */
	якщо ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		повернути (-1);

	memset(&sun_sa, 0, sizeof(struct sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	якщо (strlcpy(sun_sa.sun_path, path, sizeof(sun_sa.sun_path)) >=
	    sizeof(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		повернути (-1);
	}

	якщо (bind(s, (struct sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		повернути (-1);
	}
	повернути (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ціле
unix_connect(char *path)
{
	struct sockaddr_un sun_sa;
	ціле s;

	якщо (uflag) {
		якщо ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			повернути (-1);
	} інакше {
		якщо ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			повернути (-1);
	}
	(void)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, sizeof(struct sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	якщо (strlcpy(sun_sa.sun_path, path, sizeof(sun_sa.sun_path)) >=
	    sizeof(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		повернути (-1);
	}
	якщо (connect(s, (struct sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		повернути (-1);
	}
	повернути (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ціле
unix_listen(char *path)
{
	ціле s;
	якщо ((s = unix_bind(path)) < 0)
		повернути (-1);

	якщо (listen(s, 5) < 0) {
		close(s);
		повернути (-1);
	}
	повернути (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ціле
remote_connect(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	ціле s, error;
#якщо defined(SO_RTABLE) || defined(SO_BINDANY)
	ціле on = 1;
#endif

	якщо ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		якщо ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		якщо (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		якщо (sflag || pflag) {
			struct addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, sizeof(on));
#endif
			memset(&ahints, 0, sizeof(struct addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			якщо ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			якщо (bind(s, (struct sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		якщо (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			break;
		інакше якщо (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} поки ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	повернути (s);
}

ціле
timeout_connect(ціле s, const struct sockaddr *name, socklen_t namelen)
{
	struct pollfd pfd;
	socklen_t optlen;
	ціле flags = 0, optval;
	ціле ret;

	якщо (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		якщо (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	якщо ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		якщо ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = sizeof(optval);
			якщо ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} інакше якщо (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} інакше
			err(1, "poll failed");
	}

	якщо (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	повернути (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ціле
local_listen(char *host, char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	ціле s, ret, x = 1;
	ціле error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	якщо (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	якщо ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		якщо ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		якщо (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
		якщо (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x));
		якщо (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		якщо (bind(s, (struct sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			break;

		close(s);
		s = -1;
	} поки ((res0 = res0->ai_next) != NULL);

	якщо (!uflag && s != -1) {
		якщо (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	повернути (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(ціле net_fd)
{
	struct pollfd pfd[4];
	ціле stdin_fd = STDIN_FILENO;
	ціле stdout_fd = STDOUT_FILENO;
	unsigned char netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned char stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	ціле n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	якщо (dflag)
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

	поки (1) {
		/* both inputs are gone, buffers are empty, we are done */
		якщо (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			повернути;
		}
		/* both outputs are gone, we can't continue */
		якщо (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			повернути;
		}
		/* listen and net in gone, queues empty, done */
		якщо (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			повернути;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		якщо (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		якщо (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		якщо (num_fds == 0)
			повернути;

		/* treat socket error conditions */
		для (n = 0; n < 4; n++) {
			якщо (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		якщо (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		якщо (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		якщо (pfd[POLL_NETOUT].revents & POLLHUP) {
			якщо (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		якщо (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		якщо (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		якщо (pfd[POLL_STDOUT].fd == -1) {
			якщо (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		якщо (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			якщо (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			якщо (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			якщо (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		якщо (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			якщо (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			якщо (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			якщо (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		якщо (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			якщо (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			якщо (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			якщо (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			якщо (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			якщо (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		якщо (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			якщо (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			якщо (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			якщо (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		якщо (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			якщо (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		якщо (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ціле fd, unsigned char *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	якщо (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	якщо (n <= 0)
		повернути n;
	/* adjust buffer */
	adjust = *bufpos - n;
	якщо (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	повернути n;
}


ssize_t
fillbuf(ціле fd, unsigned char *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	якщо (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	якщо (n <= 0)
		повернути n;
	*bufpos += n;
	повернути n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(ціле nfd)
{
#якщо defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(ціле))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
#endif
	struct iovec vec;
	char ch = '\0';
	struct pollfd pfd;
	ssize_t r;

	memset(&msg, 0, sizeof(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&nfd;
	msg.msg_accrightslen = sizeof(nfd);
#інакше
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(ціле));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ціле *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, sizeof(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	для (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		якщо (r == -1) {
			якщо (errno == EAGAIN || errno == EINTR) {
				якщо (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} інакше якщо (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		інакше
			break;
	}
	exit(0);
#інакше
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(ціле nfd, unsigned char *buf, unsigned ціле size)
{
	unsigned char *p, *end;
	unsigned char obuf[4];

	якщо (size < 3)
		повернути;
	end = buf + size - 2;

	для (p = buf; p < end; p++) {
		якщо (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		якщо ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		інакше якщо ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		інакше
			continue;

		p++;
		obuf[2] = *p;
		якщо (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void
build_ports(char *p)
{
	const char *errstr;
	char *n;
	ціле hi, lo, cp;
	ціле x = 0;

	якщо ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		якщо (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		якщо (errstr)
			errx(1, "port number %s: %s", errstr, p);

		якщо (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		для (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			якщо (portlist[x] == NULL)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		якщо (rflag) {
			ціле y;
			char *c;

			для (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} інакше {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		якщо (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		якщо (portlist[0] == NULL)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ціле
udptest(ціле s)
{
	ціле i, ret;

	для (i = 0; i <= 3; i++) {
		якщо (write(s, "X", 1) == 1)
			ret = 1;
		інакше
			ret = -1;
	}
	повернути (ret);
}

void
set_common_sockopts(ціле s, ціле af)
{
	ціле x = 1;

#ifdef TCP_MD5SIG
	якщо (Sflag) {
		якщо (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, sizeof(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	якщо (Dflag) {
		якщо (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, sizeof(x)) == -1)
			err(1, "setsockopt");
	}
#якщо defined(IP_TOS) && defined(IPV6_TCLASS)
	якщо (Tflag != -1) {
		ціле proto, option;

		якщо (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} інакше {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		якщо (setsockopt(s, proto, option, &Tflag, sizeof(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	якщо (Iflag) {
		якщо (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, sizeof(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	якщо (Oflag) {
		якщо (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, sizeof(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ціле
map_tos(char *s, ціле *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	const struct toskeywords {
		const char	*keyword;
		ціле		 val;
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
		{ NULL, 		-1 },
	};

	для (t = toskeywords; t->keyword != NULL; t++) {
		якщо (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			повернути (1);
		}
	}
#endif

	повернути (0);
}

void
report_connect(const struct sockaddr *sa, socklen_t salen)
{
	char remote_host[NI_MAXHOST];
	char remote_port[NI_MAXSERV];
	ціле herr;
	ціле flags = NI_NUMERICSERV;
	
	якщо (nflag)
		flags |= NI_NUMERICHOST;
	
	якщо ((herr = getnameinfo(sa, salen,
	    remote_host, sizeof(remote_host),
	    remote_port, sizeof(remote_port),
	    flags)) != 0) {
		якщо (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		інакше
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

void
help(void)
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
	\t-i secs\t	Delay interval для lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open для multiple connects\n\
	\t-l		Listen mode, для inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername для proxy authentication\n\
	\t-p port\t	Specify local port для remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout для connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used для scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

void
usage(ціле ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	якщо (ret)
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>

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

ціле	remote_connect(const char *, const char *, struct addrinfo);
ціле	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, ціле,
	    const char *);

static ціле
decode_addrport(const char *h, const char *p, struct sockaddr *addr,
    socklen_t addrlen, ціле v4only, ціле numeric)
{
	ціле r;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	якщо (r != 0) {
		якщо (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		повернути (-1);
	}
	якщо (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	повернути (0);
}

static ціле
proxy_read_line(ціле fd, char *buf, size_t bufsz)
{
	size_t off;

	для(off = 0;;) {
		якщо (off >= bufsz)
			errx(1, "proxy read too long");
		якщо (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		якщо (buf[off] == '\r')
			continue;
		якщо (buf[off] == '\n') {
			buf[off] = '\0';
			break;
		}
		off++;
	}
	повернути (off);
}

static const char *
getproxypass(const char *proxyuser, const char *proxyhost)
{
	char prompt[512];
	static char pw[256];

	snprintf(prompt, sizeof(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	якщо (readpassphrase(prompt, pw, sizeof(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	повернути (pw);
}

ціле
socks_connect(const char *host, const char *port,
    struct addrinfo hints __attribute__ ((__unused__)),
    const char *proxyhost, const char *proxyport, struct addrinfo proxyhints,
    ціле socksv, const char *proxyuser)
{
	ціле proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned char buf[1024];
	size_t cnt;
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	in_port_t serverport;
	const char *proxypass = NULL;

	якщо (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	якщо (decode_addrport("0.0.0.0", port, (struct sockaddr *)&addr,
	    sizeof(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	якщо (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	якщо (proxyfd < 0)
		повернути (-1);

	якщо (socksv == 5) {
		якщо (decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		якщо (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		якщо (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		якщо (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		case 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			якщо (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, sizeof serverport);
			wlen = 7 + hlen;
			break;
		case AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, sizeof in4->sin_port);
			wlen = 10;
			break;
		case AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, sizeof in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    sizeof in6->sin6_port);
			wlen = 22;
			break;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		якщо (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		якщо (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		якщо (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		case SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			якщо (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			break;
		case SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			якщо (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			break;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} інакше якщо (socksv == 4 || socksv == 44) {
		якщо (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (struct sockaddr *)&addr,
			    sizeof(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, sizeof in4->sin_port);
		якщо (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
		} інакше {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		якщо (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			якщо (strlcpy(buf + 9, host,
			    sizeof(buf) - 9) >= sizeof(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		якщо (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		якщо (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		якщо (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} інакше якщо (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		якщо (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		якщо (strchr(host, ':') != NULL) {
			r = snprintf(buf, sizeof(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} інакше {
			r = snprintf(buf, sizeof(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		якщо (r == -1 || (size_t)r >= sizeof(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		якщо (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		якщо (authretry > 1) {
			char resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, sizeof(buf), "%s:%s",
			    proxyuser, proxypass);
			якщо (r == -1 || (size_t)r >= sizeof(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    sizeof(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, sizeof(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			якщо (r == -1 || (size_t)r >= sizeof(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			якщо ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		якщо ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, sizeof(buf));
		якщо (proxyuser != NULL &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			якщо (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} інакше якщо (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		для (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, sizeof(buf));
			якщо (*buf == '\0')
				break;
		}
		якщо (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} інакше
		errx(1, "Unknown proxy protocol %d", socksv);

	повернути (proxyfd);
}

