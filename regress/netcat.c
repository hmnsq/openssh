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
цео	dflag;					/* detached, no stdin */
цео	Fflag;					/* fdpass sock to stdout */
unsigned цео iflag;				/* Interval Flag */
цео	kflag;					/* More than one connect */
цео	lflag;					/* Bind to local port */
цео	Nflag;					/* shutdown() network socket */
цео	nflag;					/* Don't do name look up */
char   *Pflag;					/* Proxy username */
char   *pflag;					/* Localport flag */
цео	rflag;					/* Random ports flag */
char   *sflag;					/* Source Address */
цео	tflag;					/* Telnet Emulation */
цео	uflag;					/* UDP - Default to TCP */
цео	vflag;					/* Verbosity */
цео	xflag;					/* Socks proxy */
цео	zflag;					/* Port Scan Flag */
цео	Dflag;					/* sodebug */
цео	Iflag;					/* TCP receive buffer size */
цео	Oflag;					/* TCP send buffer size */
цео	Sflag;					/* TCP MD5 signature option */
цео	Tflag = -1;				/* IP Type of Service */
цео	rtableid = -1;

цео timeout = -1;
цео family = AF_UNSPEC;
char *portlist[PORT_MAX+1];
char *unix_dg_tmp_socket;

void	atelnet(цео, unsigned char *, unsigned цео);
void	build_ports(char *);
void	help(void);
цео	local_listen(char *, char *, struct addrinfo);
void	readwrite(цео);
void	fdpass(цео nfd) __attribute__((noreturn));
цео	remote_connect(const char *, const char *, struct addrinfo);
цео	timeout_connect(цео, const struct sockaddr *, socklen_t);
цео	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, цео, const char *);
цео	udptest(цео);
цео	unix_bind(char *);
цео	unix_connect(char *);
цео	unix_listen(char *);
void	set_common_sockopts(цео, цео);
цео	map_tos(char *, цео *);
void	report_connect(const struct sockaddr *, socklen_t);
void	usage(цео);
ssize_t drainbuf(цео, unsigned char *, size_t *);
ssize_t fillbuf(цео, unsigned char *, size_t *);


цео
main(цео argc, char *argv[])
{
	цео ch, s, ret, socksv;
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

	док ((ch = getopt(argc, argv,
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
			ако (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			инако ако (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			инако ако (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			инако ако (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			инако
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
			ако (errstr)
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
			rtableid = (цео)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ако (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			break;
#endif
		case 'v':
			vflag = 1;
			break;
		case 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			ако (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			break;
		case 'x':
			xflag = 1;
			ако ((proxy = strdup(optarg)) == NULL)
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
			ако (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			break;
		case 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ако (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			break;
		case 'S':
			Sflag = 1;
			break;
		case 'T':
			errstr = NULL;
			errno = 0;
			ако (map_tos(optarg, &Tflag))
				break;
			ако (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (цео)strtol(optarg, NULL, 16);
			инако
				Tflag = (цео)strtonum(optarg, 0, 255,
				    &errstr);
			ако (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ако (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = NULL;
	} инако ако (argv[0] && !argv[1]) {
		ако  (!lflag)
			usage(1);
		uport = argv[0];
		host = NULL;
	} инако ако (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} инако
		usage(1);

	ако (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ако (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ако (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ако (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ако ((family == AF_UNIX) && uflag && !lflag) {
		ако (sflag) {
			unix_dg_tmp_socket = sflag;
		} инако {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			ако (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ако (family != AF_UNIX) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ако (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ако (xflag) {
		ако (uflag)
			errx(1, "no proxy support for UDP mode");

		ако (lflag)
			errx(1, "no proxy support for listen");

		ако (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ако (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ако (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, sizeof(struct addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ако (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ако (lflag) {
		цео connfd;
		ret = 0;

		ако (family == AF_UNIX) {
			ако (uflag)
				s = unix_bind(host);
			инако
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		за (;;) {
			ако (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ако (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ако (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			инако ако (uflag && !kflag) {
				цео rv, plen;
				char buf[16384];
				struct sockaddr_storage z;

				len = sizeof(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (struct sockaddr *)&z, &len);
				ако (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (struct sockaddr *)&z, len);
				ако (rv < 0)
					err(1, "connect");

				ако (vflag)
					report_connect((struct sockaddr *)&z, len);

				readwrite(s);
			} инако {
				len = sizeof(cliaddr);
				connfd = accept(s, (struct sockaddr *)&cliaddr,
				    &len);
				ако (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ако (vflag)
					report_connect((struct sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ако (family != AF_UNIX)
				close(s);
			инако ако (uflag) {
				ако (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}

			ако (!kflag)
				break;
		}
	} инако ако (family == AF_UNIX) {
		ret = 0;

		ако ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} инако
			ret = 1;

		ако (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} инако {
		цео i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		за (i = 0; portlist[i] != NULL; i++) {
			ако (s)
				close(s);

			ако (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			инако
				s = remote_connect(host, portlist[i], hints);

			ако (s < 0)
				continue;

			ret = 0;
			ако (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ако (uflag) {
					ако (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				/* Don't look up port if -n. */
				ако (nflag)
					sv = NULL;
				инако {
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
			ако (Fflag)
				fdpass(s);
			инако ако (!zflag)
				readwrite(s);
		}
	}

	ако (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
цео
unix_bind(char *path)
{
	struct sockaddr_un sun_sa;
	цео s;

	/* Create unix domain socket. */
	ако ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		врати (-1);

	memset(&sun_sa, 0, sizeof(struct sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ако (strlcpy(sun_sa.sun_path, path, sizeof(sun_sa.sun_path)) >=
	    sizeof(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		врати (-1);
	}

	ако (bind(s, (struct sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		врати (-1);
	}
	врати (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
цео
unix_connect(char *path)
{
	struct sockaddr_un sun_sa;
	цео s;

	ако (uflag) {
		ако ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			врати (-1);
	} инако {
		ако ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			врати (-1);
	}
	(void)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, sizeof(struct sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ако (strlcpy(sun_sa.sun_path, path, sizeof(sun_sa.sun_path)) >=
	    sizeof(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		врати (-1);
	}
	ако (connect(s, (struct sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		врати (-1);
	}
	врати (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
цео
unix_listen(char *path)
{
	цео s;
	ако ((s = unix_bind(path)) < 0)
		врати (-1);

	ако (listen(s, 5) < 0) {
		close(s);
		врати (-1);
	}
	врати (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
цео
remote_connect(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	цео s, error;
#ако defined(SO_RTABLE) || defined(SO_BINDANY)
	цео on = 1;
#endif

	ако ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ако ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ако (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		ако (sflag || pflag) {
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
			ако ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ако (bind(s, (struct sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		ако (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			break;
		инако ако (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} док ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	врати (s);
}

цео
timeout_connect(цео s, const struct sockaddr *name, socklen_t namelen)
{
	struct pollfd pfd;
	socklen_t optlen;
	цео flags = 0, optval;
	цео ret;

	ако (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ако (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ако ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ако ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = sizeof(optval);
			ако ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} инако ако (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} инако
			err(1, "poll failed");
	}

	ако (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	врати (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
цео
local_listen(char *host, char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	цео s, ret, x = 1;
	цео error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ако (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ако ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ако ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ако (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, sizeof(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
		ако (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x));
		ако (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		ако (bind(s, (struct sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			break;

		close(s);
		s = -1;
	} док ((res0 = res0->ai_next) != NULL);

	ако (!uflag && s != -1) {
		ако (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	врати (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(цео net_fd)
{
	struct pollfd pfd[4];
	цео stdin_fd = STDIN_FILENO;
	цео stdout_fd = STDOUT_FILENO;
	unsigned char netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned char stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	цео n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ако (dflag)
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

	док (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ако (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			врати;
		}
		/* both outputs are gone, we can't continue */
		ако (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			врати;
		}
		/* listen and net in gone, queues empty, done */
		ако (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			врати;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ако (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ако (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ако (num_fds == 0)
			врати;

		/* treat socket error conditions */
		за (n = 0; n < 4; n++) {
			ако (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ако (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ако (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ако (pfd[POLL_NETOUT].revents & POLLHUP) {
			ако (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ако (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ако (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ако (pfd[POLL_STDOUT].fd == -1) {
			ако (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ако (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ако (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ако (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ако (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ако (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ако (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ако (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ако (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ако (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ако (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ако (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ако (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ако (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ако (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ако (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ако (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ако (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ако (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ако (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ако (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ако (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(цео fd, unsigned char *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ако (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ако (n <= 0)
		врати n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ако (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	врати n;
}


ssize_t
fillbuf(цео fd, unsigned char *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	ако (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ако (n <= 0)
		врати n;
	*bufpos += n;
	врати n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(цео nfd)
{
#ако defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(цео))];
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
#инако
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(цео));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(цео *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, sizeof(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	за (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		ако (r == -1) {
			ако (errno == EAGAIN || errno == EINTR) {
				ако (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} инако ако (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		инако
			break;
	}
	exit(0);
#инако
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(цео nfd, unsigned char *buf, unsigned цео size)
{
	unsigned char *p, *end;
	unsigned char obuf[4];

	ако (size < 3)
		врати;
	end = buf + size - 2;

	за (p = buf; p < end; p++) {
		ако (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		ако ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		инако ако ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		инако
			continue;

		p++;
		obuf[2] = *p;
		ако (atomicio(vwrite, nfd, obuf, 3) != 3)
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
	цео hi, lo, cp;
	цео x = 0;

	ако ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		ако (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		ако (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ако (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		за (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			ако (portlist[x] == NULL)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ако (rflag) {
			цео y;
			char *c;

			за (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} инако {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		ако (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ако (portlist[0] == NULL)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
цео
udptest(цео s)
{
	цео i, ret;

	за (i = 0; i <= 3; i++) {
		ако (write(s, "X", 1) == 1)
			ret = 1;
		инако
			ret = -1;
	}
	врати (ret);
}

void
set_common_sockopts(цео s, цео af)
{
	цео x = 1;

#ifdef TCP_MD5SIG
	ако (Sflag) {
		ако (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, sizeof(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	ако (Dflag) {
		ако (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, sizeof(x)) == -1)
			err(1, "setsockopt");
	}
#ако defined(IP_TOS) && defined(IPV6_TCLASS)
	ако (Tflag != -1) {
		цео proto, option;

		ако (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} инако {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ако (setsockopt(s, proto, option, &Tflag, sizeof(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	ако (Iflag) {
		ако (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, sizeof(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ако (Oflag) {
		ако (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, sizeof(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

цео
map_tos(char *s, цео *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	const struct toskeywords {
		const char	*keyword;
		цео		 val;
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

	за (t = toskeywords; t->keyword != NULL; t++) {
		ако (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			врати (1);
		}
	}
#endif

	врати (0);
}

void
report_connect(const struct sockaddr *sa, socklen_t salen)
{
	char remote_host[NI_MAXHOST];
	char remote_port[NI_MAXSERV];
	цео herr;
	цео flags = NI_NUMERICSERV;
	
	ако (nflag)
		flags |= NI_NUMERICHOST;
	
	ако ((herr = getnameinfo(sa, salen,
	    remote_host, sizeof(remote_host),
	    remote_port, sizeof(remote_port),
	    flags)) != 0) {
		ако (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		инако
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
	\t-i secs\t	Delay interval за lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open за multiple connects\n\
	\t-l		Listen mode, за inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername за proxy authentication\n\
	\t-p port\t	Specify local port за remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout за connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used за scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

void
usage(цео ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ако (ret)
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

цео	remote_connect(const char *, const char *, struct addrinfo);
цео	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, цео,
	    const char *);

static цео
decode_addrport(const char *h, const char *p, struct sockaddr *addr,
    socklen_t addrlen, цео v4only, цео numeric)
{
	цео r;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ако (r != 0) {
		ако (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		врати (-1);
	}
	ако (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	врати (0);
}

static цео
proxy_read_line(цео fd, char *buf, size_t bufsz)
{
	size_t off;

	за(off = 0;;) {
		ако (off >= bufsz)
			errx(1, "proxy read too long");
		ако (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ако (buf[off] == '\r')
			continue;
		ако (buf[off] == '\n') {
			buf[off] = '\0';
			break;
		}
		off++;
	}
	врати (off);
}

static const char *
getproxypass(const char *proxyuser, const char *proxyhost)
{
	char prompt[512];
	static char pw[256];

	snprintf(prompt, sizeof(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ако (readpassphrase(prompt, pw, sizeof(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	врати (pw);
}

цео
socks_connect(const char *host, const char *port,
    struct addrinfo hints __attribute__ ((__unused__)),
    const char *proxyhost, const char *proxyport, struct addrinfo proxyhints,
    цео socksv, const char *proxyuser)
{
	цео proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned char buf[1024];
	size_t cnt;
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	in_port_t serverport;
	const char *proxypass = NULL;

	ако (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	ако (decode_addrport("0.0.0.0", port, (struct sockaddr *)&addr,
	    sizeof(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	ако (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ако (proxyfd < 0)
		врати (-1);

	ако (socksv == 5) {
		ако (decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ако (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		ако (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ако (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		case 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			ако (hlen > 255)
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
		ако (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		ако (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ако (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		case SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			ако (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			break;
		case SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			ако (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			break;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} инако ако (socksv == 4 || socksv == 44) {
		ако (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (struct sockaddr *)&addr,
			    sizeof(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, sizeof in4->sin_port);
		ако (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
		} инако {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ако (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ако (strlcpy(buf + 9, host,
			    sizeof(buf) - 9) >= sizeof(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ако (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		ако (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ако (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} инако ако (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ако (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ако (strchr(host, ':') != NULL) {
			r = snprintf(buf, sizeof(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} инако {
			r = snprintf(buf, sizeof(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ако (r == -1 || (size_t)r >= sizeof(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ако (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ако (authretry > 1) {
			char resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, sizeof(buf), "%s:%s",
			    proxyuser, proxypass);
			ако (r == -1 || (size_t)r >= sizeof(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    sizeof(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, sizeof(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ако (r == -1 || (size_t)r >= sizeof(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			ако ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ако ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, sizeof(buf));
		ако (proxyuser != NULL &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			ако (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} инако ако (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		за (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, sizeof(buf));
			ако (*buf == '\0')
				break;
		}
		ако (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} инако
		errx(1, "Unknown proxy protocol %d", socksv);

	врати (proxyfd);
}

