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
	(parimaa_na(*(su)) - parimaa_na((su)->sun_path) + strlen((su)->sun_path))
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
ཧྲིལ	dflag;					/* detached, no stdin */
ཧྲིལ	Fflag;					/* fdpass sock to stdout */
unsigned ཧྲིལ iflag;				/* Interval Flag */
ཧྲིལ	kflag;					/* More than one connect */
ཧྲིལ	lflag;					/* Bind to local port */
ཧྲིལ	Nflag;					/* shutdown() network socket */
ཧྲིལ	nflag;					/* Don't do name look up */
var_na   *Pflag;					/* Proxy username */
var_na   *pflag;					/* Localport flag */
ཧྲིལ	rflag;					/* Random ports flag */
var_na   *sflag;					/* Source Address */
ཧྲིལ	tflag;					/* Telnet Emulation */
ཧྲིལ	uflag;					/* UDP - Default to TCP */
ཧྲིལ	vflag;					/* Verbosity */
ཧྲིལ	xflag;					/* Socks proxy */
ཧྲིལ	zflag;					/* Port Scan Flag */
ཧྲིལ	Dflag;					/* sodebug */
ཧྲིལ	Iflag;					/* TCP receive buffer size */
ཧྲིལ	Oflag;					/* TCP send buffer size */
ཧྲིལ	Sflag;					/* TCP MD5 signature option */
ཧྲིལ	Tflag = -1;				/* IP Type of Service */
ཧྲིལ	rtableid = -1;

ཧྲིལ timeout = -1;
ཧྲིལ family = AF_UNSPEC;
var_na *portlist[PORT_MAX+1];
var_na *unix_dg_tmp_socket;

void	atelnet(ཧྲིལ, unsigned var_na *, unsigned ཧྲིལ);
void	build_ports(var_na *);
void	help(void);
ཧྲིལ	local_listen(var_na *, var_na *, sa_nracanaa addrinfo);
void	readwrite(ཧྲིལ);
void	fdpass(ཧྲིལ nfd) __attribute__((noreturn));
ཧྲིལ	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
ཧྲིལ	timeout_connect(ཧྲིལ, const sa_nracanaa sockaddr *, socklen_t);
ཧྲིལ	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, ཧྲིལ, const var_na *);
ཧྲིལ	udptest(ཧྲིལ);
ཧྲིལ	unix_bind(var_na *);
ཧྲིལ	unix_connect(var_na *);
ཧྲིལ	unix_listen(var_na *);
void	set_common_sockopts(ཧྲིལ, ཧྲིལ);
ཧྲིལ	map_tos(var_na *, ཧྲིལ *);
void	report_connect(const sa_nracanaa sockaddr *, socklen_t);
void	usage(ཧྲིལ);
ssize_t drainbuf(ཧྲིལ, unsigned var_na *, size_t *);
ssize_t fillbuf(ཧྲིལ, unsigned var_na *, size_t *);


ཧྲིལ
གཙོ(ཧྲིལ argc, var_na *argv[])
{
	ཧྲིལ ch, s, ret, socksv;
	var_na *host, *uport;
	sa_nracanaa addrinfo hints;
	sa_nracanaa servent *sv;
	socklen_t len;
	sa_nracanaa sockaddr_storage cliaddr;
	var_na *proxy = NULL;
	const var_na *errstr, *proxyhost = "", *proxyport = NULL;
	sa_nracanaa addrinfo proxyhints;
	var_na unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = NULL;
	uport = NULL;
	sv = NULL;

	sa_nkeeta(SIGPIPE, SIG_IGN);

	སྐབས ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		switch (ch) {
		pak_sa '4':
			family = AF_INET;
			bha_nga;
		pak_sa '6':
			family = AF_INET6;
			bha_nga;
		pak_sa 'U':
			family = AF_UNIX;
			bha_nga;
		pak_sa 'X':
			གལ་ཏེ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			དེ་མིན གལ་ཏེ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			དེ་མིན གལ་ཏེ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			དེ་མིན གལ་ཏེ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			དེ་མིན
				errx(1, "unsupported proxy protocol");
			bha_nga;
		pak_sa 'd':
			dflag = 1;
			bha_nga;
		pak_sa 'F':
			Fflag = 1;
			bha_nga;
		pak_sa 'h':
			help();
			bha_nga;
		pak_sa 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			གལ་ཏེ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			bha_nga;
		pak_sa 'k':
			kflag = 1;
			bha_nga;
		pak_sa 'l':
			lflag = 1;
			bha_nga;
		pak_sa 'N':
			Nflag = 1;
			bha_nga;
		pak_sa 'n':
			nflag = 1;
			bha_nga;
		pak_sa 'P':
			Pflag = optarg;
			bha_nga;
		pak_sa 'p':
			pflag = optarg;
			bha_nga;
		pak_sa 'r':
			rflag = 1;
			bha_nga;
		pak_sa 's':
			sflag = optarg;
			bha_nga;
		pak_sa 't':
			tflag = 1;
			bha_nga;
		pak_sa 'u':
			uflag = 1;
			bha_nga;
#ifdef SO_RTABLE
		pak_sa 'V':
			rtableid = (ཧྲིལ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			གལ་ཏེ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			bha_nga;
#endif
		pak_sa 'v':
			vflag = 1;
			bha_nga;
		pak_sa 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			གལ་ཏེ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			bha_nga;
		pak_sa 'x':
			xflag = 1;
			གལ་ཏེ ((proxy = strdup(optarg)) == NULL)
				errx(1, "strdup");
			bha_nga;
		pak_sa 'z':
			zflag = 1;
			bha_nga;
		pak_sa 'D':
			Dflag = 1;
			bha_nga;
		pak_sa 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			གལ་ཏེ (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			གལ་ཏེ (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'S':
			Sflag = 1;
			bha_nga;
		pak_sa 'T':
			errstr = NULL;
			errno = 0;
			གལ་ཏེ (map_tos(optarg, &Tflag))
				bha_nga;
			གལ་ཏེ (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ཧྲིལ)strtol(optarg, NULL, 16);
			དེ་མིན
				Tflag = (ཧྲིལ)strtonum(optarg, 0, 255,
				    &errstr);
			གལ་ཏེ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			bha_nga;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	གལ་ཏེ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = NULL;
	} དེ་མིན གལ་ཏེ (argv[0] && !argv[1]) {
		གལ་ཏེ  (!lflag)
			usage(1);
		uport = argv[0];
		host = NULL;
	} དེ་མིན གལ་ཏེ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} དེ་མིན
		usage(1);

	གལ་ཏེ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	གལ་ཏེ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	གལ་ཏེ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	གལ་ཏེ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	གལ་ཏེ ((family == AF_UNIX) && uflag && !lflag) {
		གལ་ཏེ (sflag) {
			unix_dg_tmp_socket = sflag;
		} དེ་མིན {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			གལ་ཏེ (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	གལ་ཏེ (family != AF_UNIX) {
		memset(&hints, 0, parimaa_na(sa_nracanaa addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		གལ་ཏེ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	གལ་ཏེ (xflag) {
		གལ་ཏེ (uflag)
			errx(1, "no proxy support for UDP mode");

		གལ་ཏེ (lflag)
			errx(1, "no proxy support for listen");

		གལ་ཏེ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		གལ་ཏེ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		གལ་ཏེ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, parimaa_na(sa_nracanaa addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		གལ་ཏེ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	གལ་ཏེ (lflag) {
		ཧྲིལ connfd;
		ret = 0;

		གལ་ཏེ (family == AF_UNIX) {
			གལ་ཏེ (uflag)
				s = unix_bind(host);
			དེ་མིན
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ཆེད་དུ (;;) {
			གལ་ཏེ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			གལ་ཏེ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			གལ་ཏེ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			དེ་མིན གལ་ཏེ (uflag && !kflag) {
				ཧྲིལ rv, plen;
				var_na buf[16384];
				sa_nracanaa sockaddr_storage z;

				len = parimaa_na(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (sa_nracanaa sockaddr *)&z, &len);
				གལ་ཏེ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (sa_nracanaa sockaddr *)&z, len);
				གལ་ཏེ (rv < 0)
					err(1, "connect");

				གལ་ཏེ (vflag)
					report_connect((sa_nracanaa sockaddr *)&z, len);

				readwrite(s);
			} དེ་མིན {
				len = parimaa_na(cliaddr);
				connfd = accept(s, (sa_nracanaa sockaddr *)&cliaddr,
				    &len);
				གལ་ཏེ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				གལ་ཏེ (vflag)
					report_connect((sa_nracanaa sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			གལ་ཏེ (family != AF_UNIX)
				close(s);
			དེ་མིན གལ་ཏེ (uflag) {
				གལ་ཏེ (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}

			གལ་ཏེ (!kflag)
				bha_nga;
		}
	} དེ་མིན གལ་ཏེ (family == AF_UNIX) {
		ret = 0;

		གལ་ཏེ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} དེ་མིན
			ret = 1;

		གལ་ཏེ (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} དེ་མིན {
		ཧྲིལ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ཆེད་དུ (i = 0; portlist[i] != NULL; i++) {
			གལ་ཏེ (s)
				close(s);

			གལ་ཏེ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			དེ་མིན
				s = remote_connect(host, portlist[i], hints);

			གལ་ཏེ (s < 0)
				continue;

			ret = 0;
			གལ་ཏེ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				གལ་ཏེ (uflag) {
					གལ་ཏེ (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				/* Don't look up port if -n. */
				གལ་ཏེ (nflag)
					sv = NULL;
				དེ་མིན {
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
			གལ་ཏེ (Fflag)
				fdpass(s);
			དེ་མིན གལ་ཏེ (!zflag)
				readwrite(s);
		}
	}

	གལ་ཏེ (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ཧྲིལ
unix_bind(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	ཧྲིལ s;

	/* Create unix domain socket. */
	གལ་ཏེ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ཕྱིར (-1);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	གལ་ཏེ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ཕྱིར (-1);
	}

	གལ་ཏེ (bind(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ཕྱིར (-1);
	}
	ཕྱིར (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ཧྲིལ
unix_connect(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	ཧྲིལ s;

	གལ་ཏེ (uflag) {
		གལ་ཏེ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ཕྱིར (-1);
	} དེ་མིན {
		གལ་ཏེ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ཕྱིར (-1);
	}
	(void)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	གལ་ཏེ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ཕྱིར (-1);
	}
	གལ་ཏེ (connect(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ཕྱིར (-1);
	}
	ཕྱིར (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ཧྲིལ
unix_listen(var_na *path)
{
	ཧྲིལ s;
	གལ་ཏེ ((s = unix_bind(path)) < 0)
		ཕྱིར (-1);

	གལ་ཏེ (listen(s, 5) < 0) {
		close(s);
		ཕྱིར (-1);
	}
	ཕྱིར (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ཧྲིལ
remote_connect(const var_na *host, const var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	ཧྲིལ s, error;
#གལ་ཏེ defined(SO_RTABLE) || defined(SO_BINDANY)
	ཧྲིལ on = 1;
#endif

	གལ་ཏེ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		གལ་ཏེ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		གལ་ཏེ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		གལ་ཏེ (sflag || pflag) {
			sa_nracanaa addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, parimaa_na(on));
#endif
			memset(&ahints, 0, parimaa_na(sa_nracanaa addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			གལ་ཏེ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			གལ་ཏེ (bind(s, (sa_nracanaa sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		གལ་ཏེ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			bha_nga;
		དེ་མིན གལ་ཏེ (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} སྐབས ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	ཕྱིར (s);
}

ཧྲིལ
timeout_connect(ཧྲིལ s, const sa_nracanaa sockaddr *name, socklen_t namelen)
{
	sa_nracanaa pollfd pfd;
	socklen_t optlen;
	ཧྲིལ flags = 0, optval;
	ཧྲིལ ret;

	གལ་ཏེ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		གལ་ཏེ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	གལ་ཏེ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		གལ་ཏེ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = parimaa_na(optval);
			གལ་ཏེ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} དེ་མིན གལ་ཏེ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} དེ་མིན
			err(1, "poll failed");
	}

	གལ་ཏེ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ཕྱིར (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ཧྲིལ
local_listen(var_na *host, var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	ཧྲིལ s, ret, x = 1;
	ཧྲིལ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	གལ་ཏེ (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	གལ་ཏེ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		གལ་ཏེ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		གལ་ཏེ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, parimaa_na(x));
		གལ་ཏེ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, parimaa_na(x));
		གལ་ཏེ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		གལ་ཏེ (bind(s, (sa_nracanaa sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			bha_nga;

		close(s);
		s = -1;
	} སྐབས ((res0 = res0->ai_next) != NULL);

	གལ་ཏེ (!uflag && s != -1) {
		གལ་ཏེ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ཕྱིར (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(ཧྲིལ net_fd)
{
	sa_nracanaa pollfd pfd[4];
	ཧྲིལ stdin_fd = STDIN_FILENO;
	ཧྲིལ stdout_fd = STDOUT_FILENO;
	unsigned var_na netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned var_na stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	ཧྲིལ n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	གལ་ཏེ (dflag)
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

	སྐབས (1) {
		/* both inputs are gone, buffers are empty, we are done */
		གལ་ཏེ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ཕྱིར;
		}
		/* both outputs are gone, we can't continue */
		གལ་ཏེ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ཕྱིར;
		}
		/* listen and net in gone, queues empty, done */
		གལ་ཏེ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ཕྱིར;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		གལ་ཏེ (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		གལ་ཏེ (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		གལ་ཏེ (num_fds == 0)
			ཕྱིར;

		/* treat socket error conditions */
		ཆེད་དུ (n = 0; n < 4; n++) {
			གལ་ཏེ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		གལ་ཏེ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		གལ་ཏེ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		གལ་ཏེ (pfd[POLL_NETOUT].revents & POLLHUP) {
			གལ་ཏེ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		གལ་ཏེ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		གལ་ཏེ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		གལ་ཏེ (pfd[POLL_STDOUT].fd == -1) {
			གལ་ཏེ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		གལ་ཏེ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			གལ་ཏེ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			གལ་ཏེ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			གལ་ཏེ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		གལ་ཏེ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			གལ་ཏེ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			གལ་ཏེ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			གལ་ཏེ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		གལ་ཏེ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			གལ་ཏེ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			གལ་ཏེ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			གལ་ཏེ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			གལ་ཏེ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			གལ་ཏེ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		གལ་ཏེ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			གལ་ཏེ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			གལ་ཏེ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			གལ་ཏེ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		གལ་ཏེ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			གལ་ཏེ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		གལ་ཏེ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ཧྲིལ fd, unsigned var_na *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	གལ་ཏེ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	གལ་ཏེ (n <= 0)
		ཕྱིར n;
	/* adjust buffer */
	adjust = *bufpos - n;
	གལ་ཏེ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ཕྱིར n;
}


ssize_t
fillbuf(ཧྲིལ fd, unsigned var_na *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	གལ་ཏེ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	གལ་ཏེ (n <= 0)
		ཕྱིར n;
	*bufpos += n;
	ཕྱིར n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(ཧྲིལ nfd)
{
#གལ་ཏེ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	sa_nracanaa msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	sa_ngha {
		sa_nracanaa cmsghdr hdr;
		var_na buf[CMSG_SPACE(parimaa_na(ཧྲིལ))];
	} cmsgbuf;
	sa_nracanaa cmsghdr *cmsg;
#endif
	sa_nracanaa iovec vec;
	var_na ch = '\0';
	sa_nracanaa pollfd pfd;
	ssize_t r;

	memset(&msg, 0, parimaa_na(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&nfd;
	msg.msg_accrightslen = parimaa_na(nfd);
#དེ་མིན
	memset(&cmsgbuf, 0, parimaa_na(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = parimaa_na(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(parimaa_na(ཧྲིལ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ཧྲིལ *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, parimaa_na(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ཆེད་དུ (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		གལ་ཏེ (r == -1) {
			གལ་ཏེ (errno == EAGAIN || errno == EINTR) {
				གལ་ཏེ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} དེ་མིན གལ་ཏེ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		དེ་མིན
			bha_nga;
	}
	exit(0);
#དེ་མིན
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(ཧྲིལ nfd, unsigned var_na *buf, unsigned ཧྲིལ size)
{
	unsigned var_na *p, *end;
	unsigned var_na obuf[4];

	གལ་ཏེ (size < 3)
		ཕྱིར;
	end = buf + size - 2;

	ཆེད་དུ (p = buf; p < end; p++) {
		གལ་ཏེ (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		གལ་ཏེ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		དེ་མིན གལ་ཏེ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		དེ་མིན
			continue;

		p++;
		obuf[2] = *p;
		གལ་ཏེ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void
build_ports(var_na *p)
{
	const var_na *errstr;
	var_na *n;
	ཧྲིལ hi, lo, cp;
	ཧྲིལ x = 0;

	གལ་ཏེ ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		གལ་ཏེ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		གལ་ཏེ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		གལ་ཏེ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ཆེད་དུ (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			གལ་ཏེ (portlist[x] == NULL)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		གལ་ཏེ (rflag) {
			ཧྲིལ y;
			var_na *c;

			ཆེད་དུ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} དེ་མིན {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		གལ་ཏེ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		གལ་ཏེ (portlist[0] == NULL)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ཧྲིལ
udptest(ཧྲིལ s)
{
	ཧྲིལ i, ret;

	ཆེད་དུ (i = 0; i <= 3; i++) {
		གལ་ཏེ (write(s, "X", 1) == 1)
			ret = 1;
		དེ་མིན
			ret = -1;
	}
	ཕྱིར (ret);
}

void
set_common_sockopts(ཧྲིལ s, ཧྲིལ af)
{
	ཧྲིལ x = 1;

#ifdef TCP_MD5SIG
	གལ་ཏེ (Sflag) {
		གལ་ཏེ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	གལ་ཏེ (Dflag) {
		གལ་ཏེ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#གལ་ཏེ defined(IP_TOS) && defined(IPV6_TCLASS)
	གལ་ཏེ (Tflag != -1) {
		ཧྲིལ proto, option;

		གལ་ཏེ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} དེ་མིན {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		གལ་ཏེ (setsockopt(s, proto, option, &Tflag, parimaa_na(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	གལ་ཏེ (Iflag) {
		གལ་ཏེ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, parimaa_na(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	གལ་ཏེ (Oflag) {
		གལ་ཏེ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, parimaa_na(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ཧྲིལ
map_tos(var_na *s, ཧྲིལ *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	const sa_nracanaa toskeywords {
		const var_na	*keyword;
		ཧྲིལ		 val;
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

	ཆེད་དུ (t = toskeywords; t->keyword != NULL; t++) {
		གལ་ཏེ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ཕྱིར (1);
		}
	}
#endif

	ཕྱིར (0);
}

void
report_connect(const sa_nracanaa sockaddr *sa, socklen_t salen)
{
	var_na remote_host[NI_MAXHOST];
	var_na remote_port[NI_MAXSERV];
	ཧྲིལ herr;
	ཧྲིལ flags = NI_NUMERICSERV;
	
	གལ་ཏེ (nflag)
		flags |= NI_NUMERICHOST;
	
	གལ་ཏེ ((herr = getnameinfo(sa, salen,
	    remote_host, parimaa_na(remote_host),
	    remote_port, parimaa_na(remote_port),
	    flags)) != 0) {
		གལ་ཏེ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		དེ་མིན
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
	\t-i secs\t	Delay interval ཆེད་དུ lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open ཆེད་དུ multiple connects\n\
	\t-l		Listen mode, ཆེད་དུ inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername ཆེད་དུ proxy authentication\n\
	\t-p port\t	Specify local port ཆེད་དུ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ཆེད་དུ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used ཆེད་དུ scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

void
usage(ཧྲིལ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	གལ་ཏེ (ret)
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

ཧྲིལ	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
ཧྲིལ	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, ཧྲིལ,
	    const var_na *);

static ཧྲིལ
decode_addrport(const var_na *h, const var_na *p, sa_nracanaa sockaddr *addr,
    socklen_t addrlen, ཧྲིལ v4only, ཧྲིལ numeric)
{
	ཧྲིལ r;
	sa_nracanaa addrinfo hints, *res;

	bzero(&hints, parimaa_na(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	གལ་ཏེ (r != 0) {
		གལ་ཏེ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ཕྱིར (-1);
	}
	གལ་ཏེ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ཕྱིར (0);
}

static ཧྲིལ
proxy_read_line(ཧྲིལ fd, var_na *buf, size_t bufsz)
{
	size_t off;

	ཆེད་དུ(off = 0;;) {
		གལ་ཏེ (off >= bufsz)
			errx(1, "proxy read too long");
		གལ་ཏེ (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		གལ་ཏེ (buf[off] == '\r')
			continue;
		གལ་ཏེ (buf[off] == '\n') {
			buf[off] = '\0';
			bha_nga;
		}
		off++;
	}
	ཕྱིར (off);
}

static const var_na *
getproxypass(const var_na *proxyuser, const var_na *proxyhost)
{
	var_na prompt[512];
	static var_na pw[256];

	snprintf(prompt, parimaa_na(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	གལ་ཏེ (readpassphrase(prompt, pw, parimaa_na(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	ཕྱིར (pw);
}

ཧྲིལ
socks_connect(const var_na *host, const var_na *port,
    sa_nracanaa addrinfo hints __attribute__ ((__unused__)),
    const var_na *proxyhost, const var_na *proxyport, sa_nracanaa addrinfo proxyhints,
    ཧྲིལ socksv, const var_na *proxyuser)
{
	ཧྲིལ proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned var_na buf[1024];
	size_t cnt;
	sa_nracanaa sockaddr_storage addr;
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)&addr;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)&addr;
	in_port_t serverport;
	const var_na *proxypass = NULL;

	གལ་ཏེ (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	གལ་ཏེ (decode_addrport("0.0.0.0", port, (sa_nracanaa sockaddr *)&addr,
	    parimaa_na(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	གལ་ཏེ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	གལ་ཏེ (proxyfd < 0)
		ཕྱིར (-1);

	གལ་ཏེ (socksv == 5) {
		གལ་ཏེ (decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
		    parimaa_na(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		གལ་ཏེ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		གལ་ཏེ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		གལ་ཏེ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		pak_sa 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			གལ་ཏེ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);			
			memcpy(buf + 5 + hlen, &serverport, parimaa_na serverport);
			wlen = 7 + hlen;
			bha_nga;
		pak_sa AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, parimaa_na in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, parimaa_na in4->sin_port);
			wlen = 10;
			bha_nga;
		pak_sa AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, parimaa_na in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    parimaa_na in6->sin6_port);
			wlen = 22;
			bha_nga;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		གལ་ཏེ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		གལ་ཏེ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		གལ་ཏེ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		pak_sa SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			གལ་ཏེ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			bha_nga;
		pak_sa SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			གལ་ཏེ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			bha_nga;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} དེ་མིན གལ་ཏེ (socksv == 4 || socksv == 44) {
		གལ་ཏེ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
			    parimaa_na(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, parimaa_na in4->sin_port);
		གལ་ཏེ (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, parimaa_na in4->sin_addr);
		} དེ་མིན {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		གལ་ཏེ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			གལ་ཏེ (strlcpy(buf + 9, host,
			    parimaa_na(buf) - 9) >= parimaa_na(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		གལ་ཏེ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		གལ་ཏེ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		གལ་ཏེ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} དེ་མིན གལ་ཏེ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		གལ་ཏེ (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		གལ་ཏེ (strchr(host, ':') != NULL) {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} དེ་མིན {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		གལ་ཏེ (r == -1 || (size_t)r >= parimaa_na(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		གལ་ཏེ (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		གལ་ཏེ (authretry > 1) {
			var_na resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, parimaa_na(buf), "%s:%s",
			    proxyuser, proxypass);
			གལ་ཏེ (r == -1 || (size_t)r >= parimaa_na(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    parimaa_na(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, parimaa_na(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			གལ་ཏེ (r == -1 || (size_t)r >= parimaa_na(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			གལ་ཏེ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		གལ་ཏེ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, parimaa_na(buf));
		གལ་ཏེ (proxyuser != NULL &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			གལ་ཏེ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} དེ་མིན གལ་ཏེ (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ཆེད་དུ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, parimaa_na(buf));
			གལ་ཏེ (*buf == '\0')
				bha_nga;
		}
		གལ་ཏེ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} དེ་མིན
		errx(1, "Unknown proxy protocol %d", socksv);

	ཕྱིར (proxyfd);
}

