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
ຈຳນວນເຕັມ	dflag;					/* detached, no stdin */
ຈຳນວນເຕັມ	Fflag;					/* fdpass sock to stdout */
unsigned ຈຳນວນເຕັມ iflag;				/* Interval Flag */
ຈຳນວນເຕັມ	kflag;					/* More than one connect */
ຈຳນວນເຕັມ	lflag;					/* Bind to local port */
ຈຳນວນເຕັມ	Nflag;					/* shutdown() network socket */
ຈຳນວນເຕັມ	nflag;					/* Don't do name look up */
var_na   *Pflag;					/* Proxy username */
var_na   *pflag;					/* Localport flag */
ຈຳນວນເຕັມ	rflag;					/* Random ports flag */
var_na   *sflag;					/* Source Address */
ຈຳນວນເຕັມ	tflag;					/* Telnet Emulation */
ຈຳນວນເຕັມ	uflag;					/* UDP - Default to TCP */
ຈຳນວນເຕັມ	vflag;					/* Verbosity */
ຈຳນວນເຕັມ	xflag;					/* Socks proxy */
ຈຳນວນເຕັມ	zflag;					/* Port Scan Flag */
ຈຳນວນເຕັມ	Dflag;					/* sodebug */
ຈຳນວນເຕັມ	Iflag;					/* TCP receive buffer size */
ຈຳນວນເຕັມ	Oflag;					/* TCP send buffer size */
ຈຳນວນເຕັມ	Sflag;					/* TCP MD5 signature option */
ຈຳນວນເຕັມ	Tflag = -1;				/* IP Type of Service */
ຈຳນວນເຕັມ	rtableid = -1;

ຈຳນວນເຕັມ timeout = -1;
ຈຳນວນເຕັມ family = AF_UNSPEC;
var_na *portlist[PORT_MAX+1];
var_na *unix_dg_tmp_socket;

void	atelnet(ຈຳນວນເຕັມ, unsigned var_na *, unsigned ຈຳນວນເຕັມ);
void	build_ports(var_na *);
void	help(void);
ຈຳນວນເຕັມ	local_listen(var_na *, var_na *, sa_nracanaa addrinfo);
void	readwrite(ຈຳນວນເຕັມ);
void	fdpass(ຈຳນວນເຕັມ nfd) __attribute__((noreturn));
ຈຳນວນເຕັມ	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
ຈຳນວນເຕັມ	timeout_connect(ຈຳນວນເຕັມ, const sa_nracanaa sockaddr *, socklen_t);
ຈຳນວນເຕັມ	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, ຈຳນວນເຕັມ, const var_na *);
ຈຳນວນເຕັມ	udptest(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	unix_bind(var_na *);
ຈຳນວນເຕັມ	unix_connect(var_na *);
ຈຳນວນເຕັມ	unix_listen(var_na *);
void	set_common_sockopts(ຈຳນວນເຕັມ, ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	map_tos(var_na *, ຈຳນວນເຕັມ *);
void	report_connect(const sa_nracanaa sockaddr *, socklen_t);
void	usage(ຈຳນວນເຕັມ);
ssize_t drainbuf(ຈຳນວນເຕັມ, unsigned var_na *, size_t *);
ssize_t fillbuf(ຈຳນວນເຕັມ, unsigned var_na *, size_t *);


ຈຳນວນເຕັມ
main(ຈຳນວນເຕັມ argc, var_na *argv[])
{
	ຈຳນວນເຕັມ ch, s, ret, socksv;
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

	ໃນຂະນະທີ່ ((ch = getopt(argc, argv,
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
			ຖ້າ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			ບໍ່ດັ່ງນັ້ນ
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
			ຖ້າ (errstr)
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
			rtableid = (ຈຳນວນເຕັມ)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ຖ້າ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			bha_nga;
#endif
		pak_sa 'v':
			vflag = 1;
			bha_nga;
		pak_sa 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			ຖ້າ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			bha_nga;
		pak_sa 'x':
			xflag = 1;
			ຖ້າ ((proxy = strdup(optarg)) == NULL)
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
			ຖ້າ (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ຖ້າ (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			bha_nga;
		pak_sa 'S':
			Sflag = 1;
			bha_nga;
		pak_sa 'T':
			errstr = NULL;
			errno = 0;
			ຖ້າ (map_tos(optarg, &Tflag))
				bha_nga;
			ຖ້າ (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (ຈຳນວນເຕັມ)strtol(optarg, NULL, 16);
			ບໍ່ດັ່ງນັ້ນ
				Tflag = (ຈຳນວນເຕັມ)strtonum(optarg, 0, 255,
				    &errstr);
			ຖ້າ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			bha_nga;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ຖ້າ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = NULL;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (argv[0] && !argv[1]) {
		ຖ້າ  (!lflag)
			usage(1);
		uport = argv[0];
		host = NULL;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} ບໍ່ດັ່ງນັ້ນ
		usage(1);

	ຖ້າ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ຖ້າ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ຖ້າ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ຖ້າ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ຖ້າ ((family == AF_UNIX) && uflag && !lflag) {
		ຖ້າ (sflag) {
			unix_dg_tmp_socket = sflag;
		} ບໍ່ດັ່ງນັ້ນ {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			ຖ້າ (mktemp(unix_dg_tmp_socket_buf) == NULL)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ຖ້າ (family != AF_UNIX) {
		memset(&hints, 0, parimaa_na(sa_nracanaa addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ຖ້າ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ຖ້າ (xflag) {
		ຖ້າ (uflag)
			errx(1, "no proxy support for UDP mode");

		ຖ້າ (lflag)
			errx(1, "no proxy support for listen");

		ຖ້າ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ຖ້າ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ຖ້າ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, parimaa_na(sa_nracanaa addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ຖ້າ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ຖ້າ (lflag) {
		ຈຳນວນເຕັມ connfd;
		ret = 0;

		ຖ້າ (family == AF_UNIX) {
			ຖ້າ (uflag)
				s = unix_bind(host);
			ບໍ່ດັ່ງນັ້ນ
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		ສຳລັບ (;;) {
			ຖ້າ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ຖ້າ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ຖ້າ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (uflag && !kflag) {
				ຈຳນວນເຕັມ rv, plen;
				var_na buf[16384];
				sa_nracanaa sockaddr_storage z;

				len = parimaa_na(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (sa_nracanaa sockaddr *)&z, &len);
				ຖ້າ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (sa_nracanaa sockaddr *)&z, len);
				ຖ້າ (rv < 0)
					err(1, "connect");

				ຖ້າ (vflag)
					report_connect((sa_nracanaa sockaddr *)&z, len);

				readwrite(s);
			} ບໍ່ດັ່ງນັ້ນ {
				len = parimaa_na(cliaddr);
				connfd = accept(s, (sa_nracanaa sockaddr *)&cliaddr,
				    &len);
				ຖ້າ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ຖ້າ (vflag)
					report_connect((sa_nracanaa sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ຖ້າ (family != AF_UNIX)
				close(s);
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (uflag) {
				ຖ້າ (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}

			ຖ້າ (!kflag)
				bha_nga;
		}
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (family == AF_UNIX) {
		ret = 0;

		ຖ້າ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} ບໍ່ດັ່ງນັ້ນ
			ret = 1;

		ຖ້າ (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);

	} ບໍ່ດັ່ງນັ້ນ {
		ຈຳນວນເຕັມ i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		ສຳລັບ (i = 0; portlist[i] != NULL; i++) {
			ຖ້າ (s)
				close(s);

			ຖ້າ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			ບໍ່ດັ່ງນັ້ນ
				s = remote_connect(host, portlist[i], hints);

			ຖ້າ (s < 0)
				continue;

			ret = 0;
			ຖ້າ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ຖ້າ (uflag) {
					ຖ້າ (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				/* Don't look up port if -n. */
				ຖ້າ (nflag)
					sv = NULL;
				ບໍ່ດັ່ງນັ້ນ {
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
			ຖ້າ (Fflag)
				fdpass(s);
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (!zflag)
				readwrite(s);
		}
	}

	ຖ້າ (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
ຈຳນວນເຕັມ
unix_bind(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	ຈຳນວນເຕັມ s;

	/* Create unix domain socket. */
	ຖ້າ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		ສົ່ງຄືນ (-1);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ຖ້າ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ສົ່ງຄືນ (-1);
	}

	ຖ້າ (bind(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ສົ່ງຄືນ (-1);
	}
	ສົ່ງຄືນ (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
ຈຳນວນເຕັມ
unix_connect(var_na *path)
{
	sa_nracanaa sockaddr_un sun_sa;
	ຈຳນວນເຕັມ s;

	ຖ້າ (uflag) {
		ຖ້າ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			ສົ່ງຄືນ (-1);
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			ສົ່ງຄືນ (-1);
	}
	(void)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, parimaa_na(sa_nracanaa sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ຖ້າ (strlcpy(sun_sa.sun_path, path, parimaa_na(sun_sa.sun_path)) >=
	    parimaa_na(sun_sa.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		ສົ່ງຄືນ (-1);
	}
	ຖ້າ (connect(s, (sa_nracanaa sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		ສົ່ງຄືນ (-1);
	}
	ສົ່ງຄືນ (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
ຈຳນວນເຕັມ
unix_listen(var_na *path)
{
	ຈຳນວນເຕັມ s;
	ຖ້າ ((s = unix_bind(path)) < 0)
		ສົ່ງຄືນ (-1);

	ຖ້າ (listen(s, 5) < 0) {
		close(s);
		ສົ່ງຄືນ (-1);
	}
	ສົ່ງຄືນ (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
ຈຳນວນເຕັມ
remote_connect(const var_na *host, const var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	ຈຳນວນເຕັມ s, error;
#ຖ້າ defined(SO_RTABLE) || defined(SO_BINDANY)
	ຈຳນວນເຕັມ on = 1;
#endif

	ຖ້າ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ຖ້າ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ຖ້າ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		ຖ້າ (sflag || pflag) {
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
			ຖ້າ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ຖ້າ (bind(s, (sa_nracanaa sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		ຖ້າ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			bha_nga;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} ໃນຂະນະທີ່ ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	ສົ່ງຄືນ (s);
}

ຈຳນວນເຕັມ
timeout_connect(ຈຳນວນເຕັມ s, const sa_nracanaa sockaddr *name, socklen_t namelen)
{
	sa_nracanaa pollfd pfd;
	socklen_t optlen;
	ຈຳນວນເຕັມ flags = 0, optval;
	ຈຳນວນເຕັມ ret;

	ຖ້າ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ຖ້າ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ຖ້າ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ຖ້າ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = parimaa_na(optval);
			ຖ້າ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} ບໍ່ດັ່ງນັ້ນ
			err(1, "poll failed");
	}

	ຖ້າ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	ສົ່ງຄືນ (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
ຈຳນວນເຕັມ
local_listen(var_na *host, var_na *port, sa_nracanaa addrinfo hints)
{
	sa_nracanaa addrinfo *res, *res0;
	ຈຳນວນເຕັມ s, ret, x = 1;
	ຈຳນວນເຕັມ error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ຖ້າ (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ຖ້າ ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		ຖ້າ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

#ifdef SO_RTABLE
		ຖ້າ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, parimaa_na(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, parimaa_na(x));
		ຖ້າ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, parimaa_na(x));
		ຖ້າ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		ຖ້າ (bind(s, (sa_nracanaa sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			bha_nga;

		close(s);
		s = -1;
	} ໃນຂະນະທີ່ ((res0 = res0->ai_next) != NULL);

	ຖ້າ (!uflag && s != -1) {
		ຖ້າ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	ສົ່ງຄືນ (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(ຈຳນວນເຕັມ net_fd)
{
	sa_nracanaa pollfd pfd[4];
	ຈຳນວນເຕັມ stdin_fd = STDIN_FILENO;
	ຈຳນວນເຕັມ stdout_fd = STDOUT_FILENO;
	unsigned var_na netinbuf[BUFSIZE];
	size_t netinbufpos = 0;
	unsigned var_na stdinbuf[BUFSIZE];
	size_t stdinbufpos = 0;
	ຈຳນວນເຕັມ n, num_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ຖ້າ (dflag)
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

	ໃນຂະນະທີ່ (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ຖ້າ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ສົ່ງຄືນ;
		}
		/* both outputs are gone, we can't continue */
		ຖ້າ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			ສົ່ງຄືນ;
		}
		/* listen and net in gone, queues empty, done */
		ຖ້າ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			ສົ່ງຄືນ;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ຖ້າ (iflag)
			sleep(iflag);

		/* poll */
		num_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ຖ້າ (num_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ຖ້າ (num_fds == 0)
			ສົ່ງຄືນ;

		/* treat socket error conditions */
		ສຳລັບ (n = 0; n < 4; n++) {
			ຖ້າ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ຖ້າ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ຖ້າ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ຖ້າ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ຖ້າ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ຖ້າ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ຖ້າ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ຖ້າ (pfd[POLL_STDOUT].fd == -1) {
			ຖ້າ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ຖ້າ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ຖ້າ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ຖ້າ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ຖ້າ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ຖ້າ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ຖ້າ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ຖ້າ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ຖ້າ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ຖ້າ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ຖ້າ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ຖ້າ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ຖ້າ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ຖ້າ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ຖ້າ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ຖ້າ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ຖ້າ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ຖ້າ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ຖ້າ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ຖ້າ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ຖ້າ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ຖ້າ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(ຈຳນວນເຕັມ fd, unsigned var_na *buf, size_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = write(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ຖ້າ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ຖ້າ (n <= 0)
		ສົ່ງຄືນ n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ຖ້າ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	ສົ່ງຄືນ n;
}


ssize_t
fillbuf(ຈຳນວນເຕັມ fd, unsigned var_na *buf, size_t *bufpos)
{
	size_t num = BUFSIZE - *bufpos;
	ssize_t n;

	n = read(fd, buf + *bufpos, num);
	/* don't treat EAGAIN, EINTR as error */
	ຖ້າ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ຖ້າ (n <= 0)
		ສົ່ງຄືນ n;
	*bufpos += n;
	ສົ່ງຄືນ n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
void
fdpass(ຈຳນວນເຕັມ nfd)
{
#ຖ້າ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	sa_nracanaa msghdr msg;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	sa_ngha {
		sa_nracanaa cmsghdr hdr;
		var_na buf[CMSG_SPACE(parimaa_na(ຈຳນວນເຕັມ))];
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
#ບໍ່ດັ່ງນັ້ນ
	memset(&cmsgbuf, 0, parimaa_na(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = parimaa_na(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(parimaa_na(ຈຳນວນເຕັມ));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(ຈຳນວນເຕັມ *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	bzero(&pfd, parimaa_na(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	ສຳລັບ (;;) {
		r = sendmsg(STDOUT_FILENO, &msg, 0);
		ຖ້າ (r == -1) {
			ຖ້າ (errno == EAGAIN || errno == EINTR) {
				ຖ້າ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "sendmsg");
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		ບໍ່ດັ່ງນັ້ນ
			bha_nga;
	}
	exit(0);
#ບໍ່ດັ່ງນັ້ນ
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(ຈຳນວນເຕັມ nfd, unsigned var_na *buf, unsigned ຈຳນວນເຕັມ size)
{
	unsigned var_na *p, *end;
	unsigned var_na obuf[4];

	ຖ້າ (size < 3)
		ສົ່ງຄືນ;
	end = buf + size - 2;

	ສຳລັບ (p = buf; p < end; p++) {
		ຖ້າ (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		ຖ້າ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		ບໍ່ດັ່ງນັ້ນ
			continue;

		p++;
		obuf[2] = *p;
		ຖ້າ (atomicio(vwrite, nfd, obuf, 3) != 3)
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
	ຈຳນວນເຕັມ hi, lo, cp;
	ຈຳນວນເຕັມ x = 0;

	ຖ້າ ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		ຖ້າ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		ຖ້າ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ຖ້າ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		ສຳລັບ (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			ຖ້າ (portlist[x] == NULL)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ຖ້າ (rflag) {
			ຈຳນວນເຕັມ y;
			var_na *c;

			ສຳລັບ (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} ບໍ່ດັ່ງນັ້ນ {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		ຖ້າ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ຖ້າ (portlist[0] == NULL)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
ຈຳນວນເຕັມ
udptest(ຈຳນວນເຕັມ s)
{
	ຈຳນວນເຕັມ i, ret;

	ສຳລັບ (i = 0; i <= 3; i++) {
		ຖ້າ (write(s, "X", 1) == 1)
			ret = 1;
		ບໍ່ດັ່ງນັ້ນ
			ret = -1;
	}
	ສົ່ງຄືນ (ret);
}

void
set_common_sockopts(ຈຳນວນເຕັມ s, ຈຳນວນເຕັມ af)
{
	ຈຳນວນເຕັມ x = 1;

#ifdef TCP_MD5SIG
	ຖ້າ (Sflag) {
		ຖ້າ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	ຖ້າ (Dflag) {
		ຖ້າ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, parimaa_na(x)) == -1)
			err(1, "setsockopt");
	}
#ຖ້າ defined(IP_TOS) && defined(IPV6_TCLASS)
	ຖ້າ (Tflag != -1) {
		ຈຳນວນເຕັມ proto, option;

		ຖ້າ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} ບໍ່ດັ່ງນັ້ນ {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ຖ້າ (setsockopt(s, proto, option, &Tflag, parimaa_na(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	ຖ້າ (Iflag) {
		ຖ້າ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, parimaa_na(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ຖ້າ (Oflag) {
		ຖ້າ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, parimaa_na(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

ຈຳນວນເຕັມ
map_tos(var_na *s, ຈຳນວນເຕັມ *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	const sa_nracanaa toskeywords {
		const var_na	*keyword;
		ຈຳນວນເຕັມ		 val;
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

	ສຳລັບ (t = toskeywords; t->keyword != NULL; t++) {
		ຖ້າ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			ສົ່ງຄືນ (1);
		}
	}
#endif

	ສົ່ງຄືນ (0);
}

void
report_connect(const sa_nracanaa sockaddr *sa, socklen_t salen)
{
	var_na remote_host[NI_MAXHOST];
	var_na remote_port[NI_MAXSERV];
	ຈຳນວນເຕັມ herr;
	ຈຳນວນເຕັມ flags = NI_NUMERICSERV;
	
	ຖ້າ (nflag)
		flags |= NI_NUMERICHOST;
	
	ຖ້າ ((herr = getnameinfo(sa, salen,
	    remote_host, parimaa_na(remote_host),
	    remote_port, parimaa_na(remote_port),
	    flags)) != 0) {
		ຖ້າ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		ບໍ່ດັ່ງນັ້ນ
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
	\t-i secs\t	Delay interval ສຳລັບ lines sent, ports scanned\n\
	\t-k		Keep inbound sockets open ສຳລັບ multiple connects\n\
	\t-l		Listen mode, ສຳລັບ inbound connects\n\
	\t-N		Shutdown the network socket after EOF on stdin\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername ສຳລັບ proxy authentication\n\
	\t-p port\t	Specify local port ສຳລັບ remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout ສຳລັບ connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used ສຳລັບ scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(1);
}

void
usage(ຈຳນວນເຕັມ ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ຖ້າ (ret)
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

ຈຳນວນເຕັມ	remote_connect(const var_na *, const var_na *, sa_nracanaa addrinfo);
ຈຳນວນເຕັມ	socks_connect(const var_na *, const var_na *, sa_nracanaa addrinfo,
	    const var_na *, const var_na *, sa_nracanaa addrinfo, ຈຳນວນເຕັມ,
	    const var_na *);

static ຈຳນວນເຕັມ
decode_addrport(const var_na *h, const var_na *p, sa_nracanaa sockaddr *addr,
    socklen_t addrlen, ຈຳນວນເຕັມ v4only, ຈຳນວນເຕັມ numeric)
{
	ຈຳນວນເຕັມ r;
	sa_nracanaa addrinfo hints, *res;

	bzero(&hints, parimaa_na(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ຖ້າ (r != 0) {
		ຖ້າ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		ສົ່ງຄືນ (-1);
	}
	ຖ້າ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	ສົ່ງຄືນ (0);
}

static ຈຳນວນເຕັມ
proxy_read_line(ຈຳນວນເຕັມ fd, var_na *buf, size_t bufsz)
{
	size_t off;

	ສຳລັບ(off = 0;;) {
		ຖ້າ (off >= bufsz)
			errx(1, "proxy read too long");
		ຖ້າ (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ຖ້າ (buf[off] == '\r')
			continue;
		ຖ້າ (buf[off] == '\n') {
			buf[off] = '\0';
			bha_nga;
		}
		off++;
	}
	ສົ່ງຄືນ (off);
}

static const var_na *
getproxypass(const var_na *proxyuser, const var_na *proxyhost)
{
	var_na prompt[512];
	static var_na pw[256];

	snprintf(prompt, parimaa_na(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ຖ້າ (readpassphrase(prompt, pw, parimaa_na(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	ສົ່ງຄືນ (pw);
}

ຈຳນວນເຕັມ
socks_connect(const var_na *host, const var_na *port,
    sa_nracanaa addrinfo hints __attribute__ ((__unused__)),
    const var_na *proxyhost, const var_na *proxyport, sa_nracanaa addrinfo proxyhints,
    ຈຳນວນເຕັມ socksv, const var_na *proxyuser)
{
	ຈຳນວນເຕັມ proxyfd, r, authretry = 0;
	size_t hlen, wlen = 0;
	unsigned var_na buf[1024];
	size_t cnt;
	sa_nracanaa sockaddr_storage addr;
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)&addr;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)&addr;
	in_port_t serverport;
	const var_na *proxypass = NULL;

	ຖ້າ (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	ຖ້າ (decode_addrport("0.0.0.0", port, (sa_nracanaa sockaddr *)&addr,
	    parimaa_na(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	ຖ້າ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ຖ້າ (proxyfd < 0)
		ສົ່ງຄືນ (-1);

	ຖ້າ (socksv == 5) {
		ຖ້າ (decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
		    parimaa_na(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ຖ້າ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		ຖ້າ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ຖ້າ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		pak_sa 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			ຖ້າ (hlen > 255)
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
		ຖ້າ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		ຖ້າ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ຖ້າ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		pak_sa SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			ຖ້າ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			bha_nga;
		pak_sa SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			ຖ້າ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			bha_nga;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (socksv == 4 || socksv == 44) {
		ຖ້າ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (sa_nracanaa sockaddr *)&addr,
			    parimaa_na(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, parimaa_na in4->sin_port);
		ຖ້າ (socksv == 4) {
			memcpy(buf + 4, &in4->sin_addr, parimaa_na in4->sin_addr);
		} ບໍ່ດັ່ງນັ້ນ {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ຖ້າ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ຖ້າ (strlcpy(buf + 9, host,
			    parimaa_na(buf) - 9) >= parimaa_na(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + strlen(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ຖ້າ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		ຖ້າ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ຖ້າ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ຖ້າ (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ຖ້າ (strchr(host, ':') != NULL) {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} ບໍ່ດັ່ງນັ້ນ {
			r = snprintf(buf, parimaa_na(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ຖ້າ (r == -1 || (size_t)r >= parimaa_na(buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ຖ້າ (cnt != (size_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ຖ້າ (authretry > 1) {
			var_na resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, parimaa_na(buf), "%s:%s",
			    proxyuser, proxypass);
			ຖ້າ (r == -1 || (size_t)r >= parimaa_na(buf) ||
			    b64_ntop(buf, strlen(buf), resp,
			    parimaa_na(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, parimaa_na(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ຖ້າ (r == -1 || (size_t)r >= parimaa_na(buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			ຖ້າ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (size_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ຖ້າ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, buf, parimaa_na(buf));
		ຖ້າ (proxyuser != NULL &&
		    strncmp(buf, "HTTP/1.0 407 ", 12) == 0) {
			ຖ້າ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strncmp(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		ສຳລັບ (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_line(proxyfd, buf, parimaa_na(buf));
			ຖ້າ (*buf == '\0')
				bha_nga;
		}
		ຖ້າ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} ບໍ່ດັ່ງນັ້ນ
		errx(1, "Unknown proxy protocol %d", socksv);

	ສົ່ງຄືນ (proxyfd);
}

