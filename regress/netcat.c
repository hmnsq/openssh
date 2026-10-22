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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/uio.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <netinet/tcp.h>
#అన్తర్భావ <netinet/ip.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ "atomicio.h"

#అన్తర్భావ <poll.h>
#నిర్వచితమైతే HAVE_ERR_H
# include <err.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#అయితే_ముగింపు

/* rename to avoid collision in libssh */
#నిర్వచించు timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#నిర్వచించు IAC	255
#నిర్వచించు DONT	254
#నిర్వచించు DO	253
#నిర్వచించు WONT	252
#నిర్వచించు WILL	251

#నిర్వచితం_కాకపోతే SUN_LEN
#నిర్వచించు SUN_LEN(su) \
	(పరిమాణం(*(su)) - పరిమాణం((su)->sun_మార్గం) + అక్షరశ్రేణి_పొడవు((su)->sun_మార్గం))
#అయితే_ముగింపు

#నిర్వచించు పోర్టు_MAX	65535
#నిర్వచించు పోర్టు_MAX_LEN	6
#నిర్వచించు UNIX_DG_TMP_SOCKET_కొలత	19

#నిర్వచించు POLL_STDIN 0
#నిర్వచించు POLL_NETOUT 1
#నిర్వచించు POLL_NETIN 2
#నిర్వచించు POLL_STDOUT 3
#నిర్వచించు BUFSIZE 16384

/* Command Line Options */
పూర్ణాంకం	dflag;					/* detached, no stdin */
పూర్ణాంకం	Fflag;					/* fdpass sock to stdout */
గుర్తులేని పూర్ణాంకం iflag;				/* Interval Flag */
పూర్ణాంకం	kflag;					/* More than one connect */
పూర్ణాంకం	lflag;					/* Bind to local port */
పూర్ణాంకం	Nflag;					/* shutdown() network socket */
పూర్ణాంకం	nflag;					/* Don't do name look up */
అక్షరం   *Pflag;					/* Proxy username */
అక్షరం   *pflag;					/* Localport flag */
పూర్ణాంకం	rflag;					/* Random ports flag */
అక్షరం   *sflag;					/* Source Address */
పూర్ణాంకం	tflag;					/* Telnet Emulation */
పూర్ణాంకం	uflag;					/* UDP - Default to TCP */
పూర్ణాంకం	vflag;					/* Verbosity */
పూర్ణాంకం	xflag;					/* Socks proxy */
పూర్ణాంకం	zflag;					/* Port Scan Flag */
పూర్ణాంకం	Dflag;					/* sodebug */
పూర్ణాంకం	Iflag;					/* TCP receive buffer size */
పూర్ణాంకం	Oflag;					/* TCP send buffer size */
పూర్ణాంకం	Sflag;					/* TCP MD5 signature option */
పూర్ణాంకం	Tflag = -1;				/* IP Type of Service */
పూర్ణాంకం	rtableid = -1;

పూర్ణాంకం timeout = -1;
పూర్ణాంకం family = AF_UNSPEC;
అక్షరం *portlist[పోర్టు_MAX+1];
అక్షరం *unix_dg_tmp_socket;

శూన్య	atelnet(పూర్ణాంకం, గుర్తులేని అక్షరం *, గుర్తులేని పూర్ణాంకం);
శూన్య	build_ports(అక్షరం *);
శూన్య	help(శూన్య);
పూర్ణాంకం	local_listen(అక్షరం *, అక్షరం *, నిర్మాణం addrinfo);
శూన్య	readwrite(పూర్ణాంకం);
శూన్య	fdpass(పూర్ణాంకం nfd) __attribute__((noreturn));
పూర్ణాంకం	remote_connect(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo);
పూర్ణాంకం	timeout_connect(పూర్ణాంకం, స్థిరరాశి నిర్మాణం sockaddr *, socklen_t);
పూర్ణాంకం	socks_connect(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo,
	    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo, పూర్ణాంకం, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	udptest(పూర్ణాంకం);
పూర్ణాంకం	unix_bind(అక్షరం *);
పూర్ణాంకం	unix_connect(అక్షరం *);
పూర్ణాంకం	unix_listen(అక్షరం *);
శూన్య	సమితి_common_sockopts(పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	map_tos(అక్షరం *, పూర్ణాంకం *);
శూన్య	report_connect(స్థిరరాశి నిర్మాణం sockaddr *, socklen_t);
శూన్య	usage(పూర్ణాంకం);
ssize_t drainbuf(పూర్ణాంకం, గుర్తులేని అక్షరం *, కొలత_t *);
ssize_t fillbuf(పూర్ణాంకం, గుర్తులేని అక్షరం *, కొలత_t *);


పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం *argv[])
{
	పూర్ణాంకం ch, s, ret, socksv;
	అక్షరం *host, *uport;
	నిర్మాణం addrinfo hints;
	నిర్మాణం servent *sv;
	socklen_t len;
	నిర్మాణం sockaddr_storage cliaddr;
	అక్షరం *proxy = ఖాళీ;
	స్థిరరాశి అక్షరం *errstr, *proxyhost = "", *proxyport = ఖాళీ;
	నిర్మాణం addrinfo proxyhints;
	అక్షరం unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_కొలత];

	ret = 1;
	s = 0;
	socksv = 5;
	host = ఖాళీ;
	uport = ఖాళీ;
	sv = ఖాళీ;

	సంకేతం(SIGPIPE, SIG_IGN);

	అయితే ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		ఎంపిక (ch) {
		స్థితి '4':
			family = AF_INET;
			ఆపు;
		స్థితి '6':
			family = AF_INET6;
			ఆపు;
		స్థితి 'U':
			family = AF_UNIX;
			ఆపు;
		స్థితి 'X':
			ఒకవేళ (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			లేకపోతే ఒకవేళ (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			లేకపోతే ఒకవేళ (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			లేకపోతే ఒకవేళ (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			లేకపోతే
				errx(1, "unsupported proxy protocol");
			ఆపు;
		స్థితి 'd':
			dflag = 1;
			ఆపు;
		స్థితి 'F':
			Fflag = 1;
			ఆపు;
		స్థితి 'h':
			help();
			ఆపు;
		స్థితి 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			ఒకవేళ (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			ఆపు;
		స్థితి 'k':
			kflag = 1;
			ఆపు;
		స్థితి 'l':
			lflag = 1;
			ఆపు;
		స్థితి 'N':
			Nflag = 1;
			ఆపు;
		స్థితి 'n':
			nflag = 1;
			ఆపు;
		స్థితి 'P':
			Pflag = optarg;
			ఆపు;
		స్థితి 'p':
			pflag = optarg;
			ఆపు;
		స్థితి 'r':
			rflag = 1;
			ఆపు;
		స్థితి 's':
			sflag = optarg;
			ఆపు;
		స్థితి 't':
			tflag = 1;
			ఆపు;
		స్థితి 'u':
			uflag = 1;
			ఆపు;
#నిర్వచితమైతే SO_RTABLE
		స్థితి 'V':
			rtableid = (పూర్ణాంకం)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			ఒకవేళ (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			ఆపు;
#అయితే_ముగింపు
		స్థితి 'v':
			vflag = 1;
			ఆపు;
		స్థితి 'w':
			timeout = strtonum(optarg, 0, గరిష్ఠ_పూర్ణాంకం / 1000, &errstr);
			ఒకవేళ (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			ఆపు;
		స్థితి 'x':
			xflag = 1;
			ఒకవేళ ((proxy = strdup(optarg)) == ఖాళీ)
				errx(1, "strdup");
			ఆపు;
		స్థితి 'z':
			zflag = 1;
			ఆపు;
		స్థితి 'D':
			Dflag = 1;
			ఆపు;
		స్థితి 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ఒకవేళ (errstr != ఖాళీ)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			ఆపు;
		స్థితి 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			ఒకవేళ (errstr != ఖాళీ)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			ఆపు;
		స్థితి 'S':
			Sflag = 1;
			ఆపు;
		స్థితి 'T':
			errstr = ఖాళీ;
			errno = 0;
			ఒకవేళ (map_tos(optarg, &Tflag))
				ఆపు;
			ఒకవేళ (అక్షరశ్రేణి_పొడవు(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (పూర్ణాంకం)strtol(optarg, ఖాళీ, 16);
			లేకపోతే
				Tflag = (పూర్ణాంకం)strtonum(optarg, 0, 255,
				    &errstr);
			ఒకవేళ (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			ఆపు;
		అప్రమేయ:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	ఒకవేళ (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = ఖాళీ;
	} లేకపోతే ఒకవేళ (argv[0] && !argv[1]) {
		ఒకవేళ  (!lflag)
			usage(1);
		uport = argv[0];
		host = ఖాళీ;
	} లేకపోతే ఒకవేళ (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} లేకపోతే
		usage(1);

	ఒకవేళ (lflag && sflag)
		errx(1, "cannot use -s and -l");
	ఒకవేళ (lflag && pflag)
		errx(1, "cannot use -p and -l");
	ఒకవేళ (lflag && zflag)
		errx(1, "cannot use -z and -l");
	ఒకవేళ (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	ఒకవేళ ((family == AF_UNIX) && uflag && !lflag) {
		ఒకవేళ (sflag) {
			unix_dg_tmp_socket = sflag;
		} లేకపోతే {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_కొలత);
			ఒకవేళ (mktemp(unix_dg_tmp_socket_buf) == ఖాళీ)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	ఒకవేళ (family != AF_UNIX) {
		memset(&hints, 0, పరిమాణం(నిర్మాణం addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		ఒకవేళ (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	ఒకవేళ (xflag) {
		ఒకవేళ (uflag)
			errx(1, "no proxy support for UDP mode");

		ఒకవేళ (lflag)
			errx(1, "no proxy support for listen");

		ఒకవేళ (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		ఒకవేళ (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		ఒకవేళ (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		memset(&proxyhints, 0, పరిమాణం(నిర్మాణం addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		ఒకవేళ (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	ఒకవేళ (lflag) {
		పూర్ణాంకం connfd;
		ret = 0;

		ఒకవేళ (family == AF_UNIX) {
			ఒకవేళ (uflag)
				s = unix_bind(host);
			లేకపోతే
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		కొరకు (;;) {
			ఒకవేళ (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			ఒకవేళ (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			ఒకవేళ (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			లేకపోతే ఒకవేళ (uflag && !kflag) {
				పూర్ణాంకం rv, plen;
				అక్షరం buf[16384];
				నిర్మాణం sockaddr_storage z;

				len = పరిమాణం(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (నిర్మాణం sockaddr *)&z, &len);
				ఒకవేళ (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (నిర్మాణం sockaddr *)&z, len);
				ఒకవేళ (rv < 0)
					err(1, "connect");

				ఒకవేళ (vflag)
					report_connect((నిర్మాణం sockaddr *)&z, len);

				readwrite(s);
			} లేకపోతే {
				len = పరిమాణం(cliaddr);
				connfd = accept(s, (నిర్మాణం sockaddr *)&cliaddr,
				    &len);
				ఒకవేళ (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				ఒకవేళ (vflag)
					report_connect((నిర్మాణం sockaddr *)&cliaddr, len);

				readwrite(connfd);
				close(connfd);
			}

			ఒకవేళ (family != AF_UNIX)
				close(s);
			లేకపోతే ఒకవేళ (uflag) {
				ఒకవేళ (connect(s, ఖాళీ, 0) < 0)
					err(1, "connect");
			}

			ఒకవేళ (!kflag)
				ఆపు;
		}
	} లేకపోతే ఒకవేళ (family == AF_UNIX) {
		ret = 0;

		ఒకవేళ ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			close(s);
		} లేకపోతే
			ret = 1;

		ఒకవేళ (uflag)
			unlink(unix_dg_tmp_socket);
		నిష్క్రమించు(ret);

	} లేకపోతే {
		పూర్ణాంకం i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		కొరకు (i = 0; portlist[i] != ఖాళీ; i++) {
			ఒకవేళ (s)
				close(s);

			ఒకవేళ (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			లేకపోతే
				s = remote_connect(host, portlist[i], hints);

			ఒకవేళ (s < 0)
				కొనసాగు;

			ret = 0;
			ఒకవేళ (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				ఒకవేళ (uflag) {
					ఒకవేళ (udptest(s) == -1) {
						ret = 1;
						కొనసాగు;
					}
				}

				/* Don't look up port if -n. */
				ఒకవేళ (nflag)
					sv = ఖాళీ;
				లేకపోతే {
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
			ఒకవేళ (Fflag)
				fdpass(s);
			లేకపోతే ఒకవేళ (!zflag)
				readwrite(s);
		}
	}

	ఒకవేళ (s)
		close(s);

	నిష్క్రమించు(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
పూర్ణాంకం
unix_bind(అక్షరం *మార్గం)
{
	నిర్మాణం sockaddr_un sun_sa;
	పూర్ణాంకం s;

	/* Create unix domain socket. */
	ఒకవేళ ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		తిరిగి (-1);

	memset(&sun_sa, 0, పరిమాణం(నిర్మాణం sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ఒకవేళ (strlcpy(sun_sa.sun_మార్గం, మార్గం, పరిమాణం(sun_sa.sun_మార్గం)) >=
	    పరిమాణం(sun_sa.sun_మార్గం)) {
		close(s);
		errno = ENAMETOOLONG;
		తిరిగి (-1);
	}

	ఒకవేళ (bind(s, (నిర్మాణం sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		తిరిగి (-1);
	}
	తిరిగి (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
పూర్ణాంకం
unix_connect(అక్షరం *మార్గం)
{
	నిర్మాణం sockaddr_un sun_sa;
	పూర్ణాంకం s;

	ఒకవేళ (uflag) {
		ఒకవేళ ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			తిరిగి (-1);
	} లేకపోతే {
		ఒకవేళ ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			తిరిగి (-1);
	}
	(శూన్య)fcntl(s, F_SETFD, FD_CLOEXEC);

	memset(&sun_sa, 0, పరిమాణం(నిర్మాణం sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	ఒకవేళ (strlcpy(sun_sa.sun_మార్గం, మార్గం, పరిమాణం(sun_sa.sun_మార్గం)) >=
	    పరిమాణం(sun_sa.sun_మార్గం)) {
		close(s);
		errno = ENAMETOOLONG;
		తిరిగి (-1);
	}
	ఒకవేళ (connect(s, (నిర్మాణం sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		close(s);
		తిరిగి (-1);
	}
	తిరిగి (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
పూర్ణాంకం
unix_listen(అక్షరం *మార్గం)
{
	పూర్ణాంకం s;
	ఒకవేళ ((s = unix_bind(మార్గం)) < 0)
		తిరిగి (-1);

	ఒకవేళ (listen(s, 5) < 0) {
		close(s);
		తిరిగి (-1);
	}
	తిరిగి (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
పూర్ణాంకం
remote_connect(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *పోర్టు, నిర్మాణం addrinfo hints)
{
	నిర్మాణం addrinfo *res, *res0;
	పూర్ణాంకం s, error;
#ఒకవేళ defined(SO_RTABLE) || defined(SO_BINDANY)
	పూర్ణాంకం on = 1;
#అయితే_ముగింపు

	ఒకవేళ ((error = getaddrinfo(host, పోర్టు, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	చేయి {
		ఒకవేళ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			కొనసాగు;

#నిర్వచితమైతే SO_RTABLE
		ఒకవేళ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, పరిమాణం(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#అయితే_ముగింపు
		/* Bind to a local port or source address if specified. */
		ఒకవేళ (sflag || pflag) {
			నిర్మాణం addrinfo ahints, *ares;

#నిర్వచితమైతే SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, పరిమాణం(on));
#అయితే_ముగింపు
			memset(&ahints, 0, పరిమాణం(నిర్మాణం addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			ఒకవేళ ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			ఒకవేళ (bind(s, (నిర్మాణం sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		సమితి_common_sockopts(s, res0->ai_family);

		ఒకవేళ (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			ఆపు;
		లేకపోతే ఒకవేళ (vflag)
			warn("connect to %s port %s (%s) failed", host, పోర్టు,
			    uflag ? "udp" : "tcp");

		close(s);
		s = -1;
	} అయితే ((res0 = res0->ai_next) != ఖాళీ);

	freeaddrinfo(res);

	తిరిగి (s);
}

పూర్ణాంకం
timeout_connect(పూర్ణాంకం s, స్థిరరాశి నిర్మాణం sockaddr *name, socklen_t namelen)
{
	నిర్మాణం pollfd pfd;
	socklen_t optlen;
	పూర్ణాంకం flags = 0, optval;
	పూర్ణాంకం ret;

	ఒకవేళ (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		ఒకవేళ (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	ఒకవేళ ((ret = connect(s, name, namelen)) != 0 && errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		ఒకవేళ ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = పరిమాణం(optval);
			ఒకవేళ ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				errno = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} లేకపోతే ఒకవేళ (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
		} లేకపోతే
			err(1, "poll failed");
	}

	ఒకవేళ (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	తిరిగి (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
పూర్ణాంకం
local_listen(అక్షరం *host, అక్షరం *పోర్టు, నిర్మాణం addrinfo hints)
{
	నిర్మాణం addrinfo *res, *res0;
	పూర్ణాంకం s, ret, x = 1;
	పూర్ణాంకం error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	ఒకవేళ (host == ఖాళీ && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	ఒకవేళ ((error = getaddrinfo(host, పోర్టు, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	చేయి {
		ఒకవేళ ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			కొనసాగు;

#నిర్వచితమైతే SO_RTABLE
		ఒకవేళ (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, పరిమాణం(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#అయితే_ముగింపు
#నిర్వచితమైతే SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, పరిమాణం(x));
		ఒకవేళ (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#అయితే_ముగింపు
#నిర్వచితమైతే SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, పరిమాణం(x));
		ఒకవేళ (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#అయితే_ముగింపు
		సమితి_common_sockopts(s, res0->ai_family);

		ఒకవేళ (bind(s, (నిర్మాణం sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			ఆపు;

		close(s);
		s = -1;
	} అయితే ((res0 = res0->ai_next) != ఖాళీ);

	ఒకవేళ (!uflag && s != -1) {
		ఒకవేళ (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	తిరిగి (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
శూన్య
readwrite(పూర్ణాంకం net_fd)
{
	నిర్మాణం pollfd pfd[4];
	పూర్ణాంకం stdin_fd = STDIN_FILENO;
	పూర్ణాంకం stdout_fd = STDOUT_FILENO;
	గుర్తులేని అక్షరం netinbuf[BUFSIZE];
	కొలత_t netinbufpos = 0;
	గుర్తులేని అక్షరం stdinbuf[BUFSIZE];
	కొలత_t stdinbufpos = 0;
	పూర్ణాంకం n, అంకె_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	ఒకవేళ (dflag)
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

	అయితే (1) {
		/* both inputs are gone, buffers are empty, we are done */
		ఒకవేళ (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			తిరిగి;
		}
		/* both outputs are gone, we can't continue */
		ఒకవేళ (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			close(net_fd);
			తిరిగి;
		}
		/* listen and net in gone, queues empty, done */
		ఒకవేళ (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			close(net_fd);
			తిరిగి;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		ఒకవేళ (iflag)
			sleep(iflag);

		/* poll */
		అంకె_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		ఒకవేళ (అంకె_fds == -1) {
			close(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		ఒకవేళ (అంకె_fds == 0)
			తిరిగి;

		/* treat socket error conditions */
		కొరకు (n = 0; n < 4; n++) {
			ఒకవేళ (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		ఒకవేళ (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		ఒకవేళ (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		ఒకవేళ (pfd[POLL_NETOUT].revents & POLLHUP) {
			ఒకవేళ (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		ఒకవేళ (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		ఒకవేళ (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		ఒకవేళ (pfd[POLL_STDOUT].fd == -1) {
			ఒకవేళ (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		ఒకవేళ (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			ఒకవేళ (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			ఒకవేళ (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ఒకవేళ (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		ఒకవేళ (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			ఒకవేళ (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ఒకవేళ (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			ఒకవేళ (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		ఒకవేళ (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			ఒకవేళ (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			ఒకవేళ (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			ఒకవేళ (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			ఒకవేళ (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			ఒకవేళ (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		ఒకవేళ (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			ఒకవేళ (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			ఒకవేళ (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			ఒకవేళ (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		ఒకవేళ (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			ఒకవేళ (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		ఒకవేళ (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(పూర్ణాంకం fd, గుర్తులేని అక్షరం *buf, కొలత_t *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = లిఖ(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	ఒకవేళ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ఒకవేళ (n <= 0)
		తిరిగి n;
	/* adjust buffer */
	adjust = *bufpos - n;
	ఒకవేళ (adjust > 0)
		memmove(buf, buf + n, adjust);
	*bufpos -= n;
	తిరిగి n;
}


ssize_t
fillbuf(పూర్ణాంకం fd, గుర్తులేని అక్షరం *buf, కొలత_t *bufpos)
{
	కొలత_t అంకె = BUFSIZE - *bufpos;
	ssize_t n;

	n = పఠ(fd, buf + *bufpos, అంకె);
	/* don't treat EAGAIN, EINTR as error */
	ఒకవేళ (n == -1 && (errno == EAGAIN || errno == EINTR))
		n = -2;
	ఒకవేళ (n <= 0)
		తిరిగి n;
	*bufpos += n;
	తిరిగి n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
శూన్య
fdpass(పూర్ణాంకం nfd)
{
#ఒకవేళ defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_లోపల_MSGHDR) || defined(HAVE_CONTROL_లోపల_MSGHDR))
	నిర్మాణం msghdr సందేశం;
#నిర్వచితం_కాకపోతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సంఘం {
		నిర్మాణం cmsghdr hdr;
		అక్షరం buf[CMSG_SPACE(పరిమాణం(పూర్ణాంకం))];
	} cmsgbuf;
	నిర్మాణం cmsghdr *cmsg;
#అయితే_ముగింపు
	నిర్మాణం iovec vec;
	అక్షరం ch = '\0';
	నిర్మాణం pollfd pfd;
	ssize_t r;

	memset(&సందేశం, 0, పరిమాణం(సందేశం));
#నిర్వచితమైతే HAVE_ACCRIGHTS_లోపల_MSGHDR
	సందేశం.సందేశం_accrights = (caddr_t)&nfd;
	సందేశం.సందేశం_accrightslen = పరిమాణం(nfd);
#లేకపోతే
	memset(&cmsgbuf, 0, పరిమాణం(cmsgbuf));
	సందేశం.msg_control = (caddr_t)&cmsgbuf.buf;
	సందేశం.msg_controllen = పరిమాణం(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&సందేశం);
	cmsg->cmsg_len = CMSG_LEN(పరిమాణం(పూర్ణాంకం));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(పూర్ణాంకం *)CMSG_DATA(cmsg) = nfd;
#అయితే_ముగింపు

	vec.iov_base = &ch;
	vec.iov_len = 1;
	సందేశం.msg_iov = &vec;
	సందేశం.msg_iovlen = 1;

	bzero(&pfd, పరిమాణం(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	కొరకు (;;) {
		r = sendmsg(STDOUT_FILENO, &సందేశం, 0);
		ఒకవేళ (r == -1) {
			ఒకవేళ (errno == EAGAIN || errno == EINTR) {
				ఒకవేళ (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				కొనసాగు;
			}
			err(1, "sendmsg");
		} లేకపోతే ఒకవేళ (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		లేకపోతే
			ఆపు;
	}
	నిష్క్రమించు(0);
#లేకపోతే
	errx(1, "%s: file descriptor passing not supported", __func__);
#అయితే_ముగింపు
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
శూన్య
atelnet(పూర్ణాంకం nfd, గుర్తులేని అక్షరం *buf, గుర్తులేని పూర్ణాంకం కొలత)
{
	గుర్తులేని అక్షరం *p, *చివర;
	గుర్తులేని అక్షరం obuf[4];

	ఒకవేళ (కొలత < 3)
		తిరిగి;
	చివర = buf + కొలత - 2;

	కొరకు (p = buf; p < చివర; p++) {
		ఒకవేళ (*p != IAC)
			కొనసాగు;

		obuf[0] = IAC;
		p++;
		ఒకవేళ ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		లేకపోతే ఒకవేళ ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		లేకపోతే
			కొనసాగు;

		p++;
		obuf[2] = *p;
		ఒకవేళ (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
శూన్య
build_ports(అక్షరం *p)
{
	స్థిరరాశి అక్షరం *errstr;
	అక్షరం *n;
	పూర్ణాంకం hi, lo, cp;
	పూర్ణాంకం x = 0;

	ఒకవేళ ((n = strchr(p, '-')) != ఖాళీ) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, పోర్టు_MAX, &errstr);
		ఒకవేళ (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, పోర్టు_MAX, &errstr);
		ఒకవేళ (errstr)
			errx(1, "port number %s: %s", errstr, p);

		ఒకవేళ (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		కొరకు (cp = lo; cp <= hi; cp++) {
			portlist[x] = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పోర్టు_MAX_LEN);
			ఒకవేళ (portlist[x] == ఖాళీ)
				errx(1, "calloc");
			snprintf(portlist[x], పోర్టు_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		ఒకవేళ (rflag) {
			పూర్ణాంకం y;
			అక్షరం *c;

			కొరకు (x = 0; x <= (hi - lo); x++) {
				y = arc4random_ఏకరీతి(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} లేకపోతే {
		hi = strtonum(p, 1, పోర్టు_MAX, &errstr);
		ఒకవేళ (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		ఒకవేళ (portlist[0] == ఖాళీ)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
పూర్ణాంకం
udptest(పూర్ణాంకం s)
{
	పూర్ణాంకం i, ret;

	కొరకు (i = 0; i <= 3; i++) {
		ఒకవేళ (లిఖ(s, "X", 1) == 1)
			ret = 1;
		లేకపోతే
			ret = -1;
	}
	తిరిగి (ret);
}

శూన్య
సమితి_common_sockopts(పూర్ణాంకం s, పూర్ణాంకం af)
{
	పూర్ణాంకం x = 1;

#నిర్వచితమైతే TCP_MD5SIG
	ఒకవేళ (Sflag) {
		ఒకవేళ (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, పరిమాణం(x)) == -1)
			err(1, "setsockopt");
	}
#అయితే_ముగింపు
	ఒకవేళ (Dflag) {
		ఒకవేళ (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, పరిమాణం(x)) == -1)
			err(1, "setsockopt");
	}
#ఒకవేళ defined(IP_TOS) && defined(IPV6_TCLASS)
	ఒకవేళ (Tflag != -1) {
		పూర్ణాంకం proto, option;

		ఒకవేళ (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} లేకపోతే {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		ఒకవేళ (setsockopt(s, proto, option, &Tflag, పరిమాణం(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#అయితే_ముగింపు
	ఒకవేళ (Iflag) {
		ఒకవేళ (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, పరిమాణం(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	ఒకవేళ (Oflag) {
		ఒకవేళ (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, పరిమాణం(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

పూర్ణాంకం
map_tos(అక్షరం *s, పూర్ణాంకం *val)
{
#నిర్వచితమైతే IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	స్థిరరాశి నిర్మాణం toskeywords {
		స్థిరరాశి అక్షరం	*keyword;
		పూర్ణాంకం		 val;
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
		{ ఖాళీ, 		-1 },
	};

	కొరకు (t = toskeywords; t->keyword != ఖాళీ; t++) {
		ఒకవేళ (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			తిరిగి (1);
		}
	}
#అయితే_ముగింపు

	తిరిగి (0);
}

శూన్య
report_connect(స్థిరరాశి నిర్మాణం sockaddr *sa, socklen_t salen)
{
	అక్షరం remote_host[NI_MAXHOST];
	అక్షరం remote_పోర్టు[NI_MAXSERV];
	పూర్ణాంకం herr;
	పూర్ణాంకం flags = NI_NUMERICSERV;
	
	ఒకవేళ (nflag)
		flags |= NI_NUMERICHOST;
	
	ఒకవేళ ((herr = getnameinfo(sa, salen,
	    remote_host, పరిమాణం(remote_host),
	    remote_పోర్టు, పరిమాణం(remote_పోర్టు),
	    flags)) != 0) {
		ఒకవేళ (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		లేకపోతే
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	fprintf(stderr,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_పోర్టు);
}

శూన్య
help(శూన్య)
{
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n\
	\t-F		Pass socket fd\n\
	\t-h		This help పాఠ్యం\n\
	\t-I నిడివి	TCP receive బఫరు నిడివి\n\
	\t-i secs\t	Delay interval కొరకు పంక్తులు పంపిన, ports scanned\n\
	\t-k		Keep inbound sockets open కొరకు గుణిజం connects\n\
	\t-l		Listen బహుళకం, కొరకు inbound connects\n\
	\t-N		Shutdown the జాలం socket after EOF on stdin\n\
	\t-n		Suppress name/పోర్టు resolutions\n\
	\t-O నిడివి	TCP send బఫరు నిడివి\n\
	\t-P proxyuser\tUsername కొరకు proxy authentication\n\
	\t-p పోర్టు\t	Specify local పోర్టు కొరకు remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local ఆధారం చిరునామా\n\
	\t-T toskeyword\t_సమితి IP Type యొక్క Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP బహుళకం\n\
	\t-V rtable	Specify alternate routing పట్టిక\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout కొరకు connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:పోర్టు]\tSpecify proxy చిరునామా and పోర్టు\n\
	\t-z		Zero-I/O బహుళకం [వాడిన కొరకు scanning]\n\
	పోర్టు_2 numbers can be individual or ranges: lo-hi [inclusive]\n");
	నిష్క్రమించు(1);
}

శూన్య
usage(పూర్ణాంకం ret)
{
	fprintf(stderr,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	ఒకవేళ (ret)
		నిష్క్రమించు(1);
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

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <resolv.h>

#నిర్వచించు SOCKS_పోర్టు	"1080"
#నిర్వచించు HTTP_PROXY_పోర్టు	"3128"
#నిర్వచించు HTTP_MAXHDRS	64
#నిర్వచించు SOCKS_V5	5
#నిర్వచించు SOCKS_V4	4
#నిర్వచించు SOCKS_NOAUTH	0
#నిర్వచించు SOCKS_NOMETHOD	0xff
#నిర్వచించు SOCKS_CONNECT	1
#నిర్వచించు SOCKS_IPV4	1
#నిర్వచించు SOCKS_DOMAIN	3
#నిర్వచించు SOCKS_IPV6	4

పూర్ణాంకం	remote_connect(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo);
పూర్ణాంకం	socks_connect(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo,
	    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం addrinfo, పూర్ణాంకం,
	    స్థిరరాశి అక్షరం *);

స్థిర పూర్ణాంకం
decode_addrport(స్థిరరాశి అక్షరం *h, స్థిరరాశి అక్షరం *p, నిర్మాణం sockaddr *addr,
    socklen_t addrlen, పూర్ణాంకం v4only, పూర్ణాంకం numeric)
{
	పూర్ణాంకం r;
	నిర్మాణం addrinfo hints, *res;

	bzero(&hints, పరిమాణం(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	ఒకవేళ (r != 0) {
		ఒకవేళ (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		తిరిగి (-1);
	}
	ఒకవేళ (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	జ్ఞాపకం_నకలు(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	తిరిగి (0);
}

స్థిర పూర్ణాంకం
proxy_read_పంక్తి(పూర్ణాంకం fd, అక్షరం *buf, కొలత_t bufsz)
{
	కొలత_t off;

	కొరకు(off = 0;;) {
		ఒకవేళ (off >= bufsz)
			errx(1, "proxy read too long");
		ఒకవేళ (atomicio(పఠ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		ఒకవేళ (buf[off] == '\r')
			కొనసాగు;
		ఒకవేళ (buf[off] == '\n') {
			buf[off] = '\0';
			ఆపు;
		}
		off++;
	}
	తిరిగి (off);
}

స్థిర స్థిరరాశి అక్షరం *
getproxypass(స్థిరరాశి అక్షరం *proxyuser, స్థిరరాశి అక్షరం *proxyhost)
{
	అక్షరం prompt[512];
	స్థిర అక్షరం pw[256];

	snprintf(prompt, పరిమాణం(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	ఒకవేళ (readpassphrase(prompt, pw, పరిమాణం(pw), RPP_REQUIRE_TTY) == ఖాళీ)
		errx(1, "Unable to read proxy passphrase");
	తిరిగి (pw);
}

పూర్ణాంకం
socks_connect(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *పోర్టు,
    నిర్మాణం addrinfo hints __attribute__ ((__unused__)),
    స్థిరరాశి అక్షరం *proxyhost, స్థిరరాశి అక్షరం *proxyport, నిర్మాణం addrinfo proxyhints,
    పూర్ణాంకం socksv, స్థిరరాశి అక్షరం *proxyuser)
{
	పూర్ణాంకం proxyfd, r, authretry = 0;
	కొలత_t hlen, wlen = 0;
	గుర్తులేని అక్షరం buf[1024];
	కొలత_t cnt;
	నిర్మాణం sockaddr_storage addr;
	నిర్మాణం sockaddr_in *in4 = (నిర్మాణం sockaddr_in *)&addr;
	నిర్మాణం sockaddr_in6 *in6 = (నిర్మాణం sockaddr_in6 *)&addr;
	in_port_t serverport;
	స్థిరరాశి అక్షరం *proxypass = ఖాళీ;

	ఒకవేళ (proxyport == ఖాళీ)
		proxyport = (socksv == -1) ? HTTP_PROXY_పోర్టు : SOCKS_పోర్టు;

	/* Abuse API to lookup port */
	ఒకవేళ (decode_addrport("0.0.0.0", పోర్టు, (నిర్మాణం sockaddr *)&addr,
	    పరిమాణం(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", పోర్టు);
	serverport = in4->sin_port;

 again:
	ఒకవేళ (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	ఒకవేళ (proxyfd < 0)
		తిరిగి (-1);

	ఒకవేళ (socksv == 5) {
		ఒకవేళ (decode_addrport(host, పోర్టు, (నిర్మాణం sockaddr *)&addr,
		    పరిమాణం(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		ఒకవేళ (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(పఠ, proxyfd, buf, 2);
		ఒకవేళ (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		ఒకవేళ (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		ఎంపిక (addr.ss_family) {
		స్థితి 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = అక్షరశ్రేణి_పొడవు(host);
			ఒకవేళ (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			జ్ఞాపకం_నకలు(buf + 5, host, hlen);			
			జ్ఞాపకం_నకలు(buf + 5 + hlen, &serverport, పరిమాణం serverport);
			wlen = 7 + hlen;
			ఆపు;
		స్థితి AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			జ్ఞాపకం_నకలు(buf + 4, &in4->sin_addr, పరిమాణం in4->sin_addr);
			జ్ఞాపకం_నకలు(buf + 8, &in4->sin_port, పరిమాణం in4->sin_port);
			wlen = 10;
			ఆపు;
		స్థితి AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			జ్ఞాపకం_నకలు(buf + 4, &in6->sin6_addr, పరిమాణం in6->sin6_addr);
			జ్ఞాపకం_నకలు(buf + 20, &in6->sin6_port,
			    పరిమాణం in6->sin6_port);
			wlen = 22;
			ఆపు;
		అప్రమేయ:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ఒకవేళ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(పఠ, proxyfd, buf, 4);
		ఒకవేళ (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		ఒకవేళ (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		ఎంపిక (buf[3]) {
		స్థితి SOCKS_IPV4:
			cnt = atomicio(పఠ, proxyfd, buf + 4, 6);
			ఒకవేళ (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			ఆపు;
		స్థితి SOCKS_IPV6:
			cnt = atomicio(పఠ, proxyfd, buf + 4, 18);
			ఒకవేళ (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			ఆపు;
		అప్రమేయ:
			errx(1, "connection failed, unsupported address type");
		}
	} లేకపోతే ఒకవేళ (socksv == 4 || socksv == 44) {
		ఒకవేళ (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, పోర్టు, (నిర్మాణం sockaddr *)&addr,
			    పరిమాణం(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		జ్ఞాపకం_నకలు(buf + 2, &in4->sin_port, పరిమాణం in4->sin_port);
		ఒకవేళ (socksv == 4) {
			జ్ఞాపకం_నకలు(buf + 4, &in4->sin_addr, పరిమాణం in4->sin_addr);
		} లేకపోతే {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		ఒకవేళ (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			ఒకవేళ (strlcpy(buf + 9, host,
			    పరిమాణం(buf) - 9) >= పరిమాణం(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + అక్షరశ్రేణి_పొడవు(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		ఒకవేళ (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(పఠ, proxyfd, buf, 8);
		ఒకవేళ (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		ఒకవేళ (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} లేకపోతే ఒకవేళ (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		ఒకవేళ (strcspn(host, "\r\n\t []:") != అక్షరశ్రేణి_పొడవు(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		ఒకవేళ (strchr(host, ':') != ఖాళీ) {
			r = snprintf(buf, పరిమాణం(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} లేకపోతే {
			r = snprintf(buf, పరిమాణం(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		ఒకవేళ (r == -1 || (కొలత_t)r >= పరిమాణం(buf))
			errx(1, "hostname too long");
		r = అక్షరశ్రేణి_పొడవు(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		ఒకవేళ (cnt != (కొలత_t)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		ఒకవేళ (authretry > 1) {
			అక్షరం resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, పరిమాణం(buf), "%s:%s",
			    proxyuser, proxypass);
			ఒకవేళ (r == -1 || (కొలత_t)r >= పరిమాణం(buf) ||
			    b64_ntop(buf, అక్షరశ్రేణి_పొడవు(buf), resp,
			    పరిమాణం(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, పరిమాణం(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			ఒకవేళ (r == -1 || (కొలత_t)r >= పరిమాణం(buf))
				errx(1, "Proxy auth response too long");
			r = అక్షరశ్రేణి_పొడవు(buf);
			ఒకవేళ ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (కొలత_t)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		ఒకవేళ ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_పంక్తి(proxyfd, buf, పరిమాణం(buf));
		ఒకవేళ (proxyuser != ఖాళీ &&
		    అక్షరశ్రేణి_పోలిక(buf, "HTTP/1.0 407 ", 12) == 0) {
			ఒకవేళ (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			వెళ్ళు again;
		} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    అక్షరశ్రేణి_పోలిక(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		కొరకు (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_పంక్తి(proxyfd, buf, పరిమాణం(buf));
			ఒకవేళ (*buf == '\0')
				ఆపు;
		}
		ఒకవేళ (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} లేకపోతే
		errx(1, "Unknown proxy protocol %d", socksv);

	తిరిగి (proxyfd);
}

