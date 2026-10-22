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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/uio.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/tcp.h>
#अन्तर्भाव <netinet/ip.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव "atomicio.h"

#अन्तर्भाव <poll.h>
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
	(आकार(*(su)) - आकार((su)->sun_path) + म_माप((su)->sun_path))
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
पूर्णांक	dflag;					/* detached, no stdin */
पूर्णांक	Fflag;					/* fdpass sock to stdout */
अचिन्हित पूर्णांक iflag;				/* Interval Flag */
पूर्णांक	kflag;					/* More than one connect */
पूर्णांक	lflag;					/* Bind to local port */
पूर्णांक	Nflag;					/* shutdown() network socket */
पूर्णांक	nflag;					/* Don't do name look up */
अक्षर   *Pflag;					/* Proxy username */
अक्षर   *pflag;					/* Localport flag */
पूर्णांक	rflag;					/* Random ports flag */
अक्षर   *sflag;					/* Source Address */
पूर्णांक	tflag;					/* Telnet Emulation */
पूर्णांक	uflag;					/* UDP - Default to TCP */
पूर्णांक	vflag;					/* Verbosity */
पूर्णांक	xflag;					/* Socks proxy */
पूर्णांक	zflag;					/* Port Scan Flag */
पूर्णांक	Dflag;					/* sodebug */
पूर्णांक	Iflag;					/* TCP receive buffer size */
पूर्णांक	Oflag;					/* TCP send buffer size */
पूर्णांक	Sflag;					/* TCP MD5 signature option */
पूर्णांक	Tflag = -1;				/* IP Type of Service */
पूर्णांक	rtableid = -1;

पूर्णांक timeout = -1;
पूर्णांक family = AF_UNSPEC;
अक्षर *portlist[PORT_MAX+1];
अक्षर *unix_dg_tmp_socket;

शून्य	atelnet(पूर्णांक, अचिन्हित अक्षर *, अचिन्हित पूर्णांक);
शून्य	build_ports(अक्षर *);
शून्य	help(शून्य);
पूर्णांक	local_listen(अक्षर *, अक्षर *, संरचना addrinfo);
शून्य	readwrite(पूर्णांक);
शून्य	fdpass(पूर्णांक nfd) __attribute__((noreturn));
पूर्णांक	remote_connect(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo);
पूर्णांक	timeout_connect(पूर्णांक, स्थिरांक संरचना sockaddr *, socklen_t);
पूर्णांक	socks_connect(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo,
	    स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo, पूर्णांक, स्थिरांक अक्षर *);
पूर्णांक	udptest(पूर्णांक);
पूर्णांक	unix_bind(अक्षर *);
पूर्णांक	unix_connect(अक्षर *);
पूर्णांक	unix_listen(अक्षर *);
शून्य	set_common_sockopts(पूर्णांक, पूर्णांक);
पूर्णांक	map_tos(अक्षर *, पूर्णांक *);
शून्य	report_connect(स्थिरांक संरचना sockaddr *, socklen_t);
शून्य	usage(पूर्णांक);
ssize_t drainbuf(पूर्णांक, अचिन्हित अक्षर *, माप_प्रकार *);
ssize_t fillbuf(पूर्णांक, अचिन्हित अक्षर *, माप_प्रकार *);


पूर्णांक
main(पूर्णांक argc, अक्षर *argv[])
{
	पूर्णांक ch, s, ret, socksv;
	अक्षर *host, *uport;
	संरचना addrinfo hints;
	संरचना servent *sv;
	socklen_t len;
	संरचना sockaddr_storage cliaddr;
	अक्षर *proxy = रिक्त;
	स्थिरांक अक्षर *errstr, *proxyhost = "", *proxyport = रिक्त;
	संरचना addrinfo proxyhints;
	अक्षर unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = रिक्त;
	uport = रिक्त;
	sv = रिक्त;

	संकेत(SIGPIPE, संक_छोड़ो);

	पर्यंत ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		निवड (ch) {
		स्थिती '4':
			family = AF_INET;
			थांबा;
		स्थिती '6':
			family = AF_INET6;
			थांबा;
		स्थिती 'U':
			family = AF_UNIX;
			थांबा;
		स्थिती 'X':
			जर (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			अन्यथा जर (म_भेद(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			अन्यथा जर (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			अन्यथा जर (म_भेद(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			अन्यथा
				errx(1, "unsupported proxy protocol");
			थांबा;
		स्थिती 'd':
			dflag = 1;
			थांबा;
		स्थिती 'F':
			Fflag = 1;
			थांबा;
		स्थिती 'h':
			help();
			थांबा;
		स्थिती 'i':
			iflag = strtonum(optarg, 0, अच_पूर्णांक_उच्च, &errstr);
			जर (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			थांबा;
		स्थिती 'k':
			kflag = 1;
			थांबा;
		स्थिती 'l':
			lflag = 1;
			थांबा;
		स्थिती 'N':
			Nflag = 1;
			थांबा;
		स्थिती 'n':
			nflag = 1;
			थांबा;
		स्थिती 'P':
			Pflag = optarg;
			थांबा;
		स्थिती 'p':
			pflag = optarg;
			थांबा;
		स्थिती 'r':
			rflag = 1;
			थांबा;
		स्थिती 's':
			sflag = optarg;
			थांबा;
		स्थिती 't':
			tflag = 1;
			थांबा;
		स्थिती 'u':
			uflag = 1;
			थांबा;
#ifdef SO_RTABLE
		स्थिती 'V':
			rtableid = (पूर्णांक)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			जर (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			थांबा;
#endif
		स्थिती 'v':
			vflag = 1;
			थांबा;
		स्थिती 'w':
			timeout = strtonum(optarg, 0, पूर्णांक_उच्च / 1000, &errstr);
			जर (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			थांबा;
		स्थिती 'x':
			xflag = 1;
			जर ((proxy = strdup(optarg)) == रिक्त)
				errx(1, "strdup");
			थांबा;
		स्थिती 'z':
			zflag = 1;
			थांबा;
		स्थिती 'D':
			Dflag = 1;
			थांबा;
		स्थिती 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			जर (errstr != रिक्त)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			थांबा;
		स्थिती 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			जर (errstr != रिक्त)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			थांबा;
		स्थिती 'S':
			Sflag = 1;
			थांबा;
		स्थिती 'T':
			errstr = रिक्त;
			त्रुटि_सं = 0;
			जर (map_tos(optarg, &Tflag))
				थांबा;
			जर (म_माप(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (पूर्णांक)म_से_दीर्घ(optarg, रिक्त, 16);
			अन्यथा
				Tflag = (पूर्णांक)strtonum(optarg, 0, 255,
				    &errstr);
			जर (Tflag < 0 || Tflag > 255 || errstr || त्रुटि_सं)
				errx(1, "illegal tos value %s", optarg);
			थांबा;
		पूर्वनिर्धारित:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	जर (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = रिक्त;
	} अन्यथा जर (argv[0] && !argv[1]) {
		जर  (!lflag)
			usage(1);
		uport = argv[0];
		host = रिक्त;
	} अन्यथा जर (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} अन्यथा
		usage(1);

	जर (lflag && sflag)
		errx(1, "cannot use -s and -l");
	जर (lflag && pflag)
		errx(1, "cannot use -p and -l");
	जर (lflag && zflag)
		errx(1, "cannot use -z and -l");
	जर (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	जर ((family == AF_UNIX) && uflag && !lflag) {
		जर (sflag) {
			unix_dg_tmp_socket = sflag;
		} अन्यथा {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			जर (mktemp(unix_dg_tmp_socket_buf) == रिक्त)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	जर (family != AF_UNIX) {
		स_रखो(&hints, 0, आकार(संरचना addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		जर (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	जर (xflag) {
		जर (uflag)
			errx(1, "no proxy support for UDP mode");

		जर (lflag)
			errx(1, "no proxy support for listen");

		जर (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		जर (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		जर (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		स_रखो(&proxyhints, 0, आकार(संरचना addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		जर (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	जर (lflag) {
		पूर्णांक connfd;
		ret = 0;

		जर (family == AF_UNIX) {
			जर (uflag)
				s = unix_bind(host);
			अन्यथा
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		साठी (;;) {
			जर (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			जर (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			जर (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			अन्यथा जर (uflag && !kflag) {
				पूर्णांक rv, plen;
				अक्षर buf[16384];
				संरचना sockaddr_storage z;

				len = आकार(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (संरचना sockaddr *)&z, &len);
				जर (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (संरचना sockaddr *)&z, len);
				जर (rv < 0)
					err(1, "connect");

				जर (vflag)
					report_connect((संरचना sockaddr *)&z, len);

				readwrite(s);
			} अन्यथा {
				len = आकार(cliaddr);
				connfd = accept(s, (संरचना sockaddr *)&cliaddr,
				    &len);
				जर (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				जर (vflag)
					report_connect((संरचना sockaddr *)&cliaddr, len);

				readwrite(connfd);
				बंद(connfd);
			}

			जर (family != AF_UNIX)
				बंद(s);
			अन्यथा जर (uflag) {
				जर (connect(s, रिक्त, 0) < 0)
					err(1, "connect");
			}

			जर (!kflag)
				थांबा;
		}
	} अन्यथा जर (family == AF_UNIX) {
		ret = 0;

		जर ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			बंद(s);
		} अन्यथा
			ret = 1;

		जर (uflag)
			unlink(unix_dg_tmp_socket);
		निकास(ret);

	} अन्यथा {
		पूर्णांक i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		साठी (i = 0; portlist[i] != रिक्त; i++) {
			जर (s)
				बंद(s);

			जर (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			अन्यथा
				s = remote_connect(host, portlist[i], hints);

			जर (s < 0)
				सुरूठेवा;

			ret = 0;
			जर (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				जर (uflag) {
					जर (udptest(s) == -1) {
						ret = 1;
						सुरूठेवा;
					}
				}

				/* Don't look up port if -n. */
				जर (nflag)
					sv = रिक्त;
				अन्यथा {
					sv = getservbyport(
					    ntohs(म_से_प(portlist[i])),
					    uflag ? "udp" : "tcp");
				}

				ख_लिखो(मानक_त्रुटि,
				    "Connection to %s %s port [%s/%s] "
				    "succeeded!\n", host, portlist[i],
				    uflag ? "udp" : "tcp",
				    sv ? sv->s_name : "*");
			}
			जर (Fflag)
				fdpass(s);
			अन्यथा जर (!zflag)
				readwrite(s);
		}
	}

	जर (s)
		बंद(s);

	निकास(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
पूर्णांक
unix_bind(अक्षर *path)
{
	संरचना sockaddr_un sun_sa;
	पूर्णांक s;

	/* Create unix domain socket. */
	जर ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		परत (-1);

	स_रखो(&sun_sa, 0, आकार(संरचना sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	जर (strlcpy(sun_sa.sun_path, path, आकार(sun_sa.sun_path)) >=
	    आकार(sun_sa.sun_path)) {
		बंद(s);
		त्रुटि_सं = ENAMETOOLONG;
		परत (-1);
	}

	जर (bind(s, (संरचना sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		बंद(s);
		परत (-1);
	}
	परत (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
पूर्णांक
unix_connect(अक्षर *path)
{
	संरचना sockaddr_un sun_sa;
	पूर्णांक s;

	जर (uflag) {
		जर ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			परत (-1);
	} अन्यथा {
		जर ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			परत (-1);
	}
	(शून्य)fcntl(s, F_SETFD, FD_CLOEXEC);

	स_रखो(&sun_sa, 0, आकार(संरचना sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	जर (strlcpy(sun_sa.sun_path, path, आकार(sun_sa.sun_path)) >=
	    आकार(sun_sa.sun_path)) {
		बंद(s);
		त्रुटि_सं = ENAMETOOLONG;
		परत (-1);
	}
	जर (connect(s, (संरचना sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		बंद(s);
		परत (-1);
	}
	परत (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
पूर्णांक
unix_listen(अक्षर *path)
{
	पूर्णांक s;
	जर ((s = unix_bind(path)) < 0)
		परत (-1);

	जर (listen(s, 5) < 0) {
		बंद(s);
		परत (-1);
	}
	परत (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
पूर्णांक
remote_connect(स्थिरांक अक्षर *host, स्थिरांक अक्षर *port, संरचना addrinfo hints)
{
	संरचना addrinfo *res, *res0;
	पूर्णांक s, error;
#जर defined(SO_RTABLE) || defined(SO_BINDANY)
	पूर्णांक on = 1;
#endif

	जर ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	करा {
		जर ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			सुरूठेवा;

#ifdef SO_RTABLE
		जर (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, आकार(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
		/* Bind to a local port or source address if specified. */
		जर (sflag || pflag) {
			संरचना addrinfo ahints, *ares;

#ifdef SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, आकार(on));
#endif
			स_रखो(&ahints, 0, आकार(संरचना addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			जर ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			जर (bind(s, (संरचना sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		जर (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			थांबा;
		अन्यथा जर (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		बंद(s);
		s = -1;
	} पर्यंत ((res0 = res0->ai_next) != रिक्त);

	freeaddrinfo(res);

	परत (s);
}

पूर्णांक
timeout_connect(पूर्णांक s, स्थिरांक संरचना sockaddr *name, socklen_t namelen)
{
	संरचना pollfd pfd;
	socklen_t optlen;
	पूर्णांक flags = 0, optval;
	पूर्णांक ret;

	जर (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		जर (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	जर ((ret = connect(s, name, namelen)) != 0 && त्रुटि_सं == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		जर ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = आकार(optval);
			जर ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				त्रुटि_सं = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} अन्यथा जर (ret == 0) {
			त्रुटि_सं = ETIMEDOUT;
			ret = -1;
		} अन्यथा
			err(1, "poll failed");
	}

	जर (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	परत (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
पूर्णांक
local_listen(अक्षर *host, अक्षर *port, संरचना addrinfo hints)
{
	संरचना addrinfo *res, *res0;
	पूर्णांक s, ret, x = 1;
	पूर्णांक error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	जर (host == रिक्त && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	जर ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	करा {
		जर ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			सुरूठेवा;

#ifdef SO_RTABLE
		जर (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, आकार(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#endif
#ifdef SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, आकार(x));
		जर (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#endif
#ifdef SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, आकार(x));
		जर (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#endif
		set_common_sockopts(s, res0->ai_family);

		जर (bind(s, (संरचना sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			थांबा;

		बंद(s);
		s = -1;
	} पर्यंत ((res0 = res0->ai_next) != रिक्त);

	जर (!uflag && s != -1) {
		जर (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	परत (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
शून्य
readwrite(पूर्णांक net_fd)
{
	संरचना pollfd pfd[4];
	पूर्णांक stdin_fd = STDIN_FILENO;
	पूर्णांक stdout_fd = STDOUT_FILENO;
	अचिन्हित अक्षर netinbuf[BUFSIZE];
	माप_प्रकार netinbufpos = 0;
	अचिन्हित अक्षर stdinbuf[BUFSIZE];
	माप_प्रकार stdinbufpos = 0;
	पूर्णांक n, अंक_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	जर (dflag)
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

	पर्यंत (1) {
		/* both inputs are gone, buffers are empty, we are done */
		जर (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			बंद(net_fd);
			परत;
		}
		/* both outputs are gone, we can't continue */
		जर (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			बंद(net_fd);
			परत;
		}
		/* listen and net in gone, queues empty, done */
		जर (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			बंद(net_fd);
			परत;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		जर (iflag)
			sleep(iflag);

		/* poll */
		अंक_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		जर (अंक_fds == -1) {
			बंद(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		जर (अंक_fds == 0)
			परत;

		/* treat socket error conditions */
		साठी (n = 0; n < 4; n++) {
			जर (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		जर (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		जर (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		जर (pfd[POLL_NETOUT].revents & POLLHUP) {
			जर (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		जर (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		जर (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		जर (pfd[POLL_STDOUT].fd == -1) {
			जर (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		जर (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			जर (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			जर (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			जर (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		जर (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			जर (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			जर (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			जर (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		जर (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			जर (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			जर (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			जर (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			जर (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			जर (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		जर (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			जर (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			जर (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			जर (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		जर (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			जर (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		जर (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(पूर्णांक fd, अचिन्हित अक्षर *buf, माप_प्रकार *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = लिख(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	जर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR))
		n = -2;
	जर (n <= 0)
		परत n;
	/* adjust buffer */
	adjust = *bufpos - n;
	जर (adjust > 0)
		स_हटाओ(buf, buf + n, adjust);
	*bufpos -= n;
	परत n;
}


ssize_t
fillbuf(पूर्णांक fd, अचिन्हित अक्षर *buf, माप_प्रकार *bufpos)
{
	माप_प्रकार अंक = BUFSIZE - *bufpos;
	ssize_t n;

	n = पठ(fd, buf + *bufpos, अंक);
	/* don't treat EAGAIN, EINTR as error */
	जर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR))
		n = -2;
	जर (n <= 0)
		परत n;
	*bufpos += n;
	परत n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
शून्य
fdpass(पूर्णांक nfd)
{
#जर defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	संरचना msghdr संदेश;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	संघ {
		संरचना cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(आकार(पूर्णांक))];
	} cmsgbuf;
	संरचना cmsghdr *cmsg;
#endif
	संरचना iovec vec;
	अक्षर ch = '\0';
	संरचना pollfd pfd;
	ssize_t r;

	स_रखो(&संदेश, 0, आकार(संदेश));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&nfd;
	संदेश.संदेश_accrightslen = आकार(nfd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, आकार(cmsgbuf));
	संदेश.msg_control = (caddr_t)&cmsgbuf.buf;
	संदेश.msg_controllen = आकार(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&संदेश);
	cmsg->cmsg_len = CMSG_LEN(आकार(पूर्णांक));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णांक *)CMSG_DATA(cmsg) = nfd;
#endif

	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;

	bzero(&pfd, आकार(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	साठी (;;) {
		r = sendmsg(STDOUT_FILENO, &संदेश, 0);
		जर (r == -1) {
			जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR) {
				जर (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				सुरूठेवा;
			}
			err(1, "sendmsg");
		} अन्यथा जर (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		अन्यथा
			थांबा;
	}
	निकास(0);
#अन्यथा
	errx(1, "%s: file descriptor passing not supported", __func__);
#endif
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
शून्य
atelnet(पूर्णांक nfd, अचिन्हित अक्षर *buf, अचिन्हित पूर्णांक size)
{
	अचिन्हित अक्षर *p, *end;
	अचिन्हित अक्षर obuf[4];

	जर (size < 3)
		परत;
	end = buf + size - 2;

	साठी (p = buf; p < end; p++) {
		जर (*p != IAC)
			सुरूठेवा;

		obuf[0] = IAC;
		p++;
		जर ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		अन्यथा जर ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		अन्यथा
			सुरूठेवा;

		p++;
		obuf[2] = *p;
		जर (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
शून्य
build_ports(अक्षर *p)
{
	स्थिरांक अक्षर *errstr;
	अक्षर *n;
	पूर्णांक hi, lo, cp;
	पूर्णांक x = 0;

	जर ((n = म_अक्षर(p, '-')) != रिक्त) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		जर (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		जर (errstr)
			errx(1, "port number %s: %s", errstr, p);

		जर (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		साठी (cp = lo; cp <= hi; cp++) {
			portlist[x] = सुस्मृति(1, PORT_MAX_LEN);
			जर (portlist[x] == रिक्त)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		जर (rflag) {
			पूर्णांक y;
			अक्षर *c;

			साठी (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} अन्यथा {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		जर (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		जर (portlist[0] == रिक्त)
			errx(1, "strdup");
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
पूर्णांक
udptest(पूर्णांक s)
{
	पूर्णांक i, ret;

	साठी (i = 0; i <= 3; i++) {
		जर (लिख(s, "X", 1) == 1)
			ret = 1;
		अन्यथा
			ret = -1;
	}
	परत (ret);
}

शून्य
set_common_sockopts(पूर्णांक s, पूर्णांक af)
{
	पूर्णांक x = 1;

#ifdef TCP_MD5SIG
	जर (Sflag) {
		जर (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, आकार(x)) == -1)
			err(1, "setsockopt");
	}
#endif
	जर (Dflag) {
		जर (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, आकार(x)) == -1)
			err(1, "setsockopt");
	}
#जर defined(IP_TOS) && defined(IPV6_TCLASS)
	जर (Tflag != -1) {
		पूर्णांक proto, option;

		जर (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} अन्यथा {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		जर (setsockopt(s, proto, option, &Tflag, आकार(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#endif
	जर (Iflag) {
		जर (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, आकार(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	जर (Oflag) {
		जर (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, आकार(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

पूर्णांक
map_tos(अक्षर *s, पूर्णांक *val)
{
#ifdef IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	स्थिरांक संरचना toskeywords {
		स्थिरांक अक्षर	*keyword;
		पूर्णांक		 val;
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
		{ रिक्त, 		-1 },
	};

	साठी (t = toskeywords; t->keyword != रिक्त; t++) {
		जर (म_भेद(s, t->keyword) == 0) {
			*val = t->val;
			परत (1);
		}
	}
#endif

	परत (0);
}

शून्य
report_connect(स्थिरांक संरचना sockaddr *sa, socklen_t salen)
{
	अक्षर remote_host[NI_MAXHOST];
	अक्षर remote_port[NI_MAXSERV];
	पूर्णांक herr;
	पूर्णांक flags = NI_NUMERICSERV;
	
	जर (nflag)
		flags |= NI_NUMERICHOST;
	
	जर ((herr = getnameinfo(sa, salen,
	    remote_host, आकार(remote_host),
	    remote_port, आकार(remote_port),
	    flags)) != 0) {
		जर (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		अन्यथा
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	ख_लिखो(मानक_त्रुटि,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

शून्य
help(शून्य)
{
	usage(0);
	ख_लिखो(मानक_त्रुटि, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from मानक_निवेश\n\
	\t-F		Pass socket fd\n\
	\t-h		This help text\n\
	\t-I length	TCP receive buffer length\n\
	\t-i secs\t	Delay interval साठी ओळी sent, ports scanned\n\
	\t-k		Keep inbound sockets खोलो साठी multiple connects\n\
	\t-l		Listen mode, साठी inbound connects\n\
	\t-N		Shutdown the network socket after खातापूर्ण on मानक_निवेश\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername साठी proxy authentication\n\
	\t-p port\t	Specify local port साठी remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout साठी connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used साठी scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	निकास(1);
}

शून्य
usage(पूर्णांक ret)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	जर (ret)
		निकास(1);
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

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <resolv.h>

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

पूर्णांक	remote_connect(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo);
पूर्णांक	socks_connect(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo,
	    स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना addrinfo, पूर्णांक,
	    स्थिरांक अक्षर *);

स्थिर पूर्णांक
decode_addrport(स्थिरांक अक्षर *h, स्थिरांक अक्षर *p, संरचना sockaddr *addr,
    socklen_t addrlen, पूर्णांक v4only, पूर्णांक numeric)
{
	पूर्णांक r;
	संरचना addrinfo hints, *res;

	bzero(&hints, आकार(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	जर (r != 0) {
		जर (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		परत (-1);
	}
	जर (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	स_नकल(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	परत (0);
}

स्थिर पूर्णांक
proxy_read_ओळ(पूर्णांक fd, अक्षर *buf, माप_प्रकार bufsz)
{
	माप_प्रकार off;

	साठी(off = 0;;) {
		जर (off >= bufsz)
			errx(1, "proxy read too long");
		जर (atomicio(पठ, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		जर (buf[off] == '\r')
			सुरूठेवा;
		जर (buf[off] == '\n') {
			buf[off] = '\0';
			थांबा;
		}
		off++;
	}
	परत (off);
}

स्थिर स्थिरांक अक्षर *
getproxypass(स्थिरांक अक्षर *proxyuser, स्थिरांक अक्षर *proxyhost)
{
	अक्षर prompt[512];
	स्थिर अक्षर pw[256];

	snprintf(prompt, आकार(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	जर (readpassphrase(prompt, pw, आकार(pw), RPP_REQUIRE_TTY) == रिक्त)
		errx(1, "Unable to read proxy passphrase");
	परत (pw);
}

पूर्णांक
socks_connect(स्थिरांक अक्षर *host, स्थिरांक अक्षर *port,
    संरचना addrinfo hints __attribute__ ((__unused__)),
    स्थिरांक अक्षर *proxyhost, स्थिरांक अक्षर *proxyport, संरचना addrinfo proxyhints,
    पूर्णांक socksv, स्थिरांक अक्षर *proxyuser)
{
	पूर्णांक proxyfd, r, authretry = 0;
	माप_प्रकार hlen, wlen = 0;
	अचिन्हित अक्षर buf[1024];
	माप_प्रकार cnt;
	संरचना sockaddr_storage addr;
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)&addr;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)&addr;
	in_port_t serverport;
	स्थिरांक अक्षर *proxypass = रिक्त;

	जर (proxyport == रिक्त)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	जर (decode_addrport("0.0.0.0", port, (संरचना sockaddr *)&addr,
	    आकार(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	जर (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	जर (proxyfd < 0)
		परत (-1);

	जर (socksv == 5) {
		जर (decode_addrport(host, port, (संरचना sockaddr *)&addr,
		    आकार(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		जर (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(पठ, proxyfd, buf, 2);
		जर (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		जर (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		निवड (addr.ss_family) {
		स्थिती 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = म_माप(host);
			जर (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			स_नकल(buf + 5, host, hlen);			
			स_नकल(buf + 5 + hlen, &serverport, आकार serverport);
			wlen = 7 + hlen;
			थांबा;
		स्थिती AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			स_नकल(buf + 4, &in4->sin_addr, आकार in4->sin_addr);
			स_नकल(buf + 8, &in4->sin_port, आकार in4->sin_port);
			wlen = 10;
			थांबा;
		स्थिती AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			स_नकल(buf + 4, &in6->sin6_addr, आकार in6->sin6_addr);
			स_नकल(buf + 20, &in6->sin6_port,
			    आकार in6->sin6_port);
			wlen = 22;
			थांबा;
		पूर्वनिर्धारित:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		जर (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पठ, proxyfd, buf, 4);
		जर (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		जर (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		निवड (buf[3]) {
		स्थिती SOCKS_IPV4:
			cnt = atomicio(पठ, proxyfd, buf + 4, 6);
			जर (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			थांबा;
		स्थिती SOCKS_IPV6:
			cnt = atomicio(पठ, proxyfd, buf + 4, 18);
			जर (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			थांबा;
		पूर्वनिर्धारित:
			errx(1, "connection failed, unsupported address type");
		}
	} अन्यथा जर (socksv == 4 || socksv == 44) {
		जर (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (संरचना sockaddr *)&addr,
			    आकार(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		स_नकल(buf + 2, &in4->sin_port, आकार in4->sin_port);
		जर (socksv == 4) {
			स_नकल(buf + 4, &in4->sin_addr, आकार in4->sin_addr);
		} अन्यथा {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		जर (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			जर (strlcpy(buf + 9, host,
			    आकार(buf) - 9) >= आकार(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + म_माप(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		जर (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पठ, proxyfd, buf, 8);
		जर (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		जर (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} अन्यथा जर (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		जर (म_खोज(host, "\r\n\t []:") != म_माप(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		जर (म_अक्षर(host, ':') != रिक्त) {
			r = snprintf(buf, आकार(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} अन्यथा {
			r = snprintf(buf, आकार(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		जर (r == -1 || (माप_प्रकार)r >= आकार(buf))
			errx(1, "hostname too long");
		r = म_माप(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		जर (cnt != (माप_प्रकार)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		जर (authretry > 1) {
			अक्षर resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, आकार(buf), "%s:%s",
			    proxyuser, proxypass);
			जर (r == -1 || (माप_प्रकार)r >= आकार(buf) ||
			    b64_ntop(buf, म_माप(buf), resp,
			    आकार(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, आकार(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			जर (r == -1 || (माप_प्रकार)r >= आकार(buf))
				errx(1, "Proxy auth response too long");
			r = म_माप(buf);
			जर ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (माप_प्रकार)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		जर ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_ओळ(proxyfd, buf, आकार(buf));
		जर (proxyuser != रिक्त &&
		    म_भेदन(buf, "HTTP/1.0 407 ", 12) == 0) {
			जर (authretry > 1) {
				ख_लिखो(मानक_त्रुटि, "Proxy authentication "
				    "failed\n");
			}
			बंद(proxyfd);
			जा again;
		} अन्यथा जर (म_भेदन(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    म_भेदन(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		साठी (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_ओळ(proxyfd, buf, आकार(buf));
			जर (*buf == '\0')
				थांबा;
		}
		जर (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} अन्यथा
		errx(1, "Unknown proxy protocol %d", socksv);

	परत (proxyfd);
}

