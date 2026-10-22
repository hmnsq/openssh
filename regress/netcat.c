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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/time.h>
#समावेश <sys/uio.h>
#समावेश <sys/un.h>

#समावेश <netinet/in.h>
#समावेश <netinet/tcp.h>
#समावेश <netinet/ip.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश "atomicio.h"

#समावेश <poll.h>
#अगर_घोषित HAVE_ERR_H
# include <err.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_BYTEORDER_H
# include <sys/byteorder.h>
#पूर्ण_अगर

/* rename to avoid collision in libssh */
#घोषणा timeout_connect netcat_timeout_connect

/* Telnet options from arpa/telnet.h */
#घोषणा IAC	255
#घोषणा DONT	254
#घोषणा DO	253
#घोषणा WONT	252
#घोषणा WILL	251

#अगर_अघोषित SUN_LEN
#घोषणा SUN_LEN(su) \
	(माप(*(su)) - माप((su)->sun_path) + म_माप((su)->sun_path))
#पूर्ण_अगर

#घोषणा PORT_MAX	65535
#घोषणा PORT_MAX_LEN	6
#घोषणा UNIX_DG_TMP_SOCKET_आकार	19

#घोषणा POLL_STDIN 0
#घोषणा POLL_NETOUT 1
#घोषणा POLL_NETIN 2
#घोषणा POLL_STDOUT 3
#घोषणा BUFSIZE 16384

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

व्योम	atelnet(पूर्णांक, अचिन्हित अक्षर *, अचिन्हित पूर्णांक);
व्योम	build_ports(अक्षर *);
व्योम	help(व्योम);
पूर्णांक	local_listen(अक्षर *, अक्षर *, काष्ठा addrinfo);
व्योम	readwrite(पूर्णांक);
व्योम	fdpass(पूर्णांक nfd) __attribute__((noreturn));
पूर्णांक	remote_connect(स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo);
पूर्णांक	timeout_connect(पूर्णांक, स्थिर काष्ठा sockaddr *, socklen_t);
पूर्णांक	socks_connect(स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo,
	    स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo, पूर्णांक, स्थिर अक्षर *);
पूर्णांक	udptest(पूर्णांक);
पूर्णांक	unix_bind(अक्षर *);
पूर्णांक	unix_connect(अक्षर *);
पूर्णांक	unix_listen(अक्षर *);
व्योम	set_common_sockopts(पूर्णांक, पूर्णांक);
पूर्णांक	map_tos(अक्षर *, पूर्णांक *);
व्योम	report_connect(स्थिर काष्ठा sockaddr *, socklen_t);
व्योम	usage(पूर्णांक);
ssize_t drainbuf(पूर्णांक, अचिन्हित अक्षर *, माप_प्रकार *);
ssize_t fillbuf(पूर्णांक, अचिन्हित अक्षर *, माप_प्रकार *);


पूर्णांक
मुख्य(पूर्णांक argc, अक्षर *argv[])
{
	पूर्णांक ch, s, ret, socksv;
	अक्षर *host, *uport;
	काष्ठा addrinfo hints;
	काष्ठा servent *sv;
	socklen_t len;
	काष्ठा sockaddr_storage cliaddr;
	अक्षर *proxy = शून्य;
	स्थिर अक्षर *errstr, *proxyhost = "", *proxyport = शून्य;
	काष्ठा addrinfo proxyhints;
	अक्षर unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_आकार];

	ret = 1;
	s = 0;
	socksv = 5;
	host = शून्य;
	uport = शून्य;
	sv = शून्य;

	संकेत(SIGPIPE, संक_छोड़ो);

	जबतक ((ch = getopt(argc, argv,
	    "46DdFhI:i:klNnO:P:p:rSs:tT:UuV:vw:X:x:z")) != -1) {
		चयन (ch) {
		हाल '4':
			family = AF_INET;
			अवरोध;
		हाल '6':
			family = AF_INET6;
			अवरोध;
		हाल 'U':
			family = AF_UNIX;
			अवरोध;
		हाल 'X':
			अगर (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			अन्यथा अगर (म_भेद(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			अन्यथा अगर (strcasecmp(optarg, "4A") == 0)
				socksv = 44; /* SOCKS v.4A */
			अन्यथा अगर (म_भेद(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			अन्यथा
				errx(1, "unsupported proxy protocol");
			अवरोध;
		हाल 'd':
			dflag = 1;
			अवरोध;
		हाल 'F':
			Fflag = 1;
			अवरोध;
		हाल 'h':
			help();
			अवरोध;
		हाल 'i':
			iflag = strtonum(optarg, 0, अच_पूर्णांक_उच्च, &errstr);
			अगर (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			अवरोध;
		हाल 'k':
			kflag = 1;
			अवरोध;
		हाल 'l':
			lflag = 1;
			अवरोध;
		हाल 'N':
			Nflag = 1;
			अवरोध;
		हाल 'n':
			nflag = 1;
			अवरोध;
		हाल 'P':
			Pflag = optarg;
			अवरोध;
		हाल 'p':
			pflag = optarg;
			अवरोध;
		हाल 'r':
			rflag = 1;
			अवरोध;
		हाल 's':
			sflag = optarg;
			अवरोध;
		हाल 't':
			tflag = 1;
			अवरोध;
		हाल 'u':
			uflag = 1;
			अवरोध;
#अगर_घोषित SO_RTABLE
		हाल 'V':
			rtableid = (पूर्णांक)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			अगर (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
			अवरोध;
#पूर्ण_अगर
		हाल 'v':
			vflag = 1;
			अवरोध;
		हाल 'w':
			timeout = strtonum(optarg, 0, पूर्णांक_उच्च / 1000, &errstr);
			अगर (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			अवरोध;
		हाल 'x':
			xflag = 1;
			अगर ((proxy = strdup(optarg)) == शून्य)
				errx(1, "strdup");
			अवरोध;
		हाल 'z':
			zflag = 1;
			अवरोध;
		हाल 'D':
			Dflag = 1;
			अवरोध;
		हाल 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			अगर (errstr != शून्य)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			अवरोध;
		हाल 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			अगर (errstr != शून्य)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			अवरोध;
		हाल 'S':
			Sflag = 1;
			अवरोध;
		हाल 'T':
			errstr = शून्य;
			त्रुटि_सं = 0;
			अगर (map_tos(optarg, &Tflag))
				अवरोध;
			अगर (म_माप(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (पूर्णांक)म_से_दीर्घ(optarg, शून्य, 16);
			अन्यथा
				Tflag = (पूर्णांक)strtonum(optarg, 0, 255,
				    &errstr);
			अगर (Tflag < 0 || Tflag > 255 || errstr || त्रुटि_सं)
				errx(1, "illegal tos value %s", optarg);
			अवरोध;
		शेष:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
	अगर (argv[0] && !argv[1] && family == AF_UNIX) {
		host = argv[0];
		uport = शून्य;
	} अन्यथा अगर (argv[0] && !argv[1]) {
		अगर  (!lflag)
			usage(1);
		uport = argv[0];
		host = शून्य;
	} अन्यथा अगर (argv[0] && argv[1]) {
		host = argv[0];
		uport = argv[1];
	} अन्यथा
		usage(1);

	अगर (lflag && sflag)
		errx(1, "cannot use -s and -l");
	अगर (lflag && pflag)
		errx(1, "cannot use -p and -l");
	अगर (lflag && zflag)
		errx(1, "cannot use -z and -l");
	अगर (!lflag && kflag)
		errx(1, "must use -l with -k");

	/* Get name of temporary socket for unix datagram client */
	अगर ((family == AF_UNIX) && uflag && !lflag) {
		अगर (sflag) {
			unix_dg_tmp_socket = sflag;
		} अन्यथा {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_आकार);
			अगर (mktemp(unix_dg_tmp_socket_buf) == शून्य)
				err(1, "mktemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	अगर (family != AF_UNIX) {
		स_रखो(&hints, 0, माप(काष्ठा addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
		अगर (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	अगर (xflag) {
		अगर (uflag)
			errx(1, "no proxy support for UDP mode");

		अगर (lflag)
			errx(1, "no proxy support for listen");

		अगर (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		अगर (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		अगर (sflag)
			errx(1, "no proxy support for local source address");

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

		स_रखो(&proxyhints, 0, माप(काष्ठा addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		अगर (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	अगर (lflag) {
		पूर्णांक connfd;
		ret = 0;

		अगर (family == AF_UNIX) {
			अगर (uflag)
				s = unix_bind(host);
			अन्यथा
				s = unix_listen(host);
		}

		/* Allow only one connection at a time, but stay alive. */
		क्रम (;;) {
			अगर (family != AF_UNIX)
				s = local_listen(host, uport, hints);
			अगर (s < 0)
				err(1, "local_listen");
			/*
			 * For UDP and -k, don't connect the socket, let it
			 * receive datagrams from multiple socket pairs.
			 */
			अगर (uflag && kflag)
				readwrite(s);
			/*
			 * For UDP and not -k, we will use recvfrom() initially
			 * to wait for a caller, then use the regular functions
			 * to talk to the caller.
			 */
			अन्यथा अगर (uflag && !kflag) {
				पूर्णांक rv, plen;
				अक्षर buf[16384];
				काष्ठा sockaddr_storage z;

				len = माप(z);
				plen = 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (काष्ठा sockaddr *)&z, &len);
				अगर (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (काष्ठा sockaddr *)&z, len);
				अगर (rv < 0)
					err(1, "connect");

				अगर (vflag)
					report_connect((काष्ठा sockaddr *)&z, len);

				readwrite(s);
			} अन्यथा {
				len = माप(cliaddr);
				connfd = accept(s, (काष्ठा sockaddr *)&cliaddr,
				    &len);
				अगर (connfd == -1) {
					/* For now, all errnos are fatal */
					err(1, "accept");
				}
				अगर (vflag)
					report_connect((काष्ठा sockaddr *)&cliaddr, len);

				readwrite(connfd);
				बंद(connfd);
			}

			अगर (family != AF_UNIX)
				बंद(s);
			अन्यथा अगर (uflag) {
				अगर (connect(s, शून्य, 0) < 0)
					err(1, "connect");
			}

			अगर (!kflag)
				अवरोध;
		}
	} अन्यथा अगर (family == AF_UNIX) {
		ret = 0;

		अगर ((s = unix_connect(host)) > 0 && !zflag) {
			readwrite(s);
			बंद(s);
		} अन्यथा
			ret = 1;

		अगर (uflag)
			unlink(unix_dg_tmp_socket);
		निकास(ret);

	} अन्यथा {
		पूर्णांक i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		क्रम (i = 0; portlist[i] != शून्य; i++) {
			अगर (s)
				बंद(s);

			अगर (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag);
			अन्यथा
				s = remote_connect(host, portlist[i], hints);

			अगर (s < 0)
				जारी;

			ret = 0;
			अगर (vflag || zflag) {
				/* For UDP, make sure we are connected. */
				अगर (uflag) {
					अगर (udptest(s) == -1) {
						ret = 1;
						जारी;
					}
				}

				/* Don't look up port if -n. */
				अगर (nflag)
					sv = शून्य;
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
			अगर (Fflag)
				fdpass(s);
			अन्यथा अगर (!zflag)
				readwrite(s);
		}
	}

	अगर (s)
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
	काष्ठा sockaddr_un sun_sa;
	पूर्णांक s;

	/* Create unix domain socket. */
	अगर ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		वापस (-1);

	स_रखो(&sun_sa, 0, माप(काष्ठा sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	अगर (strlcpy(sun_sa.sun_path, path, माप(sun_sa.sun_path)) >=
	    माप(sun_sa.sun_path)) {
		बंद(s);
		त्रुटि_सं = ENAMETOOLONG;
		वापस (-1);
	}

	अगर (bind(s, (काष्ठा sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		बंद(s);
		वापस (-1);
	}
	वापस (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
पूर्णांक
unix_connect(अक्षर *path)
{
	काष्ठा sockaddr_un sun_sa;
	पूर्णांक s;

	अगर (uflag) {
		अगर ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			वापस (-1);
	} अन्यथा {
		अगर ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			वापस (-1);
	}
	(व्योम)fcntl(s, F_SETFD, FD_CLOEXEC);

	स_रखो(&sun_sa, 0, माप(काष्ठा sockaddr_un));
	sun_sa.sun_family = AF_UNIX;

	अगर (strlcpy(sun_sa.sun_path, path, माप(sun_sa.sun_path)) >=
	    माप(sun_sa.sun_path)) {
		बंद(s);
		त्रुटि_सं = ENAMETOOLONG;
		वापस (-1);
	}
	अगर (connect(s, (काष्ठा sockaddr *)&sun_sa, SUN_LEN(&sun_sa)) < 0) {
		बंद(s);
		वापस (-1);
	}
	वापस (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
पूर्णांक
unix_listen(अक्षर *path)
{
	पूर्णांक s;
	अगर ((s = unix_bind(path)) < 0)
		वापस (-1);

	अगर (listen(s, 5) < 0) {
		बंद(s);
		वापस (-1);
	}
	वापस (s);
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
पूर्णांक
remote_connect(स्थिर अक्षर *host, स्थिर अक्षर *port, काष्ठा addrinfo hints)
{
	काष्ठा addrinfo *res, *res0;
	पूर्णांक s, error;
#अगर defined(SO_RTABLE) || defined(SO_BINDANY)
	पूर्णांक on = 1;
#पूर्ण_अगर

	अगर ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	करो {
		अगर ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			जारी;

#अगर_घोषित SO_RTABLE
		अगर (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, माप(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#पूर्ण_अगर
		/* Bind to a local port or source address if specified. */
		अगर (sflag || pflag) {
			काष्ठा addrinfo ahints, *ares;

#अगर_घोषित SO_BINDANY
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, माप(on));
#पूर्ण_अगर
			स_रखो(&ahints, 0, माप(काष्ठा addrinfo));
			ahints.ai_family = res0->ai_family;
			ahints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
			ahints.ai_protocol = uflag ? IPPROTO_UDP : IPPROTO_TCP;
			ahints.ai_flags = AI_PASSIVE;
			अगर ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			अगर (bind(s, (काष्ठा sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				err(1, "bind failed");
			freeaddrinfo(ares);
		}

		set_common_sockopts(s, res0->ai_family);

		अगर (timeout_connect(s, res0->ai_addr, res0->ai_addrlen) == 0)
			अवरोध;
		अन्यथा अगर (vflag)
			warn("connect to %s port %s (%s) failed", host, port,
			    uflag ? "udp" : "tcp");

		बंद(s);
		s = -1;
	} जबतक ((res0 = res0->ai_next) != शून्य);

	freeaddrinfo(res);

	वापस (s);
}

पूर्णांक
timeout_connect(पूर्णांक s, स्थिर काष्ठा sockaddr *name, socklen_t namelen)
{
	काष्ठा pollfd pfd;
	socklen_t optlen;
	पूर्णांक flags = 0, optval;
	पूर्णांक ret;

	अगर (timeout != -1) {
		flags = fcntl(s, F_GETFL, 0);
		अगर (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
			err(1, "set non-blocking mode");
	}

	अगर ((ret = connect(s, name, namelen)) != 0 && त्रुटि_सं == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		अगर ((ret = poll(&pfd, 1, timeout)) == 1) {
			optlen = माप(optval);
			अगर ((ret = getsockopt(s, SOL_SOCKET, SO_ERROR,
			    &optval, &optlen)) == 0) {
				त्रुटि_सं = optval;
				ret = optval == 0 ? 0 : -1;
			}
		} अन्यथा अगर (ret == 0) {
			त्रुटि_सं = ETIMEDOUT;
			ret = -1;
		} अन्यथा
			err(1, "poll failed");
	}

	अगर (timeout != -1 && fcntl(s, F_SETFL, flags) == -1)
		err(1, "restoring flags");

	वापस (ret);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
पूर्णांक
local_listen(अक्षर *host, अक्षर *port, काष्ठा addrinfo hints)
{
	काष्ठा addrinfo *res, *res0;
	पूर्णांक s, ret, x = 1;
	पूर्णांक error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	अगर (host == शून्य && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	अगर ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	करो {
		अगर ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			जारी;

#अगर_घोषित SO_RTABLE
		अगर (rtableid >= 0 && (setsockopt(s, SOL_SOCKET, SO_RTABLE,
		    &rtableid, माप(rtableid)) == -1))
			err(1, "setsockopt SO_RTABLE");
#पूर्ण_अगर
#अगर_घोषित SO_REUSEPORT
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, माप(x));
		अगर (ret == -1)
			err(1, "setsockopt SO_REUSEPORT");
#पूर्ण_अगर
#अगर_घोषित SO_REUSEADDR
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, माप(x));
		अगर (ret == -1)
			err(1, "setsockopt SO_REUSEADDR");
#पूर्ण_अगर
		set_common_sockopts(s, res0->ai_family);

		अगर (bind(s, (काष्ठा sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			अवरोध;

		बंद(s);
		s = -1;
	} जबतक ((res0 = res0->ai_next) != शून्य);

	अगर (!uflag && s != -1) {
		अगर (listen(s, 1) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	वापस (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
व्योम
readwrite(पूर्णांक net_fd)
{
	काष्ठा pollfd pfd[4];
	पूर्णांक stdin_fd = STDIN_FILENO;
	पूर्णांक stdout_fd = STDOUT_FILENO;
	अचिन्हित अक्षर netinbuf[BUFSIZE];
	माप_प्रकार netinbufpos = 0;
	अचिन्हित अक्षर stdinbuf[BUFSIZE];
	माप_प्रकार stdinbufpos = 0;
	पूर्णांक n, अंक_fds;
	ssize_t ret;

	/* don't read from stdin if requested */
	अगर (dflag)
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

	जबतक (1) {
		/* both inputs are gone, buffers are empty, we are done */
		अगर (pfd[POLL_STDIN].fd == -1 && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			बंद(net_fd);
			वापस;
		}
		/* both outputs are gone, we can't continue */
		अगर (pfd[POLL_NETOUT].fd == -1 && pfd[POLL_STDOUT].fd == -1) {
			बंद(net_fd);
			वापस;
		}
		/* listen and net in gone, queues empty, done */
		अगर (lflag && pfd[POLL_NETIN].fd == -1
		    && stdinbufpos == 0 && netinbufpos == 0) {
			बंद(net_fd);
			वापस;
		}

		/* help says -i is for "wait between lines sent". We read and
		 * write arbitrary amounts of data, and we don't want to start
		 * scanning for newlines, so this is as good as it gets */
		अगर (iflag)
			sleep(iflag);

		/* poll */
		अंक_fds = poll(pfd, 4, timeout);

		/* treat poll errors */
		अगर (अंक_fds == -1) {
			बंद(net_fd);
			err(1, "polling error");
		}

		/* timeout happened */
		अगर (अंक_fds == 0)
			वापस;

		/* treat socket error conditions */
		क्रम (n = 0; n < 4; n++) {
			अगर (pfd[n].revents & (POLLERR|POLLNVAL)) {
				pfd[n].fd = -1;
			}
		}
		/* reading is possible after HUP */
		अगर (pfd[POLL_STDIN].events & POLLIN &&
		    pfd[POLL_STDIN].revents & POLLHUP &&
		    ! (pfd[POLL_STDIN].revents & POLLIN))
				pfd[POLL_STDIN].fd = -1;

		अगर (pfd[POLL_NETIN].events & POLLIN &&
		    pfd[POLL_NETIN].revents & POLLHUP &&
		    ! (pfd[POLL_NETIN].revents & POLLIN))
				pfd[POLL_NETIN].fd = -1;

		अगर (pfd[POLL_NETOUT].revents & POLLHUP) {
			अगर (Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* if HUP, stop watching stdout */
		अगर (pfd[POLL_STDOUT].revents & POLLHUP)
			pfd[POLL_STDOUT].fd = -1;
		/* if no net out, stop watching stdin */
		अगर (pfd[POLL_NETOUT].fd == -1)
			pfd[POLL_STDIN].fd = -1;
		/* if no stdout, stop watching net in */
		अगर (pfd[POLL_STDOUT].fd == -1) {
			अगर (pfd[POLL_NETIN].fd != -1)
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
			pfd[POLL_NETIN].fd = -1;
		}

		/* try to read from stdin */
		अगर (pfd[POLL_STDIN].revents & POLLIN && stdinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_STDIN].fd, stdinbuf,
			    &stdinbufpos);
			/* error or eof on stdin - remove from pfd */
			अगर (ret == 0 || ret == -1)
				pfd[POLL_STDIN].fd = -1;
			/* read something - poll net out */
			अगर (stdinbufpos > 0)
				pfd[POLL_NETOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			अगर (stdinbufpos == BUFSIZE)
				pfd[POLL_STDIN].events = 0;
		}
		/* try to write to network */
		अगर (pfd[POLL_NETOUT].revents & POLLOUT && stdinbufpos > 0) {
			ret = drainbuf(pfd[POLL_NETOUT].fd, stdinbuf,
			    &stdinbufpos);
			अगर (ret == -1)
				pfd[POLL_NETOUT].fd = -1;
			/* buffer empty - remove self from polling */
			अगर (stdinbufpos == 0)
				pfd[POLL_NETOUT].events = 0;
			/* buffer no longer full - poll stdin again */
			अगर (stdinbufpos < BUFSIZE)
				pfd[POLL_STDIN].events = POLLIN;
		}
		/* try to read from network */
		अगर (pfd[POLL_NETIN].revents & POLLIN && netinbufpos < BUFSIZE) {
			ret = fillbuf(pfd[POLL_NETIN].fd, netinbuf,
			    &netinbufpos);
			अगर (ret == -1)
				pfd[POLL_NETIN].fd = -1;
			/* eof on net in - remove from pfd */
			अगर (ret == 0) {
				shutdown(pfd[POLL_NETIN].fd, SHUT_RD);
				pfd[POLL_NETIN].fd = -1;
			}
			/* read something - poll stdout */
			अगर (netinbufpos > 0)
				pfd[POLL_STDOUT].events = POLLOUT;
			/* filled buffer - remove self from polling */
			अगर (netinbufpos == BUFSIZE)
				pfd[POLL_NETIN].events = 0;
			/* handle telnet */
			अगर (tflag)
				atelnet(pfd[POLL_NETIN].fd, netinbuf,
				    netinbufpos);
		}
		/* try to write to stdout */
		अगर (pfd[POLL_STDOUT].revents & POLLOUT && netinbufpos > 0) {
			ret = drainbuf(pfd[POLL_STDOUT].fd, netinbuf,
			    &netinbufpos);
			अगर (ret == -1)
				pfd[POLL_STDOUT].fd = -1;
			/* buffer empty - remove self from polling */
			अगर (netinbufpos == 0)
				pfd[POLL_STDOUT].events = 0;
			/* buffer no longer full - poll net in again */
			अगर (netinbufpos < BUFSIZE)
				pfd[POLL_NETIN].events = POLLIN;
		}

		/* stdin gone and queue empty? */
		अगर (pfd[POLL_STDIN].fd == -1 && stdinbufpos == 0) {
			अगर (pfd[POLL_NETOUT].fd != -1 && Nflag)
				shutdown(pfd[POLL_NETOUT].fd, SHUT_WR);
			pfd[POLL_NETOUT].fd = -1;
		}
		/* net in gone and queue empty? */
		अगर (pfd[POLL_NETIN].fd == -1 && netinbufpos == 0) {
			pfd[POLL_STDOUT].fd = -1;
		}
	}
}

ssize_t
drainbuf(पूर्णांक fd, अचिन्हित अक्षर *buf, माप_प्रकार *bufpos)
{
	ssize_t n;
	ssize_t adjust;

	n = ग_लिखो(fd, buf, *bufpos);
	/* don't treat EAGAIN, EINTR as error */
	अगर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR))
		n = -2;
	अगर (n <= 0)
		वापस n;
	/* adjust buffer */
	adjust = *bufpos - n;
	अगर (adjust > 0)
		स_हटाओ(buf, buf + n, adjust);
	*bufpos -= n;
	वापस n;
}


ssize_t
fillbuf(पूर्णांक fd, अचिन्हित अक्षर *buf, माप_प्रकार *bufpos)
{
	माप_प्रकार अंक = BUFSIZE - *bufpos;
	ssize_t n;

	n = पढ़ो(fd, buf + *bufpos, अंक);
	/* don't treat EAGAIN, EINTR as error */
	अगर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR))
		n = -2;
	अगर (n <= 0)
		वापस n;
	*bufpos += n;
	वापस n;
}

/*
 * fdpass()
 * Pass the connected file descriptor to stdout and exit.
 */
व्योम
fdpass(पूर्णांक nfd)
{
#अगर defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	काष्ठा msghdr संदेश;
#अगर_अघोषित HAVE_ACCRIGHTS_IN_MSGHDR
	जोड़ {
		काष्ठा cmsghdr hdr;
		अक्षर buf[CMSG_SPACE(माप(पूर्णांक))];
	} cmsgbuf;
	काष्ठा cmsghdr *cmsg;
#पूर्ण_अगर
	काष्ठा iovec vec;
	अक्षर ch = '\0';
	काष्ठा pollfd pfd;
	ssize_t r;

	स_रखो(&संदेश, 0, माप(संदेश));
#अगर_घोषित HAVE_ACCRIGHTS_IN_MSGHDR
	संदेश.संदेश_accrights = (caddr_t)&nfd;
	संदेश.संदेश_accrightslen = माप(nfd);
#अन्यथा
	स_रखो(&cmsgbuf, 0, माप(cmsgbuf));
	संदेश.msg_control = (caddr_t)&cmsgbuf.buf;
	संदेश.msg_controllen = माप(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&संदेश);
	cmsg->cmsg_len = CMSG_LEN(माप(पूर्णांक));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(पूर्णांक *)CMSG_DATA(cmsg) = nfd;
#पूर्ण_अगर

	vec.iov_base = &ch;
	vec.iov_len = 1;
	संदेश.msg_iov = &vec;
	संदेश.msg_iovlen = 1;

	bzero(&pfd, माप(pfd));
	pfd.fd = STDOUT_FILENO;
	pfd.events = POLLOUT;
	क्रम (;;) {
		r = sendmsg(STDOUT_FILENO, &संदेश, 0);
		अगर (r == -1) {
			अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR) {
				अगर (poll(&pfd, 1, -1) == -1)
					err(1, "poll");
				जारी;
			}
			err(1, "sendmsg");
		} अन्यथा अगर (r != 1)
			errx(1, "sendmsg: unexpected return value %zd", r);
		अन्यथा
			अवरोध;
	}
	निकास(0);
#अन्यथा
	errx(1, "%s: file descriptor passing not supported", __func__);
#पूर्ण_अगर
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
व्योम
atelnet(पूर्णांक nfd, अचिन्हित अक्षर *buf, अचिन्हित पूर्णांक आकार)
{
	अचिन्हित अक्षर *p, *end;
	अचिन्हित अक्षर obuf[4];

	अगर (आकार < 3)
		वापस;
	end = buf + आकार - 2;

	क्रम (p = buf; p < end; p++) {
		अगर (*p != IAC)
			जारी;

		obuf[0] = IAC;
		p++;
		अगर ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		अन्यथा अगर ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		अन्यथा
			जारी;

		p++;
		obuf[2] = *p;
		अगर (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
व्योम
build_ports(अक्षर *p)
{
	स्थिर अक्षर *errstr;
	अक्षर *n;
	पूर्णांक hi, lo, cp;
	पूर्णांक x = 0;

	अगर ((n = म_अक्षर(p, '-')) != शून्य) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		अगर (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		अगर (errstr)
			errx(1, "port number %s: %s", errstr, p);

		अगर (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		क्रम (cp = lo; cp <= hi; cp++) {
			portlist[x] = सुस्मृति(1, PORT_MAX_LEN);
			अगर (portlist[x] == शून्य)
				errx(1, "calloc");
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		अगर (rflag) {
			पूर्णांक y;
			अक्षर *c;

			क्रम (x = 0; x <= (hi - lo); x++) {
				y = arc4random_uniform(hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} अन्यथा {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		अगर (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[0] = strdup(p);
		अगर (portlist[0] == शून्य)
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

	क्रम (i = 0; i <= 3; i++) {
		अगर (ग_लिखो(s, "X", 1) == 1)
			ret = 1;
		अन्यथा
			ret = -1;
	}
	वापस (ret);
}

व्योम
set_common_sockopts(पूर्णांक s, पूर्णांक af)
{
	पूर्णांक x = 1;

#अगर_घोषित TCP_MD5SIG
	अगर (Sflag) {
		अगर (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, माप(x)) == -1)
			err(1, "setsockopt");
	}
#पूर्ण_अगर
	अगर (Dflag) {
		अगर (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, माप(x)) == -1)
			err(1, "setsockopt");
	}
#अगर defined(IP_TOS) && defined(IPV6_TCLASS)
	अगर (Tflag != -1) {
		पूर्णांक proto, option;

		अगर (af == AF_INET6) {
			proto = IPPROTO_IPV6;
			option = IPV6_TCLASS;
		} अन्यथा {
			proto = IPPROTO_IP;
			option = IP_TOS;
		}

		अगर (setsockopt(s, proto, option, &Tflag, माप(Tflag)) == -1)
			err(1, "set IP ToS");
	}
#पूर्ण_अगर
	अगर (Iflag) {
		अगर (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, माप(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	अगर (Oflag) {
		अगर (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, माप(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

पूर्णांक
map_tos(अक्षर *s, पूर्णांक *val)
{
#अगर_घोषित IP_TOS
	/* DiffServ Codepoints and other TOS mappings */
	स्थिर काष्ठा toskeywords {
		स्थिर अक्षर	*keyword;
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
		{ शून्य, 		-1 },
	};

	क्रम (t = toskeywords; t->keyword != शून्य; t++) {
		अगर (म_भेद(s, t->keyword) == 0) {
			*val = t->val;
			वापस (1);
		}
	}
#पूर्ण_अगर

	वापस (0);
}

व्योम
report_connect(स्थिर काष्ठा sockaddr *sa, socklen_t salen)
{
	अक्षर remote_host[NI_MAXHOST];
	अक्षर remote_port[NI_MAXSERV];
	पूर्णांक herr;
	पूर्णांक flags = NI_NUMERICSERV;
	
	अगर (nflag)
		flags |= NI_NUMERICHOST;
	
	अगर ((herr = getnameinfo(sa, salen,
	    remote_host, माप(remote_host),
	    remote_port, माप(remote_port),
	    flags)) != 0) {
		अगर (herr == EAI_SYSTEM)
			err(1, "getnameinfo");
		अन्यथा
			errx(1, "getnameinfo: %s", gai_strerror(herr));
	}
	
	ख_लिखो(मानक_त्रुटि,
	    "Connection from %s %s "
	    "received!\n", remote_host, remote_port);
}

व्योम
help(व्योम)
{
	usage(0);
	ख_लिखो(मानक_त्रुटि, "\tCommand Summary:\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from मानक_निवेश\n\
	\t-F		Pass socket fd\n\
	\t-h		This help text\n\
	\t-I लंबाई	TCP receive बफर लंबाई\n\
	\t-i secs\t	Delay interval क्रम पंक्तियाँ sent, ports scanned\n\
	\t-k		Keep inbound sockets खोलो क्रम multiple connects\n\
	\t-l		Listen mode, क्रम inbound connects\n\
	\t-N		Shutdown the network socket after खातापूर्ण on मानक_निवेश\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O लंबाई	TCP send बफर लंबाई\n\
	\t-P proxyuser\tUsername क्रम proxy authentication\n\
	\t-p port\t	Specify local port क्रम remote connects\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout क्रम connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-z		Zero-I/O mode [used क्रम scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	निकास(1);
}

व्योम
usage(पूर्णांक ret)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: nc [-46DdFhklNnrStUuvz] [-I length] [-i interval] [-O length]\n"
	    "\t  [-P proxy_username] [-p source_port] [-s source] [-T toskeyword]\n"
	    "\t  [-V rtable] [-w timeout] [-X proxy_protocol]\n"
	    "\t  [-x proxy_address[:port]] [destination] [port]\n");
	अगर (ret)
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

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <netdb.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <resolv.h>

#घोषणा SOCKS_PORT	"1080"
#घोषणा HTTP_PROXY_PORT	"3128"
#घोषणा HTTP_MAXHDRS	64
#घोषणा SOCKS_V5	5
#घोषणा SOCKS_V4	4
#घोषणा SOCKS_NOAUTH	0
#घोषणा SOCKS_NOMETHOD	0xff
#घोषणा SOCKS_CONNECT	1
#घोषणा SOCKS_IPV4	1
#घोषणा SOCKS_DOMAIN	3
#घोषणा SOCKS_IPV6	4

पूर्णांक	remote_connect(स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo);
पूर्णांक	socks_connect(स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo,
	    स्थिर अक्षर *, स्थिर अक्षर *, काष्ठा addrinfo, पूर्णांक,
	    स्थिर अक्षर *);

अटल पूर्णांक
decode_addrport(स्थिर अक्षर *h, स्थिर अक्षर *p, काष्ठा sockaddr *addr,
    socklen_t addrlen, पूर्णांक v4only, पूर्णांक numeric)
{
	पूर्णांक r;
	काष्ठा addrinfo hints, *res;

	bzero(&hints, माप(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	अगर (r != 0) {
		अगर (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		वापस (-1);
	}
	अगर (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	स_नकल(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	वापस (0);
}

अटल पूर्णांक
proxy_read_पंक्ति(पूर्णांक fd, अक्षर *buf, माप_प्रकार bufsz)
{
	माप_प्रकार off;

	क्रम(off = 0;;) {
		अगर (off >= bufsz)
			errx(1, "proxy read too long");
		अगर (atomicio(पढ़ो, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		अगर (buf[off] == '\r')
			जारी;
		अगर (buf[off] == '\n') {
			buf[off] = '\0';
			अवरोध;
		}
		off++;
	}
	वापस (off);
}

अटल स्थिर अक्षर *
getproxypass(स्थिर अक्षर *proxyuser, स्थिर अक्षर *proxyhost)
{
	अक्षर prompt[512];
	अटल अक्षर pw[256];

	snprintf(prompt, माप(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	अगर (readpassphrase(prompt, pw, माप(pw), RPP_REQUIRE_TTY) == शून्य)
		errx(1, "Unable to read proxy passphrase");
	वापस (pw);
}

पूर्णांक
socks_connect(स्थिर अक्षर *host, स्थिर अक्षर *port,
    काष्ठा addrinfo hints __attribute__ ((__unused__)),
    स्थिर अक्षर *proxyhost, स्थिर अक्षर *proxyport, काष्ठा addrinfo proxyhints,
    पूर्णांक socksv, स्थिर अक्षर *proxyuser)
{
	पूर्णांक proxyfd, r, authretry = 0;
	माप_प्रकार hlen, wlen = 0;
	अचिन्हित अक्षर buf[1024];
	माप_प्रकार cnt;
	काष्ठा sockaddr_storage addr;
	काष्ठा sockaddr_in *in4 = (काष्ठा sockaddr_in *)&addr;
	काष्ठा sockaddr_in6 *in6 = (काष्ठा sockaddr_in6 *)&addr;
	in_port_t serverport;
	स्थिर अक्षर *proxypass = शून्य;

	अगर (proxyport == शून्य)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	अगर (decode_addrport("0.0.0.0", port, (काष्ठा sockaddr *)&addr,
	    माप(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	अगर (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	अगर (proxyfd < 0)
		वापस (-1);

	अगर (socksv == 5) {
		अगर (decode_addrport(host, port, (काष्ठा sockaddr *)&addr,
		    माप(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		अगर (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(पढ़ो, proxyfd, buf, 2);
		अगर (cnt != 2)
			err(1, "read failed (%zu/3)", cnt);

		अगर (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		चयन (addr.ss_family) {
		हाल 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = म_माप(host);
			अगर (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			स_नकल(buf + 5, host, hlen);			
			स_नकल(buf + 5 + hlen, &serverport, माप serverport);
			wlen = 7 + hlen;
			अवरोध;
		हाल AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			स_नकल(buf + 4, &in4->sin_addr, माप in4->sin_addr);
			स_नकल(buf + 8, &in4->sin_port, माप in4->sin_port);
			wlen = 10;
			अवरोध;
		हाल AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			स_नकल(buf + 4, &in6->sin6_addr, माप in6->sin6_addr);
			स_नकल(buf + 20, &in6->sin6_port,
			    माप in6->sin6_port);
			wlen = 22;
			अवरोध;
		शेष:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		अगर (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पढ़ो, proxyfd, buf, 4);
		अगर (cnt != 4)
			err(1, "read failed (%zu/4)", cnt);
		अगर (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		चयन (buf[3]) {
		हाल SOCKS_IPV4:
			cnt = atomicio(पढ़ो, proxyfd, buf + 4, 6);
			अगर (cnt != 6)
				err(1, "read failed (%zu/6)", cnt);
			अवरोध;
		हाल SOCKS_IPV6:
			cnt = atomicio(पढ़ो, proxyfd, buf + 4, 18);
			अगर (cnt != 18)
				err(1, "read failed (%zu/18)", cnt);
			अवरोध;
		शेष:
			errx(1, "connection failed, unsupported address type");
		}
	} अन्यथा अगर (socksv == 4 || socksv == 44) {
		अगर (socksv == 4) {
			/* This will exit on lookup failure */
			decode_addrport(host, port, (काष्ठा sockaddr *)&addr,
			    माप(addr), 1, 0);
		}

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		स_नकल(buf + 2, &in4->sin_port, माप in4->sin_port);
		अगर (socksv == 4) {
			स_नकल(buf + 4, &in4->sin_addr, माप in4->sin_addr);
		} अन्यथा {
			/* SOCKS4A uses addr of 0.0.0.x, and hostname later */
			buf[4] = buf[5] = buf[6] = 0;
			buf[7] = 1;
		}
		buf[8] = 0;	/* empty username */
		wlen = 9;
		अगर (socksv == 44) {
			/* SOCKS4A has nul-terminated hostname after user */
			अगर (strlcpy(buf + 9, host,
			    माप(buf) - 9) >= माप(buf) - 9)
				errx(1, "hostname too big");
			wlen = 9 + म_माप(host) + 1;
		}
		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		अगर (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		cnt = atomicio(पढ़ो, proxyfd, buf, 8);
		अगर (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		अगर (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} अन्यथा अगर (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		अगर (म_खोज(host, "\r\n\t []:") != म_माप(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		अगर (म_अक्षर(host, ':') != शून्य) {
			r = snprintf(buf, माप(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} अन्यथा {
			r = snprintf(buf, माप(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		अगर (r == -1 || (माप_प्रकार)r >= माप(buf))
			errx(1, "hostname too long");
		r = म_माप(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		अगर (cnt != (माप_प्रकार)r)
			err(1, "write failed (%zu/%d)", cnt, r);

		अगर (authretry > 1) {
			अक्षर resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, माप(buf), "%s:%s",
			    proxyuser, proxypass);
			अगर (r == -1 || (माप_प्रकार)r >= माप(buf) ||
			    b64_ntop(buf, म_माप(buf), resp,
			    माप(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, माप(buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			अगर (r == -1 || (माप_प्रकार)r >= माप(buf))
				errx(1, "Proxy auth response too long");
			r = म_माप(buf);
			अगर ((cnt = atomicio(vwrite, proxyfd, buf, r)) != (माप_प्रकार)r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		अगर ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_पंक्ति(proxyfd, buf, माप(buf));
		अगर (proxyuser != शून्य &&
		    म_भेदन(buf, "HTTP/1.0 407 ", 12) == 0) {
			अगर (authretry > 1) {
				ख_लिखो(मानक_त्रुटि, "Proxy authentication "
				    "failed\n");
			}
			बंद(proxyfd);
			जाओ again;
		} अन्यथा अगर (म_भेदन(buf, "HTTP/1.0 200 ", 12) != 0 &&
		    म_भेदन(buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		क्रम (r = 0; r < HTTP_MAXHDRS; r++) {
			proxy_read_पंक्ति(proxyfd, buf, माप(buf));
			अगर (*buf == '\0')
				अवरोध;
		}
		अगर (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} अन्यथा
		errx(1, "Unknown proxy protocol %d", socksv);

	वापस (proxyfd);
}

