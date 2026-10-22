/* $OpenBSD: sshconnect.c,v 1.386 2026/09/16 00:29:44 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code to connect to a remote host, and to perform the client side of the
 * login (authentication) dialog.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <net/if.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <ifaddrs.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshconnect.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "dns.h"
#అన్తర్భావ "monitor_fdpass.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "kex.h"

నిర్మాణం sshkey *మునుపటి_host_కీలకం = ఖాళీ;

స్థిర పూర్ణాంకం matching_host_కీలకం_dns = 0;

స్థిర pid_t proxy_command_pid = 0;

/* import */
బాహ్య పూర్ణాంకం debug_flag;
బాహ్య Options options;
బాహ్య అక్షరం *__progname;

స్థిర పూర్ణాంకం show_other_కీలకాలు(నిర్మాణం hostkeys *, నిర్మాణం sshkey *);
స్థిర శూన్య warn_మారింది_కీలకం(నిర్మాణం sshkey *);

శూన్య
ssh_conn_info_free(నిర్మాణం ssh_conn_info *cinfo)
{
	ఒకవేళ (cinfo == ఖాళీ)
		తిరిగి;
	విడుదల(cinfo->conn_hash_hex);
	విడుదల(cinfo->shorthost);
	విడుదల(cinfo->uidstr);
	విడుదల(cinfo->keyalias);
	విడుదల(cinfo->thishost);
	విడుదల(cinfo->host_arg);
	విడుదల(cinfo->portstr);
	విడుదల(cinfo->remhost);
	విడుదల(cinfo->remuser);
	విడుదల(cinfo->homedir);
	విడుదల(cinfo->locuser);
	విడుదల(cinfo->jmphost);
	freezero(cinfo, పరిమాణం(*cinfo));
}

నిర్మాణం ssh_conn_info *
ssh_conn_info_dup(స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	నిర్మాణం ssh_conn_info *ret;

	ఒకవేళ (cinfo == ఖాళీ)
		తిరిగి ఖాళీ;
	ret = xcalloc(1, పరిమాణం(*ret));
	ret->conn_hash_hex = xstrdup(cinfo->conn_hash_hex);
	ret->shorthost = xstrdup(cinfo->shorthost);
	ret->uidstr = xstrdup(cinfo->uidstr);
	ret->keyalias = xstrdup(cinfo->keyalias);
	ret->thishost = xstrdup(cinfo->thishost);
	ret->host_arg = xstrdup(cinfo->host_arg);
	ret->portstr = xstrdup(cinfo->portstr);
	ret->remhost = xstrdup(cinfo->remhost);
	ret->remuser = xstrdup(cinfo->remuser);
	ret->homedir = xstrdup(cinfo->homedir);
	ret->locuser = xstrdup(cinfo->locuser);
	ret->jmphost = xstrdup(cinfo->jmphost);
	తిరిగి ret;
}

/* Expand a proxy command */
స్థిర అక్షరం *
expand_proxy_command(స్థిరరాశి అక్షరం *proxy_command, స్థిరరాశి అక్షరం *user,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *host_arg, పూర్ణాంకం పోర్టు)
{
	అక్షరం *tmp, *ret, strport[NI_MAXSERV];
	స్థిరరాశి అక్షరం *keyalias = options.host_కీలకం_alias ?
	    options.host_కీలకం_alias : host_arg;

	snprintf(strport, పరిమాణం strport, "%d", పోర్టు);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (అక్షరం *)ఖాళీ);
	విడుదల(tmp);
	తిరిగి ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
స్థిర పూర్ణాంకం
ssh_proxy_fdpass_connect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *host_arg, u_short పోర్టు, స్థిరరాశి అక్షరం *proxy_command)
{
	అక్షరం *command_string;
	పూర్ణాంకం sp[2], sock;
	pid_t pid;
	అక్షరం *shell;

	ఒకవేళ ((shell = getenv("SHELL")) == ఖాళీ)
		shell = _PATH_BSHELL;

	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, పోర్టు);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ఒకవేళ ((pid = fork()) == 0) {
		అక్షరం *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ఒకవేళ (sp[0] != 0) {
			ఒకవేళ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ఒకవేళ (sp[0] != 1) {
			ఒకవేళ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ఒకవేళ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ఒకవేళ (!debug_flag && options.control_మార్గం != ఖాళీ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ఖాళీ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		నిష్క్రమించు(1);
	}
	/* Parent. */
	ఒకవేళ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	విడుదల(command_string);

	ఒకవేళ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	అయితే (waitpid(pid, ఖాళీ, 0) == -1)
		ఒకవేళ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ఒకవేళ (ssh_packet_సమితి_connection(ssh, sock, sock) == ఖాళీ)
		తిరిగి -1; /* ssh_packet_set_connection logs error */

	తిరిగి 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
స్థిర పూర్ణాంకం
ssh_proxy_connect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *host_arg,
    u_short పోర్టు, స్థిరరాశి అక్షరం *proxy_command)
{
	అక్షరం *command_string;
	పూర్ణాంకం pin[2], pout[2];
	pid_t pid;
	అక్షరం *shell;

	ఒకవేళ ((shell = getenv("SHELL")) == ఖాళీ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ఒకవేళ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, పోర్టు);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ఒకవేళ ((pid = fork()) == 0) {
		అక్షరం *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ఒకవేళ (pin[0] != 0) {
			ఒకవేళ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ఒకవేళ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ఒకవేళ (!debug_flag && options.control_మార్గం != ఖాళీ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ఖాళీ;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		నిష్క్రమించు(1);
	}
	/* Parent. */
	ఒకవేళ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	లేకపోతే
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	విడుదల(command_string);

	/* Set the connection file descriptors. */
	ఒకవేళ (ssh_packet_సమితి_connection(ssh, pout[0], pin[1]) == ఖాళీ)
		తిరిగి -1; /* ssh_packet_set_connection logs error */

	తిరిగి 0;
}

శూన్య
ssh_kill_proxy_command(శూన్య)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ఒకవేళ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#నిర్వచితమైతే HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
స్థిర పూర్ణాంకం
check_ifaddrs(స్థిరరాశి అక్షరం *ifname, పూర్ణాంకం af, స్థిరరాశి నిర్మాణం ifaddrs *ifaddrs,
    నిర్మాణం sockaddr_storage *resultp, socklen_t *rlenp)
{
	నిర్మాణం sockaddr_in6 *sa6;
	నిర్మాణం sockaddr_in *sa;
	నిర్మాణం in6_addr *v6addr;
	స్థిరరాశి నిర్మాణం ifaddrs *ifa;
	పూర్ణాంకం allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	కొరకు (allow_local = 0; allow_local < 2; allow_local++) {
		కొరకు (ifa = ifaddrs; ifa != ఖాళీ; ifa = ifa->ifa_తదుపరి) {
			ఒకవేళ (ifa->ifa_addr == ఖాళీ || ifa->ifa_name == ఖాళీ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				కొనసాగు;
			ఎంపిక (ifa->ifa_addr->sa_family) {
			స్థితి AF_INET:
				sa = (నిర్మాణం sockaddr_in *)ifa->ifa_addr;
				ఒకవేళ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					కొనసాగు;
				ఒకవేళ (*rlenp < పరిమాణం(నిర్మాణం sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					తిరిగి -1;
				}
				*rlenp = పరిమాణం(నిర్మాణం sockaddr_in);
				జ్ఞాపకం_నకలు(resultp, sa, *rlenp);
				తిరిగి 0;
			స్థితి AF_INET6:
				sa6 = (నిర్మాణం sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ఒకవేళ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					కొనసాగు;
				ఒకవేళ (*rlenp < పరిమాణం(నిర్మాణం sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					తిరిగి -1;
				}
				*rlenp = పరిమాణం(నిర్మాణం sockaddr_in6);
				జ్ఞాపకం_నకలు(resultp, sa6, *rlenp);
				తిరిగి 0;
			}
		}
	}
	తిరిగి -1;
}
#అయితే_ముగింపు

/*
 * Creates a socket for use as the ssh connection.
 */
స్థిర పూర్ణాంకం
ssh_create_socket(నిర్మాణం addrinfo *ai)
{
	పూర్ణాంకం sock, r;
	నిర్మాణం sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	నిర్మాణం addrinfo hints, *res = ఖాళీ;
#నిర్వచితమైతే HAVE_IFADDRS_H
	నిర్మాణం ifaddrs *ifaddrs = ఖాళీ;
#అయితే_ముగింపు
	అక్షరం ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ఒకవేళ (sock == -1) {
		error("socket: %s", strerror(errno));
		తిరిగి -1;
	}
	(శూన్య)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ఒకవేళ (options.ip_qos_interactive != గరిష్ఠ_పూర్ణాంకం)
		సమితి_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ఒకవేళ (options.bind_చిరునామా == ఖాళీ && options.bind_interface == ఖాళీ)
		తిరిగి sock;

	ఒకవేళ (options.bind_చిరునామా != ఖాళీ) {
		memset(&hints, 0, పరిమాణం(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ఒకవేళ ((r = getaddrinfo(options.bind_చిరునామా, ఖాళీ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_చిరునామా,
			    ssh_gai_strerror(r));
			వెళ్ళు fail;
		}
		ఒకవేళ (res == ఖాళీ) {
			error("getaddrinfo: no addrs");
			వెళ్ళు fail;
		}
		జ్ఞాపకం_నకలు(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} లేకపోతే ఒకవేళ (options.bind_interface != ఖాళీ) {
#నిర్వచితమైతే HAVE_IFADDRS_H
		ఒకవేళ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			వెళ్ళు fail;
		}
		bindaddrlen = పరిమాణం(bindaddr);
		ఒకవేళ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			వెళ్ళు fail;
		}
#లేకపోతే
		error("BindInterface not supported on this platform.");
#అయితే_ముగింపు
	}
	ఒకవేళ ((r = getnameinfo((నిర్మాణం sockaddr *)&bindaddr, bindaddrlen,
	    ntop, పరిమాణం(ntop), ఖాళీ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		వెళ్ళు fail;
	}
	ఒకవేళ (bind(sock, (నిర్మాణం sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		వెళ్ళు fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	వెళ్ళు బహిర్గతం;
fail:
	close(sock);
	sock = -1;
 బహిర్గతం:
	ఒకవేళ (res != ఖాళీ)
		freeaddrinfo(res);
#నిర్వచితమైతే HAVE_IFADDRS_H
	ఒకవేళ (ifaddrs != ఖాళీ)
		freeifaddrs(ifaddrs);
#అయితే_ముగింపు
	తిరిగి sock;
}

/*
 * Opens a TCP/IP connection to the remote server on the given host.
 * The address of the remote host will be returned in hostaddr.
 * If port is 0, the default port will be used.
 * Connection_attempts specifies the maximum number of tries (one per
 * second).  If proxy_command is non-NULL, it specifies the command (with %h
 * and %p substituted for host and port, respectively) to use to contact
 * the daemon.
 */
స్థిర పూర్ణాంకం
ssh_connect_ప్రత్యక్ష(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host, నిర్మాణం addrinfo *aitop,
    నిర్మాణం sockaddr_storage *hostaddr, u_short పోర్టు, పూర్ణాంకం connection_attempts,
    పూర్ణాంకం *timeout_ms, పూర్ణాంకం want_keepalive)
{
	పూర్ణాంకం saved_timeout_ms = *timeout_ms;
	పూర్ణాంకం oerrno, sock = -1, attempt;
	అక్షరం ntop[NI_MAXHOST], strport[NI_MAXSERV];
	నిర్మాణం addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, పరిమాణం(ntop));
	memset(strport, 0, పరిమాణం(strport));

	కొరకు (attempt = 0; attempt < connection_attempts; attempt++) {
		ఒకవేళ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		కొరకు (ai = aitop; ai; ai = ai->ai_next) {
			ఒకవేళ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				కొనసాగు;
			}
			ఒకవేళ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, పరిమాణం(ntop), strport, పరిమాణం(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				కొనసాగు;
			}
			ఒకవేళ (options.చిరునామా_family != AF_UNSPEC &&
			    ai->ai_family != options.చిరునామా_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				కొనసాగు;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ఒకవేళ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				కొనసాగు;
			}

			*timeout_ms = saved_timeout_ms;
			ఒకవేళ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				జ్ఞాపకం_నకలు(hostaddr, ai->ai_addr, ai->ai_addrlen);
				ఆపు;
			} లేకపోతే {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ఒకవేళ (sock != -1)
			ఆపు;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ఒకవేళ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		తిరిగి -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ఒకవేళ (want_keepalive)
		సమితి_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ఒకవేళ (ssh_packet_సమితి_connection(ssh, sock, sock) == ఖాళీ)
		తిరిగి -1; /* ssh_packet_set_connection logs error */

	తిరిగి 0;
}

పూర్ణాంకం
ssh_connect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *host_arg,
    నిర్మాణం addrinfo *addrs, నిర్మాణం sockaddr_storage *hostaddr, u_short పోర్టు,
    పూర్ణాంకం connection_attempts, పూర్ణాంకం *timeout_ms, పూర్ణాంకం want_keepalive)
{
	పూర్ణాంకం లోపల, బహిర్గతం;

	ఒకవేళ (options.proxy_command == ఖాళీ) {
		తిరిగి ssh_connect_ప్రత్యక్ష(ssh, host, addrs, hostaddr, పోర్టు,
		    connection_attempts, timeout_ms, want_keepalive);
	} లేకపోతే ఒకవేళ (strcmp(options.proxy_command, "-") == 0) {
		ఒకవేళ ((లోపల = dup(STDIN_FILENO)) == -1 ||
		    (బహిర్గతం = dup(STDOUT_FILENO)) == -1) {
			ఒకవేళ (లోపల >= 0)
				close(లోపల);
			error_f("dup() in/out failed");
			తిరిగి -1; /* ssh_packet_set_connection logs error */
		}
		ఒకవేళ ((ssh_packet_సమితి_connection(ssh, లోపల, బహిర్గతం)) == ఖాళీ)
			తిరిగి -1; /* ssh_packet_set_connection logs error */
		తిరిగి 0;
	} లేకపోతే ఒకవేళ (options.proxy_use_fdpass) {
		తిరిగి ssh_proxy_fdpass_connect(ssh, host, host_arg, పోర్టు,
		    options.proxy_command);
	}
	తిరిగి ssh_proxy_connect(ssh, host, host_arg, పోర్టు,
	    options.proxy_command);
}

/* defaults to 'no' */
స్థిర పూర్ణాంకం
confirm(స్థిరరాశి అక్షరం *prompt, స్థిరరాశి అక్షరం *fingerprint)
{
	స్థిరరాశి అక్షరం *సందేశం, *again = "Please type 'yes' or 'no': ";
	స్థిరరాశి అక్షరం *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	అక్షరం *p, *cp;
	పూర్ణాంకం ret = -1;

	ఒకవేళ (options.batch_బహుళకం)
		తిరిగి 0;
	కొరకు (సందేశం = prompt;;సందేశం = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(సందేశం, RP_ECHO);
		ఒకవేళ (p == ఖాళీ)
			తిరిగి 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ఒకవేళ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		లేకపోతే ఒకవేళ (strcasecmp(p, "yes") == 0 || (fingerprint != ఖాళీ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		విడుదల(cp);
		ఒకవేళ (ret != -1)
			తిరిగి ret;
	}
}

స్థిర పూర్ణాంకం
sockaddr_is_local(నిర్మాణం sockaddr *hostaddr)
{
	ఎంపిక (hostaddr->sa_family) {
	స్థితి AF_INET:
		తిరిగి (ntohl(((నిర్మాణం sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	స్థితి AF_INET6:
		తిరిగి IN6_IS_ADDR_LOOPBACK(
		    &(((నిర్మాణం sockaddr_in6 *)hostaddr)->sin6_addr));
	అప్రమేయ:
		తిరిగి 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
శూన్య
get_hostfile_hostname_ipaddr(అక్షరం *hostname, నిర్మాణం sockaddr *hostaddr,
    u_short పోర్టు, అక్షరం **hostfile_hostname, అక్షరం **hostfile_ipaddr)
{
	అక్షరం ntop[NI_MAXHOST];
	socklen_t addrlen;

	ఎంపిక (hostaddr == ఖాళీ ? -1 : hostaddr->sa_family) {
	స్థితి -1:
		addrlen = 0;
		ఆపు;
	స్థితి AF_INET:
		addrlen = పరిమాణం(నిర్మాణం sockaddr_in);
		ఆపు;
	స్థితి AF_INET6:
		addrlen = పరిమాణం(నిర్మాణం sockaddr_in6);
		ఆపు;
	అప్రమేయ:
		addrlen = పరిమాణం(నిర్మాణం sockaddr);
		ఆపు;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ఒకవేళ (hostfile_ipaddr != ఖాళీ) {
		ఒకవేళ (options.proxy_command == ఖాళీ) {
			ఒకవేళ (getnameinfo(hostaddr, addrlen,
			    ntop, పరిమాణం(ntop), ఖాళీ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_పోర్టు(ntop, పోర్టు);
		} లేకపోతే {
			*hostfile_ipaddr = xstrdup("<no hostip for proxy "
			    "command>");
		}
	}

	/*
	 * Allow the user to record the key under a different name or
	 * differentiate a non-standard port.  This is useful for ssh
	 * tunneling over forwarded connections or if you run multiple
	 * sshd's on different ports on the same machine.
	 */
	ఒకవేళ (hostfile_hostname != ఖాళీ) {
		ఒకవేళ (options.host_కీలకం_alias != ఖాళీ) {
			*hostfile_hostname = xstrdup(options.host_కీలకం_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} లేకపోతే {
			*hostfile_hostname = put_host_పోర్టు(hostname, పోర్టు);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
స్థిర పూర్ణాంకం
మార్గం_లోపల_hostfiles(స్థిరరాశి అక్షరం *మార్గం, అక్షరం **hostfiles, u_int అంకె_hostfiles)
{
	u_int i;

	కొరకు (i = 0; i < అంకె_hostfiles; i++) {
		ఒకవేళ (strcmp(మార్గం, hostfiles[i]) == 0)
			తిరిగి 1;
	}
	తిరిగి 0;
}

నిర్మాణం కనుగొను_by_కీలకం_ctx {
	స్థిరరాశి అక్షరం *host, *ip;
	స్థిరరాశి నిర్మాణం sshkey *కీలకం;
	అక్షరం **పేర్లు;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
స్థిర అక్షరం *
try_tilde_unexpand(స్థిరరాశి అక్షరం *మార్గం)
{
	అక్షరం *home, *ret = ఖాళీ;
	కొలత_t l;

	ఒకవేళ (*మార్గం != '/')
		తిరిగి xstrdup(మార్గం);
	ఒకవేళ ((home = getenv("HOME")) == ఖాళీ || (l = అక్షరశ్రేణి_పొడవు(home)) == 0)
		తిరిగి xstrdup(మార్గం);
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(మార్గం, home, l) != 0)
		తిరిగి xstrdup(మార్గం);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ఒకవేళ (home[l - 1] != '/' && మార్గం[l] != '/')
		తిరిగి xstrdup(మార్గం);
	ఒకవేళ (మార్గం[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", మార్గం + l);
	తిరిగి ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
పూర్ణాంకం
hostkey_accepted_by_hostkeyalgs(స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	స్థిరరాశి అక్షరం *ktype = sshkey_ssh_name(కీలకం);
	స్థిరరాశి అక్షరం *hostkeyalgs = options.hostkeyalgorithms;

	ఒకవేళ (కీలకం->type == కీలకం_UNSPEC)
		తిరిగి 0;
	ఒకవేళ (కీలకం->type == కీలకం_RSA &&
	    (సరిపోలిక_నమూనా_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    సరిపోలిక_నమూనా_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		తిరిగి 1;
	ఒకవేళ (కీలకం->type == కీలకం_RSA_CERT &&
	    (సరిపోలిక_నమూనా_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    సరిపోలిక_నమూనా_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		తిరిగి 1;
	తిరిగి సరిపోలిక_నమూనా_list(ktype, hostkeyalgs, 0) == 1;
}

స్థిర పూర్ణాంకం
hostkeys_కనుగొను_by_కీలకం_cb(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం కనుగొను_by_కీలకం_ctx *ctx = (నిర్మాణం కనుగొను_by_కీలకం_ctx *)_ctx;
	అక్షరం *మార్గం;

	/* we are looking for keys with names that *do not* match */
	ఒకవేళ ((l->సరిపోలిక & HKF_సరిపోలిక_HOST) != 0)
		తిరిగి 0;
	/* not interested in marker lines */
	ఒకవేళ (l->marker != MRK_NONE)
		తిరిగి 0;
	/* we are only interested in exact key matches */
	ఒకవేళ (l->కీలకం == ఖాళీ || !sshkey_equal(ctx->కీలకం, l->కీలకం))
		తిరిగి 0;
	మార్గం = try_tilde_unexpand(l->మార్గం);
	debug_f("found matching key in %s:%lu", మార్గం, l->linenum);
	ctx->పేర్లు = xrecallocarray(ctx->పేర్లు,
	    ctx->nnames, ctx->nnames + 1, పరిమాణం(*ctx->పేర్లు));
	xasprintf(&ctx->పేర్లు[ctx->nnames], "%s:%lu: %s", మార్గం, l->linenum,
	    అక్షరశ్రేణి_పోలిక(l->hosts, HASH_MAGIC, అక్షరశ్రేణి_పొడవు(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	విడుదల(మార్గం);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
hostkeys_కనుగొను_by_కీలకం_hostfile(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *which,
    నిర్మాణం కనుగొను_by_కీలకం_ctx *ctx)
{
	పూర్ణాంకం r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ఒకవేళ ((r = hostkeys_foreach(file, hostkeys_కనుగొను_by_కీలకం_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_కీలకం, 0)) != 0) {
		ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			తిరిగి 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		తిరిగి r;
	}
	తిరిగి 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
స్థిర శూన్య
hostkeys_కనుగొను_by_కీలకం(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    అక్షరం **user_hostfiles, u_int అంకె_user_hostfiles,
    అక్షరం **system_hostfiles, u_int అంకె_system_hostfiles,
    అక్షరం ***పేర్లు, u_int *nnames)
{
	నిర్మాణం కనుగొను_by_కీలకం_ctx ctx = {ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ, 0};
	u_int i;

	*పేర్లు = ఖాళీ;
	*nnames = 0;

	ఒకవేళ (కీలకం == ఖాళీ || sshkey_is_cert(కీలకం))
		తిరిగి;

	ctx.host = host;
	ctx.ip = ip;
	ctx.కీలకం = కీలకం;

	కొరకు (i = 0; i < అంకె_user_hostfiles; i++) {
		ఒకవేళ (hostkeys_కనుగొను_by_కీలకం_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			వెళ్ళు fail;
	}
	కొరకు (i = 0; i < అంకె_system_hostfiles; i++) {
		ఒకవేళ (hostkeys_కనుగొను_by_కీలకం_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			వెళ్ళు fail;
	}
	/* success */
	*పేర్లు = ctx.పేర్లు;
	*nnames = ctx.nnames;
	ctx.పేర్లు = ఖాళీ;
	ctx.nnames = 0;
	తిరిగి;
 fail:
	కొరకు (i = 0; i < ctx.nnames; i++)
		విడుదల(ctx.పేర్లు[i]);
	విడుదల(ctx.పేర్లు);
}

#నిర్వచించు MAX_OTHER_పేర్లు	8 /* Maximum number of names to list */
స్థిర అక్షరం *
other_hostkeys_సందేశం(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip,
    స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    అక్షరం **user_hostfiles, u_int అంకె_user_hostfiles,
    అక్షరం **system_hostfiles, u_int అంకె_system_hostfiles)
{
	అక్షరం *ret = ఖాళీ, **othernames = ఖాళీ;
	u_int i, n, అంకె_othernames = 0;

	hostkeys_కనుగొను_by_కీలకం(host, ip, కీలకం,
	    user_hostfiles, అంకె_user_hostfiles,
	    system_hostfiles, అంకె_system_hostfiles,
	    &othernames, &అంకె_othernames);
	ఒకవేళ (అంకె_othernames == 0)
		తిరిగి xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = అంకె_othernames;
	ఒకవేళ (n > MAX_OTHER_పేర్లు)
		n = MAX_OTHER_పేర్లు;
	కొరకు (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ఒకవేళ (n < అంకె_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    అంకె_othernames - n);
	}
	కొరకు (i = 0; i < అంకె_othernames; i++)
		విడుదల(othernames[i]);
	విడుదల(othernames);
	తిరిగి ret;
}

శూన్య
ఎక్కించు_hostkeys_command(నిర్మాణం hostkeys *hostkeys, స్థిరరాశి అక్షరం *command_template,
    స్థిరరాశి అక్షరం *invocation, స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo,
    స్థిరరాశి నిర్మాణం sshkey *host_కీలకం, స్థిరరాశి అక్షరం *hostfile_hostname)
{
	పూర్ణాంకం r, i, ac = 0;
	అక్షరం *కీలకం_fp = ఖాళీ, *keytext = ఖాళీ, *tmp;
	అక్షరం *command = ఖాళీ, *ట్యాగ్ = ఖాళీ, **av = ఖాళీ;
	FILE *f = ఖాళీ;
	pid_t pid;
	శూన్య (*osigchld)(పూర్ణాంకం);

	xasprintf(&ట్యాగ్, "KnownHostsCommand-%s", invocation);

	ఒకవేళ (host_కీలకం != ఖాళీ) {
		ఒకవేళ ((కీలకం_fp = sshkey_fingerprint(host_కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint failed");
		ఒకవేళ ((r = sshkey_గమ్యం_base64(host_కీలకం, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ఒకవేళ (argv_విభజించు(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", ట్యాగ్,
		    command_template);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ac == 0) {
		error("%s \"%s\" yielded no arguments", ట్యాగ్,
		    command_template);
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_కీలకం == ఖాళీ ? "NONE" : sshkey_ssh_name(host_కీలకం),
		    "f", కీలకం_fp == ఖాళీ ? "NONE" : కీలకం_fp,
		    "K", keytext == ఖాళీ ? "NONE" : keytext,
		    (అక్షరం *)ఖాళీ);
		ఒకవేళ (tmp == ఖాళీ)
			fatal_f("percent_expand failed");
		విడుదల(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ఒకవేళ ((pid = subprocess(ట్యాగ్, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_మార్గం|
	    SSH_SUBPROCESS_PRESERVE_ENV, ఖాళీ, ఖాళీ, ఖాళీ)) == 0)
		వెళ్ళు బహిర్గతం;

	ఎక్కించు_hostkeys_file(hostkeys, hostfile_hostname, ట్యాగ్, f, 1);

	ఒకవేళ (exited_cleanly(pid, ట్యాగ్, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 బహిర్గతం:
	ఒకవేళ (f != ఖాళీ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	కొరకు (i = 0; i < ac; i++)
		విడుదల(av[i]);
	విడుదల(av);
	విడుదల(ట్యాగ్);
	విడుదల(command);
	విడుదల(కీలకం_fp);
	విడుదల(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#నిర్వచించు RDRW	0
#నిర్వచించు RDONLY	1
#నిర్వచించు ROQUIET	2
స్థిర పూర్ణాంకం
check_host_కీలకం(అక్షరం *hostname, స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo,
    నిర్మాణం sockaddr *hostaddr, u_short పోర్టు,
    నిర్మాణం sshkey *host_కీలకం, పూర్ణాంకం readonly, పూర్ణాంకం clobber_పోర్టు,
    అక్షరం **user_hostfiles, u_int అంకె_user_hostfiles,
    అక్షరం **system_hostfiles, u_int అంకె_system_hostfiles,
    స్థిరరాశి అక్షరం *hostfile_command)
{
	Host_స్థితి host_స్థితి = -1, ip_స్థితి = -1;
	నిర్మాణం sshkey *raw_కీలకం = ఖాళీ;
	అక్షరం *ip = ఖాళీ, *host = ఖాళీ;
	అక్షరం hostline[1000], *hostp, *fp, *ra;
	అక్షరం సందేశం[1024];
	స్థిరరాశి అక్షరం *type, *fail_reason = ఖాళీ;
	స్థిరరాశి నిర్మాణం hostkey_నమోదు *host_దొరికింది = ఖాళీ, *ip_దొరికింది = ఖాళీ;
	పూర్ణాంకం len, cancelled_forwarding = 0, confirmed;
	పూర్ణాంకం local = sockaddr_is_local(hostaddr);
	పూర్ణాంకం r, want_cert = sshkey_is_cert(host_కీలకం), host_ip_తేడా = 0;
	పూర్ణాంకం hostkey_trusted = 0; /* Known or explicitly accepted by user */
	నిర్మాణం hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ఒకవేళ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_కీలకం_alias == ఖాళీ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		తిరిగి 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ఒకవేళ (strcspn(hostname, "@?*#[]|'\'\"\\") != అక్షరశ్రేణి_పొడవు(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_పోర్టు ? 0 : పోర్టు, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	ఒకవేళ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ఖాళీ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	కొరకు (i = 0; i < అంకె_user_hostfiles; i++)
		ఎక్కించు_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	కొరకు (i = 0; i < అంకె_system_hostfiles; i++)
		ఎక్కించు_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ఒకవేళ (hostfile_command != ఖాళీ && !clobber_పోర్టు) {
		ఎక్కించు_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_కీలకం, host);
	}

	ip_hostkeys = ఖాళీ;
	ఒకవేళ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		కొరకు (i = 0; i < అంకె_user_hostfiles; i++)
			ఎక్కించు_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		కొరకు (i = 0; i < అంకె_system_hostfiles; i++)
			ఎక్కించు_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ఒకవేళ (hostfile_command != ఖాళీ && !clobber_పోర్టు) {
			ఎక్కించు_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_కీలకం, ip);
		}
	}

 retry:
	ఒకవేళ (!hostkey_accepted_by_hostkeyalgs(host_కీలకం)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_కీలకం));
		వెళ్ళు fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_కీలకం);
	type = sshkey_type(host_కీలకం);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_స్థితి = check_కీలకం_లోపల_hostkeys(host_hostkeys, host_కీలకం,
	    &host_దొరికింది);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ఒకవేళ (!readonly && (అంకె_user_hostfiles == 0 ||
	    (host_దొరికింది != ఖాళీ && host_దొరికింది->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ఒకవేళ (!want_cert && ip_hostkeys != ఖాళీ) {
		ip_స్థితి = check_కీలకం_లోపల_hostkeys(ip_hostkeys, host_కీలకం,
		    &ip_దొరికింది);
		ఒకవేళ (host_స్థితి == HOST_మారింది &&
		    (ip_స్థితి != HOST_మారింది ||
		    (ip_దొరికింది != ఖాళీ &&
		    !sshkey_equal(ip_దొరికింది->కీలకం, host_దొరికింది->కీలకం))))
			host_ip_తేడా = 1;
	} లేకపోతే
		ip_స్థితి = host_స్థితి;

	ఎంపిక (host_స్థితి) {
	స్థితి HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_దొరికింది->file, host_దొరికింది->పంక్తి);
		ఒకవేళ (want_cert) {
			ఒకవేళ (sshkey_cert_check_host(host_కీలకం,
			    options.host_కీలకం_alias == ఖాళీ ?
			    hostname : options.host_కీలకం_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				వెళ్ళు fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ఒకవేళ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ఒకవేళ (options.update_hostkeys != 0 &&
		    (మార్గం_లోపల_hostfiles(host_దొరికింది->file,
		    system_hostfiles, అంకె_system_hostfiles) ||
		    (ip_స్థితి == HOST_OK && ip_దొరికింది != ఖాళీ &&
		    మార్గం_లోపల_hostfiles(ip_దొరికింది->file,
		    system_hostfiles, అంకె_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ఒకవేళ (options.update_hostkeys != 0 && host_దొరికింది->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ఒకవేళ (options.check_host_ip && ip_స్థితి == HOST_NEW) {
			ఒకవేళ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			లేకపోతే ఒకవేళ (!కూడు_host_గమ్యం_hostfile(user_hostfiles[0], ip,
			    host_కీలకం, options.hash_తెలిసిన_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			లేకపోతే
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} లేకపోతే ఒకవేళ (options.visual_host_కీలకం) {
			fp = sshkey_fingerprint(host_కీలకం,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_కీలకం,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			విడుదల(ra);
			విడుదల(fp);
		}
		hostkey_trusted = 1;
		ఆపు;
	స్థితి HOST_NEW:
		ఒకవేళ (options.host_కీలకం_alias == ఖాళీ && పోర్టు != 0 &&
		    పోర్టు != SSH_DEFAULT_పోర్టు && !clobber_పోర్టు) {
			debug("checking without port identifier");
			ఒకవేళ (check_host_కీలకం(hostname, cinfo, hostaddr, 0,
			    host_కీలకం, ROQUIET, 1,
			    user_hostfiles, అంకె_user_hostfiles,
			    system_hostfiles, అంకె_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				ఆపు;
			}
		}
		ఒకవేళ (readonly || want_cert)
			వెళ్ళు fail;
		/* The host is new. */
		ఒకవేళ (options.strict_host_కీలకం_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (options.strict_host_కీలకం_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			అక్షరం *msg1 = ఖాళీ, *msg2 = ఖాళీ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ఒకవేళ (show_other_కీలకాలు(host_hostkeys, host_కీలకం)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} లేకపోతే
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_కీలకం,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_కీలకం,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ఒకవేళ (options.visual_host_కీలకం)
				xextendf(&msg1, "\n", "%s", ra);
			ఒకవేళ (options.verify_host_కీలకం_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_కీలకం_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ఒకవేళ ((msg2 = other_hostkeys_సందేశం(host, ip, host_కీలకం,
			    user_hostfiles, అంకె_user_hostfiles,
			    system_hostfiles, అంకె_system_hostfiles)) != ఖాళీ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			విడుదల(ra);
			విడుదల(fp);
			విడుదల(msg1);
			విడుదల(msg2);
			ఒకవేళ (!confirmed)
				వెళ్ళు fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ఒకవేళ (options.check_host_ip && ip_స్థితి == HOST_NEW) {
			snprintf(hostline, పరిమాణం(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ఒకవేళ (options.hash_తెలిసిన_hosts) {
				/* Add hash of host and IP separately */
				r = కూడు_host_గమ్యం_hostfile(user_hostfiles[0],
				    host, host_కీలకం, options.hash_తెలిసిన_hosts) &&
				    కూడు_host_గమ్యం_hostfile(user_hostfiles[0], ip,
				    host_కీలకం, options.hash_తెలిసిన_hosts);
			} లేకపోతే {
				/* Add unhashed "host,ip" */
				r = కూడు_host_గమ్యం_hostfile(user_hostfiles[0],
				    hostline, host_కీలకం,
				    options.hash_తెలిసిన_hosts);
			}
		} లేకపోతే {
			r = కూడు_host_గమ్యం_hostfile(user_hostfiles[0], host,
			    host_కీలకం, options.hash_తెలిసిన_hosts);
			hostp = host;
		}

		ఒకవేళ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		లేకపోతే
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		ఆపు;
	స్థితి HOST_REVOKED:
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@       WARNING: REVOKED HOST KEY DETECTED!               @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("The %s host key for %s is marked as revoked.", type, host);
		error("This could mean that a stolen key is being used to");
		error("impersonate this host.");

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ఒకవేళ (options.strict_host_కీలకం_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			వెళ్ళు fail;
		}
		వెళ్ళు continue_unsafe;

	స్థితి HOST_మారింది:
		ఒకవేళ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_దొరికింది->file, host_దొరికింది->పంక్తి);
			వెళ్ళు fail;
		}
		ఒకవేళ (readonly == ROQUIET)
			వెళ్ళు fail;
		ఒకవేళ (options.check_host_ip && host_ip_తేడా) {
			అక్షరం *కీలకం_సందేశం;
			ఒకవేళ (ip_స్థితి == HOST_NEW)
				కీలకం_సందేశం = "is unknown";
			లేకపోతే ఒకవేళ (ip_స్థితి == HOST_OK)
				కీలకం_సందేశం = "is unchanged";
			లేకపోతే
				కీలకం_సందేశం = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", కీలకం_సందేశం);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ఒకవేళ (ip_స్థితి != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_దొరికింది->file, ip_దొరికింది->పంక్తి);
		}
		/* The host key has changed. */
		warn_మారింది_కీలకం(host_కీలకం);
		ఒకవేళ (అంకె_user_hostfiles > 0 || అంకె_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", అంకె_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_దొరికింది->కీలకం),
		    host_దొరికింది->file, host_దొరికింది->పంక్తి);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ఒకవేళ (options.strict_host_కీలకం_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			వెళ్ళు fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ఒకవేళ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.అంకె_local_forwards > 0 ||
		    options.అంకె_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.అంకె_local_forwards =
			    options.అంకె_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ఒకవేళ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ఒకవేళ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		ఆపు;
	స్థితి HOST_దొరికింది:
		fatal("internal error");
		ఆపు;
	}

	ఒకవేళ (options.check_host_ip && host_స్థితి != HOST_మారింది &&
	    ip_స్థితి == HOST_మారింది) {
		snprintf(సందేశం, పరిమాణం(సందేశం),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_దొరికింది->file, ip_దొరికింది->పంక్తి);
		ఒకవేళ (host_స్థితి == HOST_OK) {
			len = అక్షరశ్రేణి_పొడవు(సందేశం);
			snprintf(సందేశం + len, పరిమాణం(సందేశం) - len,
			    "\nMatching host key in %s:%lu",
			    host_దొరికింది->file, host_దొరికింది->పంక్తి);
		}
		ఒకవేళ (options.strict_host_కీలకం_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(సందేశం, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", పరిమాణం(సందేశం));
			ఒకవేళ (!confirm(సందేశం, ఖాళీ))
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (options.strict_host_కీలకం_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", సందేశం);
			error("Exiting, you have requested strict checking.");
			వెళ్ళు fail;
		} లేకపోతే {
			logit("%s", సందేశం);
		}
	}

	ఒకవేళ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_కీలకం);
	విడుదల(ip);
	విడుదల(host);
	ఒకవేళ (host_hostkeys != ఖాళీ)
		free_hostkeys(host_hostkeys);
	ఒకవేళ (ip_hostkeys != ఖాళీ)
		free_hostkeys(ip_hostkeys);
	తిరిగి 0;

fail:
	ఒకవేళ (want_cert && host_స్థితి != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(host_కీలకం, &raw_కీలకం)) != 0)
			fatal_fr(r, "decode key");
		ఒకవేళ ((r = sshkey_drop_cert(raw_కీలకం)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_కీలకం = raw_కీలకం;
		వెళ్ళు retry;
	}
	sshkey_free(raw_కీలకం);
	విడుదల(ip);
	విడుదల(host);
	ఒకవేళ (host_hostkeys != ఖాళీ)
		free_hostkeys(host_hostkeys);
	ఒకవేళ (ip_hostkeys != ఖాళీ)
		free_hostkeys(ip_hostkeys);
	తిరిగి -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
పూర్ణాంకం
verify_host_కీలకం(అక్షరం *host, నిర్మాణం sockaddr *hostaddr, నిర్మాణం sshkey *host_కీలకం,
    స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	u_int i;
	పూర్ణాంకం r = -1, flags = 0;
	అక్షరం valid[64], *fp = ఖాళీ, *cafp = ఖాళీ;
	నిర్మాణం sshkey *plain = ఖాళీ;

	ఒకవేళ ((fp = sshkey_fingerprint(host_కీలకం,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (sshkey_is_cert(host_కీలకం)) {
		ఒకవేళ ((cafp = sshkey_fingerprint(host_కీలకం->cert->signature_కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			వెళ్ళు బహిర్గతం;
		}
		sshkey_format_cert_validity(host_కీలకం->cert,
		    valid, పరిమాణం(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_కీలకం), fp,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)host_కీలకం->cert->serial,
		    host_కీలకం->cert->కీలకం_id,
		    sshkey_ssh_name(host_కీలకం->cert->signature_కీలకం), cafp,
		    valid);
		కొరకు (i = 0; i < host_కీలకం->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_కీలకం->cert->principals[i]);
		}
	} లేకపోతే {
		debug("Server host key: %s %s", sshkey_ssh_name(host_కీలకం), fp);
	}

	ఒకవేళ (sshkey_equal(మునుపటి_host_కీలకం, host_కీలకం)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_కీలకం), fp);
		r = 0;
		వెళ్ళు బహిర్గతం;
	}

	/* Check in RevokedHostKeys files if specified */
	కొరకు (i = 0; i < options.అంకె_revoked_host_కీలకాలు; i++) {
		r = sshkey_check_revoked(host_కీలకం,
		    options.revoked_host_కీలకాలు[i]);
		ఎంపిక (r) {
		స్థితి 0:
			ఆపు; /* not revoked */
		స్థితి SSH_ERR_కీలకం_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_కీలకం), fp,
			    options.revoked_host_కీలకాలు[i]);
			r = -1;
			వెళ్ళు బహిర్గతం;
		అప్రమేయ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_కీలకం),
			    fp, options.revoked_host_కీలకాలు[i]);
			r = -1;
			వెళ్ళు బహిర్గతం;
		}
	}

	ఒకవేళ (options.verify_host_కీలకం_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(host_కీలకం, &plain)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ఒకవేళ (verify_host_కీలకం_dns(host, hostaddr, plain, &flags) == 0) {
			ఒకవేళ (flags & DNS_VERIFY_దొరికింది) {
				ఒకవేళ (options.verify_host_కీలకం_dns == 1 &&
				    flags & DNS_VERIFY_సరిపోలిక &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					వెళ్ళు బహిర్గతం;
				}
				ఒకవేళ (flags & DNS_VERIFY_సరిపోలిక) {
					matching_host_కీలకం_dns = 1;
				} లేకపోతే {
					warn_మారింది_కీలకం(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_కీలకం(host, cinfo, hostaddr, options.పోర్టు, host_కీలకం,
	    RDRW, 0, options.user_hostfiles, options.అంకె_user_hostfiles,
	    options.system_hostfiles, options.అంకె_system_hostfiles,
	    options.తెలిసిన_hosts_command);

బహిర్గతం:
	sshkey_free(plain);
	విడుదల(fp);
	విడుదల(cafp);
	ఒకవేళ (r == 0 && host_కీలకం != ఖాళీ) {
		sshkey_free(మునుపటి_host_కీలకం);
		r = sshkey_from_వ్యక్తిగత(host_కీలకం, &మునుపటి_host_కీలకం);
	}

	తిరిగి r;
}

స్థిర శూన్య
warn_nonpq_kex(శూన్య)
{
	logit("** WARNING: connection is not using a post-quantum key exchange algorithm.");
	logit("** This session may be vulnerable to \"store now, decrypt later\" attacks.");
	logit("** The server may need to be upgraded. See https://openssh.com/pq.html");
}

/*
 * Starts a dialog with the server, and authenticates the current user on the
 * server.  This does not need any extra privileges.  The basic connection
 * to the server must already have been established before this is called.
 * If login fails, this function prints an error and never returns.
 * This function does not require super-user privileges.
 */
శూన్య
ssh_login(నిర్మాణం ssh *ssh, Sensitive *sensitive, స్థిరరాశి అక్షరం *orighost,
    నిర్మాణం sockaddr_storage *hostaddr, u_short పోర్టు, నిర్మాణం passwd *pw,
    పూర్ణాంకం timeout_ms, స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	అక్షరం *host;
	అక్షరం *server_user, *local_user;
	పూర్ణాంకం r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ఒకవేళ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.సంస్కరణ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ఒకవేళ ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_సమితి_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, పోర్టు, server_user);
	ssh_kex2(ssh, host, hostaddr, పోర్టు, cinfo);
	kex_సమితి_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_సమితి);
	ఒకవేళ (!options.kex_algorithms_సమితి && ssh->kex != ఖాళీ &&
	    ssh->kex->name != ఖాళీ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	విడుదల(local_user);
	విడుదల(host);
}

/* print all known host keys for a given host, but skip keys of given type */
స్థిర పూర్ణాంకం
show_other_కీలకాలు(నిర్మాణం hostkeys *hostkeys, నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం type[] = {
		కీలకం_RSA,
		కీలకం_ECDSA,
		కీలకం_ED25519,
		కీలకం_MLDSA44_ED25519,
		-1
	};
	పూర్ణాంకం i, ret = 0;
	అక్షరం *fp, *ra;
	స్థిరరాశి నిర్మాణం hostkey_నమోదు *దొరికింది;

	కొరకు (i = 0; type[i] != -1; i++) {
		ఒకవేళ (type[i] == కీలకం->type)
			కొనసాగు;
		ఒకవేళ (!lookup_కీలకం_లోపల_hostkeys_by_type(hostkeys, type[i],
		    -1, &దొరికింది))
			కొనసాగు;
		fp = sshkey_fingerprint(దొరికింది->కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(దొరికింది->కీలకం,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(దొరికింది->కీలకం),
		    దొరికింది->host, దొరికింది->file, దొరికింది->పంక్తి,
		    sshkey_type(దొరికింది->కీలకం), fp);
		ఒకవేళ (options.visual_host_కీలకం)
			logit("%s", ra);
		విడుదల(ra);
		విడుదల(fp);
		ret = 1;
	}
	తిరిగి ret;
}

స్థిర శూన్య
warn_మారింది_కీలకం(నిర్మాణం sshkey *host_కీలకం)
{
	అక్షరం *fp;

	fp = sshkey_fingerprint(host_కీలకం, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ఒకవేళ (fp == ఖాళీ)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_కీలకం), fp);
	error("Please contact your system administrator.");

	విడుదల(fp);
}

/*
 * Execute a local command
 */
పూర్ణాంకం
ssh_local_cmd(స్థిరరాశి అక్షరం *వాదనలు)
{
	అక్షరం *shell;
	pid_t pid;
	పూర్ణాంకం స్థితి_2;
	శూన్య (*osighand)(పూర్ణాంకం);

	ఒకవేళ (!options.permit_local_command ||
	    వాదనలు == ఖాళీ || !*వాదనలు)
		తిరిగి (1);

	ఒకవేళ ((shell = getenv("SHELL")) == ఖాళీ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ఒకవేళ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, వాదనలు);
		execl(shell, shell, "-c", వాదనలు, (అక్షరం *)ఖాళీ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, వాదనలు, strerror(errno));
		_exit(1);
	} లేకపోతే ఒకవేళ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	అయితే (waitpid(pid, &స్థితి_2, 0) == -1)
		ఒకవేళ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ఒకవేళ (!WIFEXITED(స్థితి_2))
		తిరిగి (1);

	తిరిగి (WEXITSTATUS(స్థితి_2));
}

శూన్య
maybe_కూడు_కీలకం_గమ్యం_agent(స్థిరరాశి అక్షరం *authfile, నిర్మాణం sshkey *అంతరంగ,
    స్థిరరాశి అక్షరం *comment, స్థిరరాశి అక్షరం *passphrase)
{
	పూర్ణాంకం auth_sock = -1, r;
	స్థిరరాశి అక్షరం *skprovider = ఖాళీ;

	ఒకవేళ (options.కూడు_కీలకాలు_గమ్యం_agent == 0)
		తిరిగి;

	ఒకవేళ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		తిరిగి;
	}

	ఒకవేళ (options.కూడు_కీలకాలు_గమ్యం_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		తిరిగి;
	}
	ఒకవేళ (sshkey_is_sk(అంతరంగ))
		skprovider = options.sk_provider;
	ఒకవేళ ((r = ssh_కూడు_తటస్థం_constrained(auth_sock, అంతరంగ,
	    comment == ఖాళీ ? authfile : comment,
	    options.కూడు_కీలకాలు_గమ్యం_agent_lifespan,
	    (options.కూడు_కీలకాలు_గమ్యం_agent == 3), skprovider, ఖాళీ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	లేకపోతే
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
