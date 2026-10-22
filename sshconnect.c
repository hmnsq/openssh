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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <net/if.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <ifaddrs.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshconnect.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "dns.h"
#ଅନ୍ତର୍ଭାଵ "monitor_fdpass.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"

ସଂରଚନା sshkey *previous_host_ଚାବି = ଖାଲି;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା matching_host_ଚାବି_dns = 0;

ସ୍ଥିର pid_t proxy_command_pid = 0;

/* import */
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag;
ବାହ୍ୟ Options options;
ବାହ୍ୟ ଅକ୍ଷର *__progname;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା show_other_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା hostkeys *, ସଂରଚନା sshkey *);
ସ୍ଥିର ଶୂନ୍ୟ warn_changed_ଚାବି(ସଂରଚନା sshkey *);

ଶୂନ୍ୟ
ssh_conn_info_free(ସଂରଚନା ssh_conn_info *cinfo)
{
	ଯଦି (cinfo == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(cinfo->conn_hash_hex);
	ମୁକ୍ତ(cinfo->shorthost);
	ମୁକ୍ତ(cinfo->uidstr);
	ମୁକ୍ତ(cinfo->keyalias);
	ମୁକ୍ତ(cinfo->thishost);
	ମୁକ୍ତ(cinfo->host_arg);
	ମୁକ୍ତ(cinfo->portstr);
	ମୁକ୍ତ(cinfo->remhost);
	ମୁକ୍ତ(cinfo->remuser);
	ମୁକ୍ତ(cinfo->homedir);
	ମୁକ୍ତ(cinfo->locuser);
	ମୁକ୍ତ(cinfo->jmphost);
	freezero(cinfo, ଆକାର(*cinfo));
}

ସଂରଚନା ssh_conn_info *
ssh_conn_info_dup(ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ସଂରଚନା ssh_conn_info *ret;

	ଯଦି (cinfo == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ret = xcalloc(1, ଆକାର(*ret));
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
	ଫେରନ୍ତୁ ret;
}

/* Expand a proxy command */
ସ୍ଥିର ଅକ୍ଷର *
expand_proxy_command(ଅଚଳ ଅକ୍ଷର *proxy_command, ଅଚଳ ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *host_arg, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ଅକ୍ଷର *tmp, *ret, strport[NI_MAXSERV];
	ଅଚଳ ଅକ୍ଷର *keyalias = options.host_ଚାବି_alias ?
	    options.host_ଚାବି_alias : host_arg;

	snprintf(strport, ଆକାର strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (ଅକ୍ଷର *)ଖାଲି);
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_proxy_fdpass_connect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *host_arg, u_short port, ଅଚଳ ଅକ୍ଷର *proxy_command)
{
	ଅକ୍ଷର *command_string;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sp[2], sock;
	pid_t pid;
	ଅକ୍ଷର *shell;

	ଯଦି ((shell = getenv("SHELL")) == ଖାଲି)
		shell = _PATH_BSHELL;

	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ଯଦି ((pid = fork()) == 0) {
		ଅକ୍ଷର *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ଯଦି (sp[0] != 0) {
			ଯଦି (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ଯଦି (sp[0] != 1) {
			ଯଦି (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ଯଦି (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ଯଦି (!debug_flag && options.control_path != ଖାଲି &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ଖାଲି;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	ଯଦି (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	ମୁକ୍ତ(command_string);

	ଯଦି ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ଯେତେବେଳେ (waitpid(pid, ଖାଲି, 0) == -1)
		ଯଦି (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ଯଦି (ssh_packet_set_connection(ssh, sock, sock) == ଖାଲି)
		ଫେରନ୍ତୁ -1; /* ssh_packet_set_connection logs error */

	ଫେରନ୍ତୁ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_proxy_connect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *host_arg,
    u_short port, ଅଚଳ ଅକ୍ଷର *proxy_command)
{
	ଅକ୍ଷର *command_string;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pin[2], pout[2];
	pid_t pid;
	ଅକ୍ଷର *shell;

	ଯଦି ((shell = getenv("SHELL")) == ଖାଲି || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ଯଦି (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ଯଦି ((pid = fork()) == 0) {
		ଅକ୍ଷର *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ଯଦି (pin[0] != 0) {
			ଯଦି (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ଯଦି (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ଯଦି (!debug_flag && options.control_path != ଖାଲି &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ଖାଲି;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	ଯଦି (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ଅନ୍ୟଥା
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	ମୁକ୍ତ(command_string);

	/* Set the connection file descriptors. */
	ଯଦି (ssh_packet_set_connection(ssh, pout[0], pin[1]) == ଖାଲି)
		ଫେରନ୍ତୁ -1; /* ssh_packet_set_connection logs error */

	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_kill_proxy_command(ଶୂନ୍ୟ)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ଯଦି (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_ifaddrs(ଅଚଳ ଅକ୍ଷର *ifname, ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, ଅଚଳ ସଂରଚନା ifaddrs *ifaddrs,
    ସଂରଚନା sockaddr_storage *resultp, socklen_t *rlenp)
{
	ସଂରଚନା sockaddr_in6 *sa6;
	ସଂରଚନା sockaddr_in *sa;
	ସଂରଚନା in6_addr *v6addr;
	ଅଚଳ ସଂରଚନା ifaddrs *ifa;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	ପାଇଁ (allow_local = 0; allow_local < 2; allow_local++) {
		ପାଇଁ (ifa = ifaddrs; ifa != ଖାଲି; ifa = ifa->ifa_next) {
			ଯଦି (ifa->ifa_addr == ଖାଲି || ifa->ifa_name == ଖାଲି ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ଜାରି;
			ବାଛ (ifa->ifa_addr->sa_family) {
			ସ୍ଥିତି AF_INET:
				sa = (ସଂରଚନା sockaddr_in *)ifa->ifa_addr;
				ଯଦି (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ଜାରି;
				ଯଦି (*rlenp < ଆକାର(ସଂରଚନା sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ଫେରନ୍ତୁ -1;
				}
				*rlenp = ଆକାର(ସଂରଚନା sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				ଫେରନ୍ତୁ 0;
			ସ୍ଥିତି AF_INET6:
				sa6 = (ସଂରଚନା sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ଯଦି (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ଜାରି;
				ଯଦି (*rlenp < ଆକାର(ସଂରଚନା sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ଫେରନ୍ତୁ -1;
				}
				*rlenp = ଆକାର(ସଂରଚନା sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				ଫେରନ୍ତୁ 0;
			}
		}
	}
	ଫେରନ୍ତୁ -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_create_socket(ସଂରଚନା addrinfo *ai)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, r;
	ସଂରଚନା sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ସଂରଚନା addrinfo hints, *res = ଖାଲି;
#ifdef HAVE_IFADDRS_H
	ସଂରଚନା ifaddrs *ifaddrs = ଖାଲି;
#endif
	ଅକ୍ଷର ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ଯଦି (sock == -1) {
		error("socket: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	(ଶୂନ୍ୟ)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ଯଦି (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ଯଦି (options.bind_address == ଖାଲି && options.bind_interface == ଖାଲି)
		ଫେରନ୍ତୁ sock;

	ଯଦି (options.bind_address != ଖାଲି) {
		memset(&hints, 0, ଆକାର(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ଯଦି ((r = getaddrinfo(options.bind_address, ଖାଲି,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			ଯାଅ fail;
		}
		ଯଦି (res == ଖାଲି) {
			error("getaddrinfo: no addrs");
			ଯାଅ fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ଅନ୍ୟଥା ଯଦି (options.bind_interface != ଖାଲି) {
#ifdef HAVE_IFADDRS_H
		ଯଦି ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			ଯାଅ fail;
		}
		bindaddrlen = ଆକାର(bindaddr);
		ଯଦି (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			ଯାଅ fail;
		}
#ଅନ୍ୟଥା
		error("BindInterface not supported on this platform.");
#endif
	}
	ଯଦି ((r = getnameinfo((ସଂରଚନା sockaddr *)&bindaddr, bindaddrlen,
	    ntop, ଆକାର(ntop), ଖାଲି, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		ଯାଅ fail;
	}
	ଯଦି (bind(sock, (ସଂରଚନା sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		ଯାଅ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	ଯାଅ out;
fail:
	close(sock);
	sock = -1;
 out:
	ଯଦି (res != ଖାଲି)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	ଯଦି (ifaddrs != ଖାଲି)
		freeifaddrs(ifaddrs);
#endif
	ଫେରନ୍ତୁ sock;
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_connect_direct(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା addrinfo *aitop,
    ସଂରଚନା sockaddr_storage *hostaddr, u_short port, ପୂର୍ଣ୍ଣସଂଖ୍ୟା connection_attempts,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *timeout_ms, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_keepalive)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_timeout_ms = *timeout_ms;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, sock = -1, attempt;
	ଅକ୍ଷର ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ସଂରଚନା addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, ଆକାର(ntop));
	memset(strport, 0, ଆକାର(strport));

	ପାଇଁ (attempt = 0; attempt < connection_attempts; attempt++) {
		ଯଦି (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		ପାଇଁ (ai = aitop; ai; ai = ai->ai_next) {
			ଯଦି (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ଜାରି;
			}
			ଯଦି (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, ଆକାର(ntop), strport, ଆକାର(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ଜାରି;
			}
			ଯଦି (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ଜାରି;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ଯଦି (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ଜାରି;
			}

			*timeout_ms = saved_timeout_ms;
			ଯଦି (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				ଭାଙ୍ଗ;
			} ଅନ୍ୟଥା {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ଯଦି (sock != -1)
			ଭାଙ୍ଗ;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ଯଦି (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ଯଦି (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ଯଦି (ssh_packet_set_connection(ssh, sock, sock) == ଖାଲି)
		ଫେରନ୍ତୁ -1; /* ssh_packet_set_connection logs error */

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_connect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *host_arg,
    ସଂରଚନା addrinfo *addrs, ସଂରଚନା sockaddr_storage *hostaddr, u_short port,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା connection_attempts, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *timeout_ms, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_keepalive)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା in, out;

	ଯଦି (options.proxy_command == ଖାଲି) {
		ଫେରନ୍ତୁ ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} ଅନ୍ୟଥା ଯଦି (strcmp(options.proxy_command, "-") == 0) {
		ଯଦି ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			ଯଦି (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			ଫେରନ୍ତୁ -1; /* ssh_packet_set_connection logs error */
		}
		ଯଦି ((ssh_packet_set_connection(ssh, in, out)) == ଖାଲି)
			ଫେରନ୍ତୁ -1; /* ssh_packet_set_connection logs error */
		ଫେରନ୍ତୁ 0;
	} ଅନ୍ୟଥା ଯଦି (options.proxy_use_fdpass) {
		ଫେରନ୍ତୁ ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	ଫେରନ୍ତୁ ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
confirm(ଅଚଳ ଅକ୍ଷର *prompt, ଅଚଳ ଅକ୍ଷର *fingerprint)
{
	ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ, *again = "Please type 'yes' or 'no': ";
	ଅଚଳ ଅକ୍ଷର *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	ଅକ୍ଷର *p, *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (options.batch_mode)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (ସନ୍ଦେଶ = prompt;;ସନ୍ଦେଶ = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(ସନ୍ଦେଶ, RP_ECHO);
		ଯଦି (p == ଖାଲି)
			ଫେରନ୍ତୁ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ଯଦି (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ଅନ୍ୟଥା ଯଦି (strcasecmp(p, "yes") == 0 || (fingerprint != ଖାଲି &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		ମୁକ୍ତ(cp);
		ଯଦି (ret != -1)
			ଫେରନ୍ତୁ ret;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sockaddr_is_local(ସଂରଚନା sockaddr *hostaddr)
{
	ବାଛ (hostaddr->sa_family) {
	ସ୍ଥିତି AF_INET:
		ଫେରନ୍ତୁ (ntohl(((ସଂରଚନା sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	ସ୍ଥିତି AF_INET6:
		ଫେରନ୍ତୁ IN6_IS_ADDR_LOOPBACK(
		    &(((ସଂରଚନା sockaddr_in6 *)hostaddr)->sin6_addr));
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
ଶୂନ୍ୟ
get_hostfile_hostname_ipaddr(ଅକ୍ଷର *hostname, ସଂରଚନା sockaddr *hostaddr,
    u_short port, ଅକ୍ଷର **hostfile_hostname, ଅକ୍ଷର **hostfile_ipaddr)
{
	ଅକ୍ଷର ntop[NI_MAXHOST];
	socklen_t addrlen;

	ବାଛ (hostaddr == ଖାଲି ? -1 : hostaddr->sa_family) {
	ସ୍ଥିତି -1:
		addrlen = 0;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET:
		addrlen = ଆକାର(ସଂରଚନା sockaddr_in);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
		addrlen = ଆକାର(ସଂରଚନା sockaddr_in6);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		addrlen = ଆକାର(ସଂରଚନା sockaddr);
		ଭାଙ୍ଗ;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ଯଦି (hostfile_ipaddr != ଖାଲି) {
		ଯଦି (options.proxy_command == ଖାଲି) {
			ଯଦି (getnameinfo(hostaddr, addrlen,
			    ntop, ଆକାର(ntop), ଖାଲି, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} ଅନ୍ୟଥା {
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
	ଯଦି (hostfile_hostname != ଖାଲି) {
		ଯଦି (options.host_ଚାବି_alias != ଖାଲି) {
			*hostfile_hostname = xstrdup(options.host_ଚାବି_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ଅନ୍ୟଥା {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
path_in_hostfiles(ଅଚଳ ଅକ୍ଷର *path, ଅକ୍ଷର **hostfiles, u_int ଅଙ୍କ_hostfiles)
{
	u_int i;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_hostfiles; i++) {
		ଯଦି (strcmp(path, hostfiles[i]) == 0)
			ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା find_by_ଚାବି_ctx {
	ଅଚଳ ଅକ୍ଷର *host, *ip;
	ଅଚଳ ସଂରଚନା sshkey *ଚାବି;
	ଅକ୍ଷର **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ସ୍ଥିର ଅକ୍ଷର *
try_tilde_unexpand(ଅଚଳ ଅକ୍ଷର *path)
{
	ଅକ୍ଷର *home, *ret = ଖାଲି;
	size_t l;

	ଯଦି (*path != '/')
		ଫେରନ୍ତୁ xstrdup(path);
	ଯଦି ((home = getenv("HOME")) == ଖାଲି || (l = strlen(home)) == 0)
		ଫେରନ୍ତୁ xstrdup(path);
	ଯଦି (strncmp(path, home, l) != 0)
		ଫେରନ୍ତୁ xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ଯଦି (home[l - 1] != '/' && path[l] != '/')
		ଫେରନ୍ତୁ xstrdup(path);
	ଯଦି (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	ଫେରନ୍ତୁ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostkey_accepted_by_hostkeyalgs(ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ଅଚଳ ଅକ୍ଷର *ktype = sshkey_ssh_name(ଚାବି);
	ଅଚଳ ଅକ୍ଷର *hostkeyalgs = options.hostkeyalgorithms;

	ଯଦି (ଚାବି->type == ଚାବି_UNSPEC)
		ଫେରନ୍ତୁ 0;
	ଯଦି (ଚାବି->type == ଚାବି_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ଫେରନ୍ତୁ 1;
	ଯଦି (ଚାବି->type == ଚାବି_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ଫେରନ୍ତୁ 1;
	ଫେରନ୍ତୁ match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostkeys_find_by_ଚାବି_cb(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା find_by_ଚାବି_ctx *ctx = (ସଂରଚନା find_by_ଚାବି_ctx *)_ctx;
	ଅକ୍ଷର *path;

	/* we are looking for keys with names that *do not* match */
	ଯଦି ((l->match & HKF_MATCH_HOST) != 0)
		ଫେରନ୍ତୁ 0;
	/* not interested in marker lines */
	ଯଦି (l->marker != MRK_NONE)
		ଫେରନ୍ତୁ 0;
	/* we are only interested in exact key matches */
	ଯଦି (l->ଚାବି == ଖାଲି || !sshkey_equal(ctx->ଚାବି, l->ଚାବି))
		ଫେରନ୍ତୁ 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, ଆକାର(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostkeys_find_by_ଚାବି_hostfile(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *which,
    ସଂରଚନା find_by_ଚାବି_ctx *ctx)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ଯଦି ((r = hostkeys_foreach(file, hostkeys_find_by_ଚାବି_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_ଚାବି, 0)) != 0) {
		ଯଦି (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ଫେରନ୍ତୁ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ସ୍ଥିର ଶୂନ୍ୟ
hostkeys_find_by_ଚାବି(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅକ୍ଷର **user_hostfiles, u_int ଅଙ୍କ_user_hostfiles,
    ଅକ୍ଷର **system_hostfiles, u_int ଅଙ୍କ_system_hostfiles,
    ଅକ୍ଷର ***names, u_int *nnames)
{
	ସଂରଚନା find_by_ଚାବି_ctx ctx = {ଖାଲି, ଖାଲି, ଖାଲି, ଖାଲି, 0};
	u_int i;

	*names = ଖାଲି;
	*nnames = 0;

	ଯଦି (ଚାବି == ଖାଲି || sshkey_is_cert(ଚାବି))
		ଫେରନ୍ତୁ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.ଚାବି = ଚାବି;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_user_hostfiles; i++) {
		ଯଦି (hostkeys_find_by_ଚାବି_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			ଯାଅ fail;
	}
	ପାଇଁ (i = 0; i < ଅଙ୍କ_system_hostfiles; i++) {
		ଯଦି (hostkeys_find_by_ଚାବି_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			ଯାଅ fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = ଖାଲି;
	ctx.nnames = 0;
	ଫେରନ୍ତୁ;
 fail:
	ପାଇଁ (i = 0; i < ctx.nnames; i++)
		ମୁକ୍ତ(ctx.names[i]);
	ମୁକ୍ତ(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
ସ୍ଥିର ଅକ୍ଷର *
other_hostkeys_message(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip,
    ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅକ୍ଷର **user_hostfiles, u_int ଅଙ୍କ_user_hostfiles,
    ଅକ୍ଷର **system_hostfiles, u_int ଅଙ୍କ_system_hostfiles)
{
	ଅକ୍ଷର *ret = ଖାଲି, **othernames = ଖାଲି;
	u_int i, n, ଅଙ୍କ_othernames = 0;

	hostkeys_find_by_ଚାବି(host, ip, ଚାବି,
	    user_hostfiles, ଅଙ୍କ_user_hostfiles,
	    system_hostfiles, ଅଙ୍କ_system_hostfiles,
	    &othernames, &ଅଙ୍କ_othernames);
	ଯଦି (ଅଙ୍କ_othernames == 0)
		ଫେରନ୍ତୁ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = ଅଙ୍କ_othernames;
	ଯଦି (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	ପାଇଁ (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ଯଦି (n < ଅଙ୍କ_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    ଅଙ୍କ_othernames - n);
	}
	ପାଇଁ (i = 0; i < ଅଙ୍କ_othernames; i++)
		ମୁକ୍ତ(othernames[i]);
	ମୁକ୍ତ(othernames);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
load_hostkeys_command(ସଂରଚନା hostkeys *hostkeys, ଅଚଳ ଅକ୍ଷର *command_template,
    ଅଚଳ ଅକ୍ଷର *invocation, ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo,
    ଅଚଳ ସଂରଚନା sshkey *host_ଚାବି, ଅଚଳ ଅକ୍ଷର *hostfile_hostname)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ac = 0;
	ଅକ୍ଷର *ଚାବି_fp = ଖାଲି, *keytext = ଖାଲି, *tmp;
	ଅକ୍ଷର *command = ଖାଲି, *tag = ଖାଲି, **av = ଖାଲି;
	FILE *f = ଖାଲି;
	pid_t pid;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	ଯଦି (host_ଚାବି != ଖାଲି) {
		ଯଦି ((ଚାବି_fp = sshkey_fingerprint(host_ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("sshkey_fingerprint failed");
		ଯଦି ((r = sshkey_to_base64(host_ଚାବି, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ଯଦି (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		ଯାଅ out;
	}
	ଯଦି (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		ଯାଅ out;
	}
	ପାଇଁ (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_ଚାବି == ଖାଲି ? "NONE" : sshkey_ssh_name(host_ଚାବି),
		    "f", ଚାବି_fp == ଖାଲି ? "NONE" : ଚାବି_fp,
		    "K", keytext == ଖାଲି ? "NONE" : keytext,
		    (ଅକ୍ଷର *)ଖାଲି);
		ଯଦି (tmp == ଖାଲି)
			fatal_f("percent_expand failed");
		ମୁକ୍ତ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ଯଦି ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, ଖାଲି, ଖାଲି, ଖାଲି)) == 0)
		ଯାଅ out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	ଯଦି (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	ଯଦି (f != ଖାଲି)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ପାଇଁ (i = 0; i < ac; i++)
		ମୁକ୍ତ(av[i]);
	ମୁକ୍ତ(av);
	ମୁକ୍ତ(tag);
	ମୁକ୍ତ(command);
	ମୁକ୍ତ(ଚାବି_fp);
	ମୁକ୍ତ(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_host_ଚାବି(ଅକ୍ଷର *hostname, ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo,
    ସଂରଚନା sockaddr *hostaddr, u_short port,
    ସଂରଚନା sshkey *host_ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା readonly, ପୂର୍ଣ୍ଣସଂଖ୍ୟା clobber_port,
    ଅକ୍ଷର **user_hostfiles, u_int ଅଙ୍କ_user_hostfiles,
    ଅକ୍ଷର **system_hostfiles, u_int ଅଙ୍କ_system_hostfiles,
    ଅଚଳ ଅକ୍ଷର *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	ସଂରଚନା sshkey *raw_ଚାବି = ଖାଲି;
	ଅକ୍ଷର *ip = ଖାଲି, *host = ଖାଲି;
	ଅକ୍ଷର hostline[1000], *hostp, *fp, *ra;
	ଅକ୍ଷର ସନ୍ଦେଶ[1024];
	ଅଚଳ ଅକ୍ଷର *type, *fail_reason = ଖାଲି;
	ଅଚଳ ସଂରଚନା hostkey_entry *host_found = ଖାଲି, *ip_found = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len, cancelled_forwarding = 0, confirmed;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା local = sockaddr_is_local(hostaddr);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, want_cert = sshkey_is_cert(host_ଚାବି), host_ip_differ = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ସଂରଚନା hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ଯଦି (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_ଚାବି_alias == ଖାଲି) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ଯଦି (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_port ? 0 : port, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	ଯଦି (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ଖାଲି))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	ପାଇଁ (i = 0; i < ଅଙ୍କ_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	ପାଇଁ (i = 0; i < ଅଙ୍କ_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ଯଦି (hostfile_command != ଖାଲି && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_ଚାବି, host);
	}

	ip_hostkeys = ଖାଲି;
	ଯଦି (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		ପାଇଁ (i = 0; i < ଅଙ୍କ_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		ପାଇଁ (i = 0; i < ଅଙ୍କ_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ଯଦି (hostfile_command != ଖାଲି && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_ଚାବି, ip);
		}
	}

 retry:
	ଯଦି (!hostkey_accepted_by_hostkeyalgs(host_ଚାବି)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_ଚାବି));
		ଯାଅ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_ଚାବି);
	type = sshkey_type(host_ଚାବି);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_ଚାବି_in_hostkeys(host_hostkeys, host_ଚାବି,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ଯଦି (!readonly && (ଅଙ୍କ_user_hostfiles == 0 ||
	    (host_found != ଖାଲି && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ଯଦି (!want_cert && ip_hostkeys != ଖାଲି) {
		ip_status = check_ଚାବି_in_hostkeys(ip_hostkeys, host_ଚାବି,
		    &ip_found);
		ଯଦି (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != ଖାଲି &&
		    !sshkey_equal(ip_found->ଚାବି, host_found->ଚାବି))))
			host_ip_differ = 1;
	} ଅନ୍ୟଥା
		ip_status = host_status;

	ବାଛ (host_status) {
	ସ୍ଥିତି HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->ଧାଡ଼ି);
		ଯଦି (want_cert) {
			ଯଦି (sshkey_cert_check_host(host_ଚାବି,
			    options.host_ଚାବି_alias == ଖାଲି ?
			    hostname : options.host_ଚାବି_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				ଯାଅ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ଯଦି (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ଯଦି (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, ଅଙ୍କ_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != ଖାଲି &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, ଅଙ୍କ_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ଯଦି (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ଯଦି (options.check_host_ip && ip_status == HOST_NEW) {
			ଯଦି (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ଅନ୍ୟଥା ଯଦି (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_ଚାବି, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ଅନ୍ୟଥା
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ଅନ୍ୟଥା ଯଦି (options.visual_host_ଚାବି) {
			fp = sshkey_fingerprint(host_ଚାବି,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ଚାବି,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			ମୁକ୍ତ(ra);
			ମୁକ୍ତ(fp);
		}
		hostkey_trusted = 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି HOST_NEW:
		ଯଦି (options.host_ଚାବି_alias == ଖାଲି && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			ଯଦି (check_host_ଚାବି(hostname, cinfo, hostaddr, 0,
			    host_ଚାବି, ROQUIET, 1,
			    user_hostfiles, ଅଙ୍କ_user_hostfiles,
			    system_hostfiles, ଅଙ୍କ_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (readonly || want_cert)
			ଯାଅ fail;
		/* The host is new. */
		ଯଦି (options.strict_host_ଚାବି_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (options.strict_host_ଚାବି_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			ଅକ୍ଷର *msg1 = ଖାଲି, *msg2 = ଖାଲି;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ଯଦି (show_other_ଚାବିଗୁଡ଼ିକ(host_hostkeys, host_ଚାବି)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ଅନ୍ୟଥା
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_ଚାବି,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ଚାବି,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ଯଦି (options.visual_host_ଚାବି)
				xextendf(&msg1, "\n", "%s", ra);
			ଯଦି (options.verify_host_ଚାବି_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_ଚାବି_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ଯଦି ((msg2 = other_hostkeys_message(host, ip, host_ଚାବି,
			    user_hostfiles, ଅଙ୍କ_user_hostfiles,
			    system_hostfiles, ଅଙ୍କ_system_hostfiles)) != ଖାଲି)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			ମୁକ୍ତ(ra);
			ମୁକ୍ତ(fp);
			ମୁକ୍ତ(msg1);
			ମୁକ୍ତ(msg2);
			ଯଦି (!confirmed)
				ଯାଅ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ଯଦି (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, ଆକାର(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ଯଦି (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_ଚାବି, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_ଚାବି, options.hash_known_hosts);
			} ଅନ୍ୟଥା {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_ଚାବି,
				    options.hash_known_hosts);
			}
		} ଅନ୍ୟଥା {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_ଚାବି, options.hash_known_hosts);
			hostp = host;
		}

		ଯଦି (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ଅନ୍ୟଥା
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି HOST_REVOKED:
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
		ଯଦି (options.strict_host_ଚାବି_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			ଯାଅ fail;
		}
		ଯାଅ continue_unsafe;

	ସ୍ଥିତି HOST_CHANGED:
		ଯଦି (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->ଧାଡ଼ି);
			ଯାଅ fail;
		}
		ଯଦି (readonly == ROQUIET)
			ଯାଅ fail;
		ଯଦି (options.check_host_ip && host_ip_differ) {
			ଅକ୍ଷର *ଚାବି_ସନ୍ଦେଶ;
			ଯଦି (ip_status == HOST_NEW)
				ଚାବି_ସନ୍ଦେଶ = "is unknown";
			ଅନ୍ୟଥା ଯଦି (ip_status == HOST_OK)
				ଚାବି_ସନ୍ଦେଶ = "is unchanged";
			ଅନ୍ୟଥା
				ଚାବି_ସନ୍ଦେଶ = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", ଚାବି_ସନ୍ଦେଶ);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ଯଦି (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->ଧାଡ଼ି);
		}
		/* The host key has changed. */
		warn_changed_ଚାବି(host_ଚାବି);
		ଯଦି (ଅଙ୍କ_user_hostfiles > 0 || ଅଙ୍କ_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", ଅଙ୍କ_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->ଚାବି),
		    host_found->file, host_found->ଧାଡ଼ି);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ଯଦି (options.strict_host_ଚାବି_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			ଯାଅ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ଯଦି (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.ଅଙ୍କ_local_forwards > 0 ||
		    options.ଅଙ୍କ_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.ଅଙ୍କ_local_forwards =
			    options.ଅଙ୍କ_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ଯଦି (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ଯଦି (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି HOST_FOUND:
		fatal("internal error");
		ଭାଙ୍ଗ;
	}

	ଯଦି (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->ଧାଡ଼ି);
		ଯଦି (host_status == HOST_OK) {
			len = strlen(ସନ୍ଦେଶ);
			snprintf(ସନ୍ଦେଶ + len, ଆକାର(ସନ୍ଦେଶ) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->ଧାଡ଼ି);
		}
		ଯଦି (options.strict_host_ଚାବି_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(ସନ୍ଦେଶ, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", ଆକାର(ସନ୍ଦେଶ));
			ଯଦି (!confirm(ସନ୍ଦେଶ, ଖାଲି))
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (options.strict_host_ଚାବି_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", ସନ୍ଦେଶ);
			error("Exiting, you have requested strict checking.");
			ଯାଅ fail;
		} ଅନ୍ୟଥା {
			logit("%s", ସନ୍ଦେଶ);
		}
	}

	ଯଦି (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_ଚାବି);
	ମୁକ୍ତ(ip);
	ମୁକ୍ତ(host);
	ଯଦି (host_hostkeys != ଖାଲି)
		free_hostkeys(host_hostkeys);
	ଯଦି (ip_hostkeys != ଖାଲି)
		free_hostkeys(ip_hostkeys);
	ଫେରନ୍ତୁ 0;

fail:
	ଯଦି (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ଯଦି ((r = sshkey_from_private(host_ଚାବି, &raw_ଚାବି)) != 0)
			fatal_fr(r, "decode key");
		ଯଦି ((r = sshkey_drop_cert(raw_ଚାବି)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_ଚାବି = raw_ଚାବି;
		ଯାଅ retry;
	}
	sshkey_free(raw_ଚାବି);
	ମୁକ୍ତ(ip);
	ମୁକ୍ତ(host);
	ଯଦି (host_hostkeys != ଖାଲି)
		free_hostkeys(host_hostkeys);
	ଯଦି (ip_hostkeys != ଖାଲି)
		free_hostkeys(ip_hostkeys);
	ଫେରନ୍ତୁ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
verify_host_ଚାବି(ଅକ୍ଷର *host, ସଂରଚନା sockaddr *hostaddr, ସଂରଚନା sshkey *host_ଚାବି,
    ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = -1, flags = 0;
	ଅକ୍ଷର valid[64], *fp = ଖାଲି, *cafp = ଖାଲି;
	ସଂରଚନା sshkey *plain = ଖାଲି;

	ଯଦି ((fp = sshkey_fingerprint(host_ଚାବି,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି) {
		error_fr(r, "fingerprint host key");
		r = -1;
		ଯାଅ out;
	}

	ଯଦି (sshkey_is_cert(host_ଚାବି)) {
		ଯଦି ((cafp = sshkey_fingerprint(host_ଚାବି->cert->signature_ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			ଯାଅ out;
		}
		sshkey_format_cert_validity(host_ଚାବି->cert,
		    valid, ଆକାର(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_ଚାବି), fp,
		    (unsigned long long)host_ଚାବି->cert->serial,
		    host_ଚାବି->cert->ଚାବି_id,
		    sshkey_ssh_name(host_ଚାବି->cert->signature_ଚାବି), cafp,
		    valid);
		ପାଇଁ (i = 0; i < host_ଚାବି->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_ଚାବି->cert->principals[i]);
		}
	} ଅନ୍ୟଥା {
		debug("Server host key: %s %s", sshkey_ssh_name(host_ଚାବି), fp);
	}

	ଯଦି (sshkey_equal(previous_host_ଚାବି, host_ଚାବି)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_ଚାବି), fp);
		r = 0;
		ଯାଅ out;
	}

	/* Check in RevokedHostKeys files if specified */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ; i++) {
		r = sshkey_check_revoked(host_ଚାବି,
		    options.revoked_host_ଚାବିଗୁଡ଼ିକ[i]);
		ବାଛ (r) {
		ସ୍ଥିତି 0:
			ଭାଙ୍ଗ; /* not revoked */
		ସ୍ଥିତି SSH_ERR_ଚାବି_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_ଚାବି), fp,
			    options.revoked_host_ଚାବିଗୁଡ଼ିକ[i]);
			r = -1;
			ଯାଅ out;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_ଚାବି),
			    fp, options.revoked_host_ଚାବିଗୁଡ଼ିକ[i]);
			r = -1;
			ଯାଅ out;
		}
	}

	ଯଦି (options.verify_host_ଚାବି_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ଯଦି ((r = sshkey_from_private(host_ଚାବି, &plain)) != 0)
			ଯାଅ out;
		ଯଦି (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ଯଦି (verify_host_ଚାବି_dns(host, hostaddr, plain, &flags) == 0) {
			ଯଦି (flags & DNS_VERIFY_FOUND) {
				ଯଦି (options.verify_host_ଚାବି_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					ଯାଅ out;
				}
				ଯଦି (flags & DNS_VERIFY_MATCH) {
					matching_host_ଚାବି_dns = 1;
				} ଅନ୍ୟଥା {
					warn_changed_ଚାବି(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_ଚାବି(host, cinfo, hostaddr, options.port, host_ଚାବି,
	    RDRW, 0, options.user_hostfiles, options.ଅଙ୍କ_user_hostfiles,
	    options.system_hostfiles, options.ଅଙ୍କ_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	ମୁକ୍ତ(fp);
	ମୁକ୍ତ(cafp);
	ଯଦି (r == 0 && host_ଚାବି != ଖାଲି) {
		sshkey_free(previous_host_ଚାବି);
		r = sshkey_from_private(host_ଚାବି, &previous_host_ଚାବି);
	}

	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
warn_nonpq_kex(ଶୂନ୍ୟ)
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
ଶୂନ୍ୟ
ssh_login(ସଂରଚନା ssh *ssh, Sensitive *sensitive, ଅଚଳ ଅକ୍ଷର *orighost,
    ସଂରଚନା sockaddr_storage *hostaddr, u_short port, ସଂରଚନା passwd *pw,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout_ms, ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଅକ୍ଷର *host;
	ଅକ୍ଷର *server_user, *local_user;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ଯଦି ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ଯଦି ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_set_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, port, server_user);
	ssh_kex2(ssh, host, hostaddr, port, cinfo);
	kex_set_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_set);
	ଯଦି (!options.kex_algorithms_set && ssh->kex != ଖାଲି &&
	    ssh->kex->name != ଖାଲି && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	ମୁକ୍ତ(local_user);
	ମୁକ୍ତ(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
show_other_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା hostkeys *hostkeys, ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type[] = {
		ଚାବି_RSA,
		ଚାବି_ECDSA,
		ଚାବି_ED25519,
		ଚାବି_MLDSA44_ED25519,
		-1
	};
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret = 0;
	ଅକ୍ଷର *fp, *ra;
	ଅଚଳ ସଂରଚନା hostkey_entry *found;

	ପାଇଁ (i = 0; type[i] != -1; i++) {
		ଯଦି (type[i] == ଚାବି->type)
			ଜାରି;
		ଯଦି (!lookup_ଚାବି_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			ଜାରି;
		fp = sshkey_fingerprint(found->ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->ଚାବି,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->ଚାବି),
		    found->host, found->file, found->ଧାଡ଼ି,
		    sshkey_type(found->ଚାବି), fp);
		ଯଦି (options.visual_host_ଚାବି)
			logit("%s", ra);
		ମୁକ୍ତ(ra);
		ମୁକ୍ତ(fp);
		ret = 1;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
warn_changed_ଚାବି(ସଂରଚନା sshkey *host_ଚାବି)
{
	ଅକ୍ଷର *fp;

	fp = sshkey_fingerprint(host_ଚାବି, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ଯଦି (fp == ଖାଲି)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_ଚାବି), fp);
	error("Please contact your system administrator.");

	ମୁକ୍ତ(fp);
}

/*
 * Execute a local command
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_local_cmd(ଅଚଳ ଅକ୍ଷର *args)
{
	ଅକ୍ଷର *shell;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;
	ଶୂନ୍ୟ (*osighand)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	ଯଦି (!options.permit_local_command ||
	    args == ଖାଲି || !*args)
		ଫେରନ୍ତୁ (1);

	ଯଦି ((shell = getenv("SHELL")) == ଖାଲି || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ଯଦି (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (ଅକ୍ଷର *)ଖାଲି);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} ଅନ୍ୟଥା ଯଦି (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1)
		ଯଦି (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ଯଦି (!WIFEXITED(status))
		ଫେରନ୍ତୁ (1);

	ଫେରନ୍ତୁ (WEXITSTATUS(status));
}

ଶୂନ୍ୟ
maybe_add_ଚାବି_to_agent(ଅଚଳ ଅକ୍ଷର *authfile, ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ,
    ଅଚଳ ଅକ୍ଷର *comment, ଅଚଳ ଅକ୍ଷର *passphrase)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_sock = -1, r;
	ଅଚଳ ଅକ୍ଷର *skprovider = ଖାଲି;

	ଯଦି (options.add_ଚାବିଗୁଡ଼ିକ_to_agent == 0)
		ଫେରନ୍ତୁ;

	ଯଦି ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ଫେରନ୍ତୁ;
	}

	ଯଦି (options.add_ଚାବିଗୁଡ଼ିକ_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (sshkey_is_sk(ବ୍ୟକ୍ତିଗତ))
		skprovider = options.sk_provider;
	ଯଦି ((r = ssh_add_identity_constrained(auth_sock, ବ୍ୟକ୍ତିଗତ,
	    comment == ଖାଲି ? authfile : comment,
	    options.add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan,
	    (options.add_ଚାବିଗୁଡ଼ିକ_to_agent == 3), skprovider, ଖାଲି, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ଅନ୍ୟଥା
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
