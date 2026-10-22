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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <net/if.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <ifaddrs.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshconnect.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "dns.h"
#অন্তর্ভাব "monitor_fdpass.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "kex.h"

কাঠামো sshkey *previous_host_চাবি = ফাঁকা;

স্থির পূর্ণসংখ্যা matching_host_চাবি_dns = 0;

স্থির pid_t proxy_command_pid = 0;

/* import */
বাহ্যিক পূর্ণসংখ্যা debug_flag;
বাহ্যিক Options options;
বাহ্যিক অক্ষর *__progname;

স্থির পূর্ণসংখ্যা show_other_চাবিগুলি(কাঠামো hostkeys *, কাঠামো sshkey *);
স্থির শূন্য warn_changed_চাবি(কাঠামো sshkey *);

শূন্য
ssh_conn_info_free(কাঠামো ssh_conn_info *cinfo)
{
	যদি (cinfo == ফাঁকা)
		ফেরত;
	মুক্ত(cinfo->conn_hash_hex);
	মুক্ত(cinfo->shorthost);
	মুক্ত(cinfo->uidstr);
	মুক্ত(cinfo->keyalias);
	মুক্ত(cinfo->thishost);
	মুক্ত(cinfo->host_arg);
	মুক্ত(cinfo->portstr);
	মুক্ত(cinfo->remhost);
	মুক্ত(cinfo->remuser);
	মুক্ত(cinfo->homedir);
	মুক্ত(cinfo->locuser);
	মুক্ত(cinfo->jmphost);
	freezero(cinfo, আকার(*cinfo));
}

কাঠামো ssh_conn_info *
ssh_conn_info_dup(ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	কাঠামো ssh_conn_info *ret;

	যদি (cinfo == ফাঁকা)
		ফেরত ফাঁকা;
	ret = xcalloc(1, আকার(*ret));
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
	ফেরত ret;
}

/* Expand a proxy command */
স্থির অক্ষর *
expand_proxy_command(ধ্রুবক অক্ষর *proxy_command, ধ্রুবক অক্ষর *user,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *host_arg, পূর্ণসংখ্যা port)
{
	অক্ষর *tmp, *ret, strport[NI_MAXSERV];
	ধ্রুবক অক্ষর *keyalias = options.host_চাবি_alias ?
	    options.host_চাবি_alias : host_arg;

	snprintf(strport, আকার strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (অক্ষর *)ফাঁকা);
	মুক্ত(tmp);
	ফেরত ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
স্থির পূর্ণসংখ্যা
ssh_proxy_fdpass_connect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *host_arg, u_short port, ধ্রুবক অক্ষর *proxy_command)
{
	অক্ষর *command_string;
	পূর্ণসংখ্যা sp[2], sock;
	pid_t pid;
	অক্ষর *shell;

	যদি ((shell = getenv("SHELL")) == ফাঁকা)
		shell = _PATH_BSHELL;

	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	যদি ((pid = fork()) == 0) {
		অক্ষর *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		যদি (sp[0] != 0) {
			যদি (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		যদি (sp[0] != 1) {
			যদি (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		যদি (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		যদি (!debug_flag && options.control_path != ফাঁকা &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ফাঁকা;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	যদি (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	মুক্ত(command_string);

	যদি ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	যখন (waitpid(pid, ফাঁকা, 0) == -1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	যদি (ssh_packet_set_connection(ssh, sock, sock) == ফাঁকা)
		ফেরত -1; /* ssh_packet_set_connection logs error */

	ফেরত 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
স্থির পূর্ণসংখ্যা
ssh_proxy_connect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *host_arg,
    u_short port, ধ্রুবক অক্ষর *proxy_command)
{
	অক্ষর *command_string;
	পূর্ণসংখ্যা pin[2], pout[2];
	pid_t pid;
	অক্ষর *shell;

	যদি ((shell = getenv("SHELL")) == ফাঁকা || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	যদি (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	যদি ((pid = fork()) == 0) {
		অক্ষর *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		যদি (pin[0] != 0) {
			যদি (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		যদি (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		যদি (!debug_flag && options.control_path != ফাঁকা &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ফাঁকা;

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
	যদি (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	অন্যথা
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	মুক্ত(command_string);

	/* Set the connection file descriptors. */
	যদি (ssh_packet_set_connection(ssh, pout[0], pin[1]) == ফাঁকা)
		ফেরত -1; /* ssh_packet_set_connection logs error */

	ফেরত 0;
}

শূন্য
ssh_kill_proxy_command(শূন্য)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	যদি (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
স্থির পূর্ণসংখ্যা
check_ifaddrs(ধ্রুবক অক্ষর *ifname, পূর্ণসংখ্যা af, ধ্রুবক কাঠামো ifaddrs *ifaddrs,
    কাঠামো sockaddr_storage *resultp, socklen_t *rlenp)
{
	কাঠামো sockaddr_in6 *sa6;
	কাঠামো sockaddr_in *sa;
	কাঠামো in6_addr *v6addr;
	ধ্রুবক কাঠামো ifaddrs *ifa;
	পূর্ণসংখ্যা allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	জন্য (allow_local = 0; allow_local < 2; allow_local++) {
		জন্য (ifa = ifaddrs; ifa != ফাঁকা; ifa = ifa->ifa_পরবর্তী) {
			যদি (ifa->ifa_addr == ফাঁকা || ifa->ifa_name == ফাঁকা ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				চালু;
			নির্বাচন (ifa->ifa_addr->sa_family) {
			ক্ষেত্র AF_INET:
				sa = (কাঠামো sockaddr_in *)ifa->ifa_addr;
				যদি (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					চালু;
				যদি (*rlenp < আকার(কাঠামো sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ফেরত -1;
				}
				*rlenp = আকার(কাঠামো sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				ফেরত 0;
			ক্ষেত্র AF_INET6:
				sa6 = (কাঠামো sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				যদি (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					চালু;
				যদি (*rlenp < আকার(কাঠামো sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ফেরত -1;
				}
				*rlenp = আকার(কাঠামো sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				ফেরত 0;
			}
		}
	}
	ফেরত -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
স্থির পূর্ণসংখ্যা
ssh_create_socket(কাঠামো addrinfo *ai)
{
	পূর্ণসংখ্যা sock, r;
	কাঠামো sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	কাঠামো addrinfo hints, *res = ফাঁকা;
#ifdef HAVE_IFADDRS_H
	কাঠামো ifaddrs *ifaddrs = ফাঁকা;
#endif
	অক্ষর ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	যদি (sock == -1) {
		error("socket: %s", strerror(errno));
		ফেরত -1;
	}
	(শূন্য)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	যদি (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	যদি (options.bind_address == ফাঁকা && options.bind_interface == ফাঁকা)
		ফেরত sock;

	যদি (options.bind_address != ফাঁকা) {
		memset(&hints, 0, আকার(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		যদি ((r = getaddrinfo(options.bind_address, ফাঁকা,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			যাও fail;
		}
		যদি (res == ফাঁকা) {
			error("getaddrinfo: no addrs");
			যাও fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} অন্যথা যদি (options.bind_interface != ফাঁকা) {
#ifdef HAVE_IFADDRS_H
		যদি ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			যাও fail;
		}
		bindaddrlen = আকার(bindaddr);
		যদি (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			যাও fail;
		}
#অন্যথা
		error("BindInterface not supported on this platform.");
#endif
	}
	যদি ((r = getnameinfo((কাঠামো sockaddr *)&bindaddr, bindaddrlen,
	    ntop, আকার(ntop), ফাঁকা, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		যাও fail;
	}
	যদি (bind(sock, (কাঠামো sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		যাও fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	যাও out;
fail:
	close(sock);
	sock = -1;
 out:
	যদি (res != ফাঁকা)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	যদি (ifaddrs != ফাঁকা)
		freeifaddrs(ifaddrs);
#endif
	ফেরত sock;
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
স্থির পূর্ণসংখ্যা
ssh_connect_direct(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host, কাঠামো addrinfo *aitop,
    কাঠামো sockaddr_storage *hostaddr, u_short port, পূর্ণসংখ্যা connection_attempts,
    পূর্ণসংখ্যা *timeout_ms, পূর্ণসংখ্যা want_keepalive)
{
	পূর্ণসংখ্যা saved_timeout_ms = *timeout_ms;
	পূর্ণসংখ্যা oerrno, sock = -1, attempt;
	অক্ষর ntop[NI_MAXHOST], strport[NI_MAXSERV];
	কাঠামো addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, আকার(ntop));
	memset(strport, 0, আকার(strport));

	জন্য (attempt = 0; attempt < connection_attempts; attempt++) {
		যদি (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		জন্য (ai = aitop; ai; ai = ai->ai_next) {
			যদি (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				চালু;
			}
			যদি (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, আকার(ntop), strport, আকার(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				চালু;
			}
			যদি (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				চালু;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			যদি (sock < 0) {
				/* Any error is already output */
				errno = 0;
				চালু;
			}

			*timeout_ms = saved_timeout_ms;
			যদি (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				বিরতি;
			} অন্যথা {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		যদি (sock != -1)
			বিরতি;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	যদি (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ফেরত -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	যদি (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	যদি (ssh_packet_set_connection(ssh, sock, sock) == ফাঁকা)
		ফেরত -1; /* ssh_packet_set_connection logs error */

	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_connect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *host_arg,
    কাঠামো addrinfo *addrs, কাঠামো sockaddr_storage *hostaddr, u_short port,
    পূর্ণসংখ্যা connection_attempts, পূর্ণসংখ্যা *timeout_ms, পূর্ণসংখ্যা want_keepalive)
{
	পূর্ণসংখ্যা in, out;

	যদি (options.proxy_command == ফাঁকা) {
		ফেরত ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} অন্যথা যদি (strcmp(options.proxy_command, "-") == 0) {
		যদি ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			যদি (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			ফেরত -1; /* ssh_packet_set_connection logs error */
		}
		যদি ((ssh_packet_set_connection(ssh, in, out)) == ফাঁকা)
			ফেরত -1; /* ssh_packet_set_connection logs error */
		ফেরত 0;
	} অন্যথা যদি (options.proxy_use_fdpass) {
		ফেরত ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	ফেরত ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
স্থির পূর্ণসংখ্যা
confirm(ধ্রুবক অক্ষর *prompt, ধ্রুবক অক্ষর *fingerprint)
{
	ধ্রুবক অক্ষর *বার্তা, *again = "Please type 'yes' or 'no': ";
	ধ্রুবক অক্ষর *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	অক্ষর *p, *cp;
	পূর্ণসংখ্যা ret = -1;

	যদি (options.batch_mode)
		ফেরত 0;
	জন্য (বার্তা = prompt;;বার্তা = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(বার্তা, RP_ECHO);
		যদি (p == ফাঁকা)
			ফেরত 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		যদি (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		অন্যথা যদি (strcasecmp(p, "yes") == 0 || (fingerprint != ফাঁকা &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		মুক্ত(cp);
		যদি (ret != -1)
			ফেরত ret;
	}
}

স্থির পূর্ণসংখ্যা
sockaddr_is_local(কাঠামো sockaddr *hostaddr)
{
	নির্বাচন (hostaddr->sa_family) {
	ক্ষেত্র AF_INET:
		ফেরত (ntohl(((কাঠামো sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	ক্ষেত্র AF_INET6:
		ফেরত IN6_IS_ADDR_LOOPBACK(
		    &(((কাঠামো sockaddr_in6 *)hostaddr)->sin6_addr));
	পূর্বনির্ধারিত:
		ফেরত 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
শূন্য
get_hostfile_hostname_ipaddr(অক্ষর *hostname, কাঠামো sockaddr *hostaddr,
    u_short port, অক্ষর **hostfile_hostname, অক্ষর **hostfile_ipaddr)
{
	অক্ষর ntop[NI_MAXHOST];
	socklen_t addrlen;

	নির্বাচন (hostaddr == ফাঁকা ? -1 : hostaddr->sa_family) {
	ক্ষেত্র -1:
		addrlen = 0;
		বিরতি;
	ক্ষেত্র AF_INET:
		addrlen = আকার(কাঠামো sockaddr_in);
		বিরতি;
	ক্ষেত্র AF_INET6:
		addrlen = আকার(কাঠামো sockaddr_in6);
		বিরতি;
	পূর্বনির্ধারিত:
		addrlen = আকার(কাঠামো sockaddr);
		বিরতি;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	যদি (hostfile_ipaddr != ফাঁকা) {
		যদি (options.proxy_command == ফাঁকা) {
			যদি (getnameinfo(hostaddr, addrlen,
			    ntop, আকার(ntop), ফাঁকা, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} অন্যথা {
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
	যদি (hostfile_hostname != ফাঁকা) {
		যদি (options.host_চাবি_alias != ফাঁকা) {
			*hostfile_hostname = xstrdup(options.host_চাবি_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} অন্যথা {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
স্থির পূর্ণসংখ্যা
path_in_hostfiles(ধ্রুবক অক্ষর *path, অক্ষর **hostfiles, u_int অঙ্ক_hostfiles)
{
	u_int i;

	জন্য (i = 0; i < অঙ্ক_hostfiles; i++) {
		যদি (strcmp(path, hostfiles[i]) == 0)
			ফেরত 1;
	}
	ফেরত 0;
}

কাঠামো find_by_চাবি_ctx {
	ধ্রুবক অক্ষর *host, *ip;
	ধ্রুবক কাঠামো sshkey *চাবি;
	অক্ষর **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
স্থির অক্ষর *
try_tilde_unexpand(ধ্রুবক অক্ষর *path)
{
	অক্ষর *home, *ret = ফাঁকা;
	আকার_t l;

	যদি (*path != '/')
		ফেরত xstrdup(path);
	যদি ((home = getenv("HOME")) == ফাঁকা || (l = strlen(home)) == 0)
		ফেরত xstrdup(path);
	যদি (strncmp(path, home, l) != 0)
		ফেরত xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	যদি (home[l - 1] != '/' && path[l] != '/')
		ফেরত xstrdup(path);
	যদি (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	ফেরত ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
পূর্ণসংখ্যা
hostkey_accepted_by_hostkeyalgs(ধ্রুবক কাঠামো sshkey *চাবি)
{
	ধ্রুবক অক্ষর *ktype = sshkey_ssh_name(চাবি);
	ধ্রুবক অক্ষর *hostkeyalgs = options.hostkeyalgorithms;

	যদি (চাবি->type == চাবি_UNSPEC)
		ফেরত 0;
	যদি (চাবি->type == চাবি_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ফেরত 1;
	যদি (চাবি->type == চাবি_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ফেরত 1;
	ফেরত match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

স্থির পূর্ণসংখ্যা
hostkeys_find_by_চাবি_cb(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো find_by_চাবি_ctx *ctx = (কাঠামো find_by_চাবি_ctx *)_ctx;
	অক্ষর *path;

	/* we are looking for keys with names that *do not* match */
	যদি ((l->match & HKF_MATCH_HOST) != 0)
		ফেরত 0;
	/* not interested in marker lines */
	যদি (l->marker != MRK_NONE)
		ফেরত 0;
	/* we are only interested in exact key matches */
	যদি (l->চাবি == ফাঁকা || !sshkey_equal(ctx->চাবি, l->চাবি))
		ফেরত 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, আকার(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	মুক্ত(path);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
hostkeys_find_by_চাবি_hostfile(ধ্রুবক অক্ষর *file, ধ্রুবক অক্ষর *which,
    কাঠামো find_by_চাবি_ctx *ctx)
{
	পূর্ণসংখ্যা r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	যদি ((r = hostkeys_foreach(file, hostkeys_find_by_চাবি_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_চাবি, 0)) != 0) {
		যদি (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ফেরত 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ফেরত r;
	}
	ফেরত 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
স্থির শূন্য
hostkeys_find_by_চাবি(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, ধ্রুবক কাঠামো sshkey *চাবি,
    অক্ষর **user_hostfiles, u_int অঙ্ক_user_hostfiles,
    অক্ষর **system_hostfiles, u_int অঙ্ক_system_hostfiles,
    অক্ষর ***names, u_int *nnames)
{
	কাঠামো find_by_চাবি_ctx ctx = {ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা, 0};
	u_int i;

	*names = ফাঁকা;
	*nnames = 0;

	যদি (চাবি == ফাঁকা || sshkey_is_cert(চাবি))
		ফেরত;

	ctx.host = host;
	ctx.ip = ip;
	ctx.চাবি = চাবি;

	জন্য (i = 0; i < অঙ্ক_user_hostfiles; i++) {
		যদি (hostkeys_find_by_চাবি_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			যাও fail;
	}
	জন্য (i = 0; i < অঙ্ক_system_hostfiles; i++) {
		যদি (hostkeys_find_by_চাবি_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			যাও fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = ফাঁকা;
	ctx.nnames = 0;
	ফেরত;
 fail:
	জন্য (i = 0; i < ctx.nnames; i++)
		মুক্ত(ctx.names[i]);
	মুক্ত(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
স্থির অক্ষর *
other_hostkeys_message(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip,
    ধ্রুবক কাঠামো sshkey *চাবি,
    অক্ষর **user_hostfiles, u_int অঙ্ক_user_hostfiles,
    অক্ষর **system_hostfiles, u_int অঙ্ক_system_hostfiles)
{
	অক্ষর *ret = ফাঁকা, **othernames = ফাঁকা;
	u_int i, n, অঙ্ক_othernames = 0;

	hostkeys_find_by_চাবি(host, ip, চাবি,
	    user_hostfiles, অঙ্ক_user_hostfiles,
	    system_hostfiles, অঙ্ক_system_hostfiles,
	    &othernames, &অঙ্ক_othernames);
	যদি (অঙ্ক_othernames == 0)
		ফেরত xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = অঙ্ক_othernames;
	যদি (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	জন্য (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	যদি (n < অঙ্ক_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    অঙ্ক_othernames - n);
	}
	জন্য (i = 0; i < অঙ্ক_othernames; i++)
		মুক্ত(othernames[i]);
	মুক্ত(othernames);
	ফেরত ret;
}

শূন্য
load_hostkeys_command(কাঠামো hostkeys *hostkeys, ধ্রুবক অক্ষর *command_template,
    ধ্রুবক অক্ষর *invocation, ধ্রুবক কাঠামো ssh_conn_info *cinfo,
    ধ্রুবক কাঠামো sshkey *host_চাবি, ধ্রুবক অক্ষর *hostfile_hostname)
{
	পূর্ণসংখ্যা r, i, ac = 0;
	অক্ষর *চাবি_fp = ফাঁকা, *keytext = ফাঁকা, *tmp;
	অক্ষর *command = ফাঁকা, *tag = ফাঁকা, **av = ফাঁকা;
	FILE *f = ফাঁকা;
	pid_t pid;
	শূন্য (*osigchld)(পূর্ণসংখ্যা);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	যদি (host_চাবি != ফাঁকা) {
		যদি ((চাবি_fp = sshkey_fingerprint(host_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("sshkey_fingerprint failed");
		যদি ((r = sshkey_to_base64(host_চাবি, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	যদি (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		যাও out;
	}
	যদি (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		যাও out;
	}
	জন্য (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_চাবি == ফাঁকা ? "NONE" : sshkey_ssh_name(host_চাবি),
		    "f", চাবি_fp == ফাঁকা ? "NONE" : চাবি_fp,
		    "K", keytext == ফাঁকা ? "NONE" : keytext,
		    (অক্ষর *)ফাঁকা);
		যদি (tmp == ফাঁকা)
			fatal_f("percent_expand failed");
		মুক্ত(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	যদি ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, ফাঁকা, ফাঁকা, ফাঁকা)) == 0)
		যাও out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	যদি (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	যদি (f != ফাঁকা)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	জন্য (i = 0; i < ac; i++)
		মুক্ত(av[i]);
	মুক্ত(av);
	মুক্ত(tag);
	মুক্ত(command);
	মুক্ত(চাবি_fp);
	মুক্ত(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
স্থির পূর্ণসংখ্যা
check_host_চাবি(অক্ষর *hostname, ধ্রুবক কাঠামো ssh_conn_info *cinfo,
    কাঠামো sockaddr *hostaddr, u_short port,
    কাঠামো sshkey *host_চাবি, পূর্ণসংখ্যা readonly, পূর্ণসংখ্যা clobber_port,
    অক্ষর **user_hostfiles, u_int অঙ্ক_user_hostfiles,
    অক্ষর **system_hostfiles, u_int অঙ্ক_system_hostfiles,
    ধ্রুবক অক্ষর *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	কাঠামো sshkey *raw_চাবি = ফাঁকা;
	অক্ষর *ip = ফাঁকা, *host = ফাঁকা;
	অক্ষর hostline[1000], *hostp, *fp, *ra;
	অক্ষর বার্তা[1024];
	ধ্রুবক অক্ষর *type, *fail_reason = ফাঁকা;
	ধ্রুবক কাঠামো hostkey_entry *host_found = ফাঁকা, *ip_found = ফাঁকা;
	পূর্ণসংখ্যা len, cancelled_forwarding = 0, confirmed;
	পূর্ণসংখ্যা local = sockaddr_is_local(hostaddr);
	পূর্ণসংখ্যা r, want_cert = sshkey_is_cert(host_চাবি), host_ip_differ = 0;
	পূর্ণসংখ্যা hostkey_trusted = 0; /* Known or explicitly accepted by user */
	কাঠামো hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	যদি (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_চাবি_alias == ফাঁকা) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ফেরত 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	যদি (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	যদি (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ফাঁকা))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	জন্য (i = 0; i < অঙ্ক_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	জন্য (i = 0; i < অঙ্ক_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	যদি (hostfile_command != ফাঁকা && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_চাবি, host);
	}

	ip_hostkeys = ফাঁকা;
	যদি (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		জন্য (i = 0; i < অঙ্ক_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		জন্য (i = 0; i < অঙ্ক_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		যদি (hostfile_command != ফাঁকা && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_চাবি, ip);
		}
	}

 retry:
	যদি (!hostkey_accepted_by_hostkeyalgs(host_চাবি)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_চাবি));
		যাও fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_চাবি);
	type = sshkey_type(host_চাবি);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_চাবি_in_hostkeys(host_hostkeys, host_চাবি,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	যদি (!readonly && (অঙ্ক_user_hostfiles == 0 ||
	    (host_found != ফাঁকা && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	যদি (!want_cert && ip_hostkeys != ফাঁকা) {
		ip_status = check_চাবি_in_hostkeys(ip_hostkeys, host_চাবি,
		    &ip_found);
		যদি (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != ফাঁকা &&
		    !sshkey_equal(ip_found->চাবি, host_found->চাবি))))
			host_ip_differ = 1;
	} অন্যথা
		ip_status = host_status;

	নির্বাচন (host_status) {
	ক্ষেত্র HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->সারি);
		যদি (want_cert) {
			যদি (sshkey_cert_check_host(host_চাবি,
			    options.host_চাবি_alias == ফাঁকা ?
			    hostname : options.host_চাবি_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				যাও fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			যদি (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		যদি (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, অঙ্ক_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != ফাঁকা &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, অঙ্ক_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		যদি (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		যদি (options.check_host_ip && ip_status == HOST_NEW) {
			যদি (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			অন্যথা যদি (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_চাবি, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			অন্যথা
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} অন্যথা যদি (options.visual_host_চাবি) {
			fp = sshkey_fingerprint(host_চাবি,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_চাবি,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			যদি (fp == ফাঁকা || ra == ফাঁকা)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			মুক্ত(ra);
			মুক্ত(fp);
		}
		hostkey_trusted = 1;
		বিরতি;
	ক্ষেত্র HOST_NEW:
		যদি (options.host_চাবি_alias == ফাঁকা && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			যদি (check_host_চাবি(hostname, cinfo, hostaddr, 0,
			    host_চাবি, ROQUIET, 1,
			    user_hostfiles, অঙ্ক_user_hostfiles,
			    system_hostfiles, অঙ্ক_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				বিরতি;
			}
		}
		যদি (readonly || want_cert)
			যাও fail;
		/* The host is new. */
		যদি (options.strict_host_চাবি_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			যাও fail;
		} অন্যথা যদি (options.strict_host_চাবি_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			অক্ষর *msg1 = ফাঁকা, *msg2 = ফাঁকা;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			যদি (show_other_চাবিগুলি(host_hostkeys, host_চাবি)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} অন্যথা
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_চাবি,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_চাবি,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			যদি (fp == ফাঁকা || ra == ফাঁকা)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			যদি (options.visual_host_চাবি)
				xextendf(&msg1, "\n", "%s", ra);
			যদি (options.verify_host_চাবি_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_চাবি_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			যদি ((msg2 = other_hostkeys_message(host, ip, host_চাবি,
			    user_hostfiles, অঙ্ক_user_hostfiles,
			    system_hostfiles, অঙ্ক_system_hostfiles)) != ফাঁকা)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			মুক্ত(ra);
			মুক্ত(fp);
			মুক্ত(msg1);
			মুক্ত(msg2);
			যদি (!confirmed)
				যাও fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		যদি (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, আকার(hostline), "%s,%s", host, ip);
			hostp = hostline;
			যদি (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_চাবি, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_চাবি, options.hash_known_hosts);
			} অন্যথা {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_চাবি,
				    options.hash_known_hosts);
			}
		} অন্যথা {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_চাবি, options.hash_known_hosts);
			hostp = host;
		}

		যদি (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		অন্যথা
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		বিরতি;
	ক্ষেত্র HOST_REVOKED:
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
		যদি (options.strict_host_চাবি_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			যাও fail;
		}
		যাও continue_unsafe;

	ক্ষেত্র HOST_CHANGED:
		যদি (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->সারি);
			যাও fail;
		}
		যদি (readonly == ROQUIET)
			যাও fail;
		যদি (options.check_host_ip && host_ip_differ) {
			অক্ষর *চাবি_বার্তা;
			যদি (ip_status == HOST_NEW)
				চাবি_বার্তা = "is unknown";
			অন্যথা যদি (ip_status == HOST_OK)
				চাবি_বার্তা = "is unchanged";
			অন্যথা
				চাবি_বার্তা = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", চাবি_বার্তা);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			যদি (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->সারি);
		}
		/* The host key has changed. */
		warn_changed_চাবি(host_চাবি);
		যদি (অঙ্ক_user_hostfiles > 0 || অঙ্ক_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", অঙ্ক_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->চাবি),
		    host_found->file, host_found->সারি);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		যদি (options.strict_host_চাবি_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			যাও fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		যদি (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		যদি (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		যদি (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		যদি (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		যদি (options.অঙ্ক_local_forwards > 0 ||
		    options.অঙ্ক_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.অঙ্ক_local_forwards =
			    options.অঙ্ক_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		যদি (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		যদি (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		যদি (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		বিরতি;
	ক্ষেত্র HOST_FOUND:
		fatal("internal error");
		বিরতি;
	}

	যদি (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(বার্তা, আকার(বার্তা),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->সারি);
		যদি (host_status == HOST_OK) {
			len = strlen(বার্তা);
			snprintf(বার্তা + len, আকার(বার্তা) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->সারি);
		}
		যদি (options.strict_host_চাবি_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(বার্তা, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", আকার(বার্তা));
			যদি (!confirm(বার্তা, ফাঁকা))
				যাও fail;
		} অন্যথা যদি (options.strict_host_চাবি_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", বার্তা);
			error("Exiting, you have requested strict checking.");
			যাও fail;
		} অন্যথা {
			logit("%s", বার্তা);
		}
	}

	যদি (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_চাবি);
	মুক্ত(ip);
	মুক্ত(host);
	যদি (host_hostkeys != ফাঁকা)
		free_hostkeys(host_hostkeys);
	যদি (ip_hostkeys != ফাঁকা)
		free_hostkeys(ip_hostkeys);
	ফেরত 0;

fail:
	যদি (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		যদি ((r = sshkey_from_private(host_চাবি, &raw_চাবি)) != 0)
			fatal_fr(r, "decode key");
		যদি ((r = sshkey_drop_cert(raw_চাবি)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_চাবি = raw_চাবি;
		যাও retry;
	}
	sshkey_free(raw_চাবি);
	মুক্ত(ip);
	মুক্ত(host);
	যদি (host_hostkeys != ফাঁকা)
		free_hostkeys(host_hostkeys);
	যদি (ip_hostkeys != ফাঁকা)
		free_hostkeys(ip_hostkeys);
	ফেরত -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
পূর্ণসংখ্যা
verify_host_চাবি(অক্ষর *host, কাঠামো sockaddr *hostaddr, কাঠামো sshkey *host_চাবি,
    ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	u_int i;
	পূর্ণসংখ্যা r = -1, flags = 0;
	অক্ষর valid[64], *fp = ফাঁকা, *cafp = ফাঁকা;
	কাঠামো sshkey *plain = ফাঁকা;

	যদি ((fp = sshkey_fingerprint(host_চাবি,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা) {
		error_fr(r, "fingerprint host key");
		r = -1;
		যাও out;
	}

	যদি (sshkey_is_cert(host_চাবি)) {
		যদি ((cafp = sshkey_fingerprint(host_চাবি->cert->signature_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			যাও out;
		}
		sshkey_format_cert_validity(host_চাবি->cert,
		    valid, আকার(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_চাবি), fp,
		    (unsigned long long)host_চাবি->cert->serial,
		    host_চাবি->cert->চাবি_id,
		    sshkey_ssh_name(host_চাবি->cert->signature_চাবি), cafp,
		    valid);
		জন্য (i = 0; i < host_চাবি->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_চাবি->cert->principals[i]);
		}
	} অন্যথা {
		debug("Server host key: %s %s", sshkey_ssh_name(host_চাবি), fp);
	}

	যদি (sshkey_equal(previous_host_চাবি, host_চাবি)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_চাবি), fp);
		r = 0;
		যাও out;
	}

	/* Check in RevokedHostKeys files if specified */
	জন্য (i = 0; i < options.অঙ্ক_revoked_host_চাবিগুলি; i++) {
		r = sshkey_check_revoked(host_চাবি,
		    options.revoked_host_চাবিগুলি[i]);
		নির্বাচন (r) {
		ক্ষেত্র 0:
			বিরতি; /* not revoked */
		ক্ষেত্র SSH_ERR_চাবি_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_চাবি), fp,
			    options.revoked_host_চাবিগুলি[i]);
			r = -1;
			যাও out;
		পূর্বনির্ধারিত:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_চাবি),
			    fp, options.revoked_host_চাবিগুলি[i]);
			r = -1;
			যাও out;
		}
	}

	যদি (options.verify_host_চাবি_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		যদি ((r = sshkey_from_private(host_চাবি, &plain)) != 0)
			যাও out;
		যদি (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		যদি (verify_host_চাবি_dns(host, hostaddr, plain, &flags) == 0) {
			যদি (flags & DNS_VERIFY_FOUND) {
				যদি (options.verify_host_চাবি_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					যাও out;
				}
				যদি (flags & DNS_VERIFY_MATCH) {
					matching_host_চাবি_dns = 1;
				} অন্যথা {
					warn_changed_চাবি(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_চাবি(host, cinfo, hostaddr, options.port, host_চাবি,
	    RDRW, 0, options.user_hostfiles, options.অঙ্ক_user_hostfiles,
	    options.system_hostfiles, options.অঙ্ক_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	মুক্ত(fp);
	মুক্ত(cafp);
	যদি (r == 0 && host_চাবি != ফাঁকা) {
		sshkey_free(previous_host_চাবি);
		r = sshkey_from_private(host_চাবি, &previous_host_চাবি);
	}

	ফেরত r;
}

স্থির শূন্য
warn_nonpq_kex(শূন্য)
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
শূন্য
ssh_login(কাঠামো ssh *ssh, Sensitive *sensitive, ধ্রুবক অক্ষর *orighost,
    কাঠামো sockaddr_storage *hostaddr, u_short port, কাঠামো passwd *pw,
    পূর্ণসংখ্যা timeout_ms, ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	অক্ষর *host;
	অক্ষর *server_user, *local_user;
	পূর্ণসংখ্যা r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	যদি ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	যদি ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	যদি (!options.kex_algorithms_set && ssh->kex != ফাঁকা &&
	    ssh->kex->name != ফাঁকা && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	মুক্ত(local_user);
	মুক্ত(host);
}

/* print all known host keys for a given host, but skip keys of given type */
স্থির পূর্ণসংখ্যা
show_other_চাবিগুলি(কাঠামো hostkeys *hostkeys, কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা type[] = {
		চাবি_RSA,
		চাবি_ECDSA,
		চাবি_ED25519,
		চাবি_MLDSA44_ED25519,
		-1
	};
	পূর্ণসংখ্যা i, ret = 0;
	অক্ষর *fp, *ra;
	ধ্রুবক কাঠামো hostkey_entry *found;

	জন্য (i = 0; type[i] != -1; i++) {
		যদি (type[i] == চাবি->type)
			চালু;
		যদি (!lookup_চাবি_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			চালু;
		fp = sshkey_fingerprint(found->চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->চাবি,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		যদি (fp == ফাঁকা || ra == ফাঁকা)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->চাবি),
		    found->host, found->file, found->সারি,
		    sshkey_type(found->চাবি), fp);
		যদি (options.visual_host_চাবি)
			logit("%s", ra);
		মুক্ত(ra);
		মুক্ত(fp);
		ret = 1;
	}
	ফেরত ret;
}

স্থির শূন্য
warn_changed_চাবি(কাঠামো sshkey *host_চাবি)
{
	অক্ষর *fp;

	fp = sshkey_fingerprint(host_চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	যদি (fp == ফাঁকা)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_চাবি), fp);
	error("Please contact your system administrator.");

	মুক্ত(fp);
}

/*
 * Execute a local command
 */
পূর্ণসংখ্যা
ssh_local_cmd(ধ্রুবক অক্ষর *args)
{
	অক্ষর *shell;
	pid_t pid;
	পূর্ণসংখ্যা status;
	শূন্য (*osighand)(পূর্ণসংখ্যা);

	যদি (!options.permit_local_command ||
	    args == ফাঁকা || !*args)
		ফেরত (1);

	যদি ((shell = getenv("SHELL")) == ফাঁকা || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	যদি (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (অক্ষর *)ফাঁকা);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} অন্যথা যদি (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	যখন (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	যদি (!WIFEXITED(status))
		ফেরত (1);

	ফেরত (WEXITSTATUS(status));
}

শূন্য
maybe_add_চাবি_to_agent(ধ্রুবক অক্ষর *authfile, কাঠামো sshkey *ব্যক্তিগত,
    ধ্রুবক অক্ষর *comment, ধ্রুবক অক্ষর *passphrase)
{
	পূর্ণসংখ্যা auth_sock = -1, r;
	ধ্রুবক অক্ষর *skprovider = ফাঁকা;

	যদি (options.add_চাবিগুলি_to_agent == 0)
		ফেরত;

	যদি ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ফেরত;
	}

	যদি (options.add_চাবিগুলি_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ফেরত;
	}
	যদি (sshkey_is_sk(ব্যক্তিগত))
		skprovider = options.sk_provider;
	যদি ((r = ssh_add_identity_constrained(auth_sock, ব্যক্তিগত,
	    comment == ফাঁকা ? authfile : comment,
	    options.add_চাবিগুলি_to_agent_lifespan,
	    (options.add_চাবিগুলি_to_agent == 3), skprovider, ফাঁকা, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	অন্যথা
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
