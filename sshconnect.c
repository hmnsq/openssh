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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <net/if.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <ifaddrs.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshconnect.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "dns.h"
#അന്തര്ഭാവ "monitor_fdpass.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "kex.h"

ഘടന sshkey *previous_host_താക്കോൽ = ശൂന്യ;

സ്ഥിതം പൂർണ്ണസംഖ്യ matching_host_താക്കോൽ_dns = 0;

സ്ഥിതം pid_t proxy_command_pid = 0;

/* import */
ബാഹ്യ പൂർണ്ണസംഖ്യ debug_flag;
ബാഹ്യ Options options;
ബാഹ്യ അക്ഷരം *__progname;

സ്ഥിതം പൂർണ്ണസംഖ്യ show_other_താക്കോലുകൾ(ഘടന hostkeys *, ഘടന sshkey *);
സ്ഥിതം ശൂന്യം warn_changed_താക്കോൽ(ഘടന sshkey *);

ശൂന്യം
ssh_conn_info_free(ഘടന ssh_conn_info *cinfo)
{
	എങ്കിൽ (cinfo == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(cinfo->conn_hash_hex);
	സ്വതന്ത്രം(cinfo->shorthost);
	സ്വതന്ത്രം(cinfo->uidstr);
	സ്വതന്ത്രം(cinfo->keyalias);
	സ്വതന്ത്രം(cinfo->thishost);
	സ്വതന്ത്രം(cinfo->host_arg);
	സ്വതന്ത്രം(cinfo->portstr);
	സ്വതന്ത്രം(cinfo->remhost);
	സ്വതന്ത്രം(cinfo->remuser);
	സ്വതന്ത്രം(cinfo->homedir);
	സ്വതന്ത്രം(cinfo->locuser);
	സ്വതന്ത്രം(cinfo->jmphost);
	freezero(cinfo, വലുപ്പം(*cinfo));
}

ഘടന ssh_conn_info *
ssh_conn_info_dup(സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	ഘടന ssh_conn_info *ret;

	എങ്കിൽ (cinfo == ശൂന്യ)
		തിരികെ ശൂന്യ;
	ret = xcalloc(1, വലുപ്പം(*ret));
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
	തിരികെ ret;
}

/* Expand a proxy command */
സ്ഥിതം അക്ഷരം *
expand_proxy_command(സ്ഥിരം അക്ഷരം *proxy_command, സ്ഥിരം അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *host_arg, പൂർണ്ണസംഖ്യ port)
{
	അക്ഷരം *tmp, *ret, strport[NI_MAXSERV];
	സ്ഥിരം അക്ഷരം *keyalias = options.host_താക്കോൽ_alias ?
	    options.host_താക്കോൽ_alias : host_arg;

	snprintf(strport, വലുപ്പം strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (അക്ഷരം *)ശൂന്യ);
	സ്വതന്ത്രം(tmp);
	തിരികെ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_proxy_fdpass_connect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *host_arg, u_short port, സ്ഥിരം അക്ഷരം *proxy_command)
{
	അക്ഷരം *command_string;
	പൂർണ്ണസംഖ്യ sp[2], sock;
	pid_t pid;
	അക്ഷരം *shell;

	എങ്കിൽ ((shell = getenv("SHELL")) == ശൂന്യ)
		shell = _PATH_BSHELL;

	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	എങ്കിൽ ((pid = fork()) == 0) {
		അക്ഷരം *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		എങ്കിൽ (sp[0] != 0) {
			എങ്കിൽ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		എങ്കിൽ (sp[0] != 1) {
			എങ്കിൽ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		എങ്കിൽ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		എങ്കിൽ (!debug_flag && options.control_path != ശൂന്യ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ശൂന്യ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	എങ്കിൽ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	സ്വതന്ത്രം(command_string);

	എങ്കിൽ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ആകുമ്പോൾ (waitpid(pid, ശൂന്യ, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	എങ്കിൽ (ssh_packet_set_connection(ssh, sock, sock) == ശൂന്യ)
		തിരികെ -1; /* ssh_packet_set_connection logs error */

	തിരികെ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_proxy_connect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *host_arg,
    u_short port, സ്ഥിരം അക്ഷരം *proxy_command)
{
	അക്ഷരം *command_string;
	പൂർണ്ണസംഖ്യ pin[2], pout[2];
	pid_t pid;
	അക്ഷരം *shell;

	എങ്കിൽ ((shell = getenv("SHELL")) == ശൂന്യ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	എങ്കിൽ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	എങ്കിൽ ((pid = fork()) == 0) {
		അക്ഷരം *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		എങ്കിൽ (pin[0] != 0) {
			എങ്കിൽ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		എങ്കിൽ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		എങ്കിൽ (!debug_flag && options.control_path != ശൂന്യ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ശൂന്യ;

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
	എങ്കിൽ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	അല്ലെങ്കിൽ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	സ്വതന്ത്രം(command_string);

	/* Set the connection file descriptors. */
	എങ്കിൽ (ssh_packet_set_connection(ssh, pout[0], pin[1]) == ശൂന്യ)
		തിരികെ -1; /* ssh_packet_set_connection logs error */

	തിരികെ 0;
}

ശൂന്യം
ssh_kill_proxy_command(ശൂന്യം)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	എങ്കിൽ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_ifaddrs(സ്ഥിരം അക്ഷരം *ifname, പൂർണ്ണസംഖ്യ af, സ്ഥിരം ഘടന ifaddrs *ifaddrs,
    ഘടന sockaddr_storage *resultp, socklen_t *rlenp)
{
	ഘടന sockaddr_in6 *sa6;
	ഘടന sockaddr_in *sa;
	ഘടന in6_addr *v6addr;
	സ്ഥിരം ഘടന ifaddrs *ifa;
	പൂർണ്ണസംഖ്യ allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	വേണ്ടി (allow_local = 0; allow_local < 2; allow_local++) {
		വേണ്ടി (ifa = ifaddrs; ifa != ശൂന്യ; ifa = ifa->ifa_next) {
			എങ്കിൽ (ifa->ifa_addr == ശൂന്യ || ifa->ifa_name == ശൂന്യ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				തുടരുക;
			തിരഞ്ഞെടുപ്പ് (ifa->ifa_addr->sa_family) {
			അവസ്ഥ AF_INET:
				sa = (ഘടന sockaddr_in *)ifa->ifa_addr;
				എങ്കിൽ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					തുടരുക;
				എങ്കിൽ (*rlenp < വലുപ്പം(ഘടന sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					തിരികെ -1;
				}
				*rlenp = വലുപ്പം(ഘടന sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				തിരികെ 0;
			അവസ്ഥ AF_INET6:
				sa6 = (ഘടന sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				എങ്കിൽ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					തുടരുക;
				എങ്കിൽ (*rlenp < വലുപ്പം(ഘടന sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					തിരികെ -1;
				}
				*rlenp = വലുപ്പം(ഘടന sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				തിരികെ 0;
			}
		}
	}
	തിരികെ -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_create_socket(ഘടന addrinfo *ai)
{
	പൂർണ്ണസംഖ്യ sock, r;
	ഘടന sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ഘടന addrinfo hints, *res = ശൂന്യ;
#ifdef HAVE_IFADDRS_H
	ഘടന ifaddrs *ifaddrs = ശൂന്യ;
#endif
	അക്ഷരം ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	എങ്കിൽ (sock == -1) {
		error("socket: %s", strerror(errno));
		തിരികെ -1;
	}
	(ശൂന്യം)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	എങ്കിൽ (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	എങ്കിൽ (options.bind_address == ശൂന്യ && options.bind_interface == ശൂന്യ)
		തിരികെ sock;

	എങ്കിൽ (options.bind_address != ശൂന്യ) {
		memset(&hints, 0, വലുപ്പം(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		എങ്കിൽ ((r = getaddrinfo(options.bind_address, ശൂന്യ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			പോകുക fail;
		}
		എങ്കിൽ (res == ശൂന്യ) {
			error("getaddrinfo: no addrs");
			പോകുക fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} അല്ലെങ്കിൽ എങ്കിൽ (options.bind_interface != ശൂന്യ) {
#ifdef HAVE_IFADDRS_H
		എങ്കിൽ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			പോകുക fail;
		}
		bindaddrlen = വലുപ്പം(bindaddr);
		എങ്കിൽ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			പോകുക fail;
		}
#അല്ലെങ്കിൽ
		error("BindInterface not supported on this platform.");
#endif
	}
	എങ്കിൽ ((r = getnameinfo((ഘടന sockaddr *)&bindaddr, bindaddrlen,
	    ntop, വലുപ്പം(ntop), ശൂന്യ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		പോകുക fail;
	}
	എങ്കിൽ (bind(sock, (ഘടന sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		പോകുക fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	പോകുക out;
fail:
	close(sock);
	sock = -1;
 out:
	എങ്കിൽ (res != ശൂന്യ)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	എങ്കിൽ (ifaddrs != ശൂന്യ)
		freeifaddrs(ifaddrs);
#endif
	തിരികെ sock;
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_connect_direct(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host, ഘടന addrinfo *aitop,
    ഘടന sockaddr_storage *hostaddr, u_short port, പൂർണ്ണസംഖ്യ connection_attempts,
    പൂർണ്ണസംഖ്യ *timeout_ms, പൂർണ്ണസംഖ്യ want_keepalive)
{
	പൂർണ്ണസംഖ്യ saved_timeout_ms = *timeout_ms;
	പൂർണ്ണസംഖ്യ oerrno, sock = -1, attempt;
	അക്ഷരം ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ഘടന addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, വലുപ്പം(ntop));
	memset(strport, 0, വലുപ്പം(strport));

	വേണ്ടി (attempt = 0; attempt < connection_attempts; attempt++) {
		എങ്കിൽ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		വേണ്ടി (ai = aitop; ai; ai = ai->ai_next) {
			എങ്കിൽ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				തുടരുക;
			}
			എങ്കിൽ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, വലുപ്പം(ntop), strport, വലുപ്പം(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				തുടരുക;
			}
			എങ്കിൽ (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				തുടരുക;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			എങ്കിൽ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				തുടരുക;
			}

			*timeout_ms = saved_timeout_ms;
			എങ്കിൽ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				നിർത്തുക;
			} അല്ലെങ്കിൽ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		എങ്കിൽ (sock != -1)
			നിർത്തുക;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	എങ്കിൽ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		തിരികെ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	എങ്കിൽ (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	എങ്കിൽ (ssh_packet_set_connection(ssh, sock, sock) == ശൂന്യ)
		തിരികെ -1; /* ssh_packet_set_connection logs error */

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_connect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *host_arg,
    ഘടന addrinfo *addrs, ഘടന sockaddr_storage *hostaddr, u_short port,
    പൂർണ്ണസംഖ്യ connection_attempts, പൂർണ്ണസംഖ്യ *timeout_ms, പൂർണ്ണസംഖ്യ want_keepalive)
{
	പൂർണ്ണസംഖ്യ in, out;

	എങ്കിൽ (options.proxy_command == ശൂന്യ) {
		തിരികെ ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(options.proxy_command, "-") == 0) {
		എങ്കിൽ ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			എങ്കിൽ (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			തിരികെ -1; /* ssh_packet_set_connection logs error */
		}
		എങ്കിൽ ((ssh_packet_set_connection(ssh, in, out)) == ശൂന്യ)
			തിരികെ -1; /* ssh_packet_set_connection logs error */
		തിരികെ 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (options.proxy_use_fdpass) {
		തിരികെ ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	തിരികെ ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
സ്ഥിതം പൂർണ്ണസംഖ്യ
confirm(സ്ഥിരം അക്ഷരം *prompt, സ്ഥിരം അക്ഷരം *fingerprint)
{
	സ്ഥിരം അക്ഷരം *സന്ദേശം, *again = "Please type 'yes' or 'no': ";
	സ്ഥിരം അക്ഷരം *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	അക്ഷരം *p, *cp;
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (options.batch_mode)
		തിരികെ 0;
	വേണ്ടി (സന്ദേശം = prompt;;സന്ദേശം = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(സന്ദേശം, RP_ECHO);
		എങ്കിൽ (p == ശൂന്യ)
			തിരികെ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		എങ്കിൽ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(p, "yes") == 0 || (fingerprint != ശൂന്യ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		സ്വതന്ത്രം(cp);
		എങ്കിൽ (ret != -1)
			തിരികെ ret;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sockaddr_is_local(ഘടന sockaddr *hostaddr)
{
	തിരഞ്ഞെടുപ്പ് (hostaddr->sa_family) {
	അവസ്ഥ AF_INET:
		തിരികെ (ntohl(((ഘടന sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	അവസ്ഥ AF_INET6:
		തിരികെ IN6_IS_ADDR_LOOPBACK(
		    &(((ഘടന sockaddr_in6 *)hostaddr)->sin6_addr));
	സ്ഥിരസ്ഥിതി:
		തിരികെ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
ശൂന്യം
get_hostfile_hostname_ipaddr(അക്ഷരം *hostname, ഘടന sockaddr *hostaddr,
    u_short port, അക്ഷരം **hostfile_hostname, അക്ഷരം **hostfile_ipaddr)
{
	അക്ഷരം ntop[NI_MAXHOST];
	socklen_t addrlen;

	തിരഞ്ഞെടുപ്പ് (hostaddr == ശൂന്യ ? -1 : hostaddr->sa_family) {
	അവസ്ഥ -1:
		addrlen = 0;
		നിർത്തുക;
	അവസ്ഥ AF_INET:
		addrlen = വലുപ്പം(ഘടന sockaddr_in);
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
		addrlen = വലുപ്പം(ഘടന sockaddr_in6);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		addrlen = വലുപ്പം(ഘടന sockaddr);
		നിർത്തുക;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	എങ്കിൽ (hostfile_ipaddr != ശൂന്യ) {
		എങ്കിൽ (options.proxy_command == ശൂന്യ) {
			എങ്കിൽ (getnameinfo(hostaddr, addrlen,
			    ntop, വലുപ്പം(ntop), ശൂന്യ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} അല്ലെങ്കിൽ {
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
	എങ്കിൽ (hostfile_hostname != ശൂന്യ) {
		എങ്കിൽ (options.host_താക്കോൽ_alias != ശൂന്യ) {
			*hostfile_hostname = xstrdup(options.host_താക്കോൽ_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} അല്ലെങ്കിൽ {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
path_in_hostfiles(സ്ഥിരം അക്ഷരം *path, അക്ഷരം **hostfiles, u_int അക്കം_hostfiles)
{
	u_int i;

	വേണ്ടി (i = 0; i < അക്കം_hostfiles; i++) {
		എങ്കിൽ (strcmp(path, hostfiles[i]) == 0)
			തിരികെ 1;
	}
	തിരികെ 0;
}

ഘടന find_by_താക്കോൽ_ctx {
	സ്ഥിരം അക്ഷരം *host, *ip;
	സ്ഥിരം ഘടന sshkey *താക്കോൽ;
	അക്ഷരം **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
സ്ഥിതം അക്ഷരം *
try_tilde_unexpand(സ്ഥിരം അക്ഷരം *path)
{
	അക്ഷരം *home, *ret = ശൂന്യ;
	size_t l;

	എങ്കിൽ (*path != '/')
		തിരികെ xstrdup(path);
	എങ്കിൽ ((home = getenv("HOME")) == ശൂന്യ || (l = strlen(home)) == 0)
		തിരികെ xstrdup(path);
	എങ്കിൽ (strncmp(path, home, l) != 0)
		തിരികെ xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	എങ്കിൽ (home[l - 1] != '/' && path[l] != '/')
		തിരികെ xstrdup(path);
	എങ്കിൽ (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	തിരികെ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
പൂർണ്ണസംഖ്യ
hostkey_accepted_by_hostkeyalgs(സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	സ്ഥിരം അക്ഷരം *ktype = sshkey_ssh_name(താക്കോൽ);
	സ്ഥിരം അക്ഷരം *hostkeyalgs = options.hostkeyalgorithms;

	എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_UNSPEC)
		തിരികെ 0;
	എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		തിരികെ 1;
	എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		തിരികെ 1;
	തിരികെ match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
hostkeys_find_by_താക്കോൽ_cb(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന find_by_താക്കോൽ_ctx *ctx = (ഘടന find_by_താക്കോൽ_ctx *)_ctx;
	അക്ഷരം *path;

	/* we are looking for keys with names that *do not* match */
	എങ്കിൽ ((l->match & HKF_MATCH_HOST) != 0)
		തിരികെ 0;
	/* not interested in marker lines */
	എങ്കിൽ (l->marker != MRK_NONE)
		തിരികെ 0;
	/* we are only interested in exact key matches */
	എങ്കിൽ (l->താക്കോൽ == ശൂന്യ || !sshkey_equal(ctx->താക്കോൽ, l->താക്കോൽ))
		തിരികെ 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, വലുപ്പം(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	സ്വതന്ത്രം(path);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
hostkeys_find_by_താക്കോൽ_hostfile(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *which,
    ഘടന find_by_താക്കോൽ_ctx *ctx)
{
	പൂർണ്ണസംഖ്യ r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	എങ്കിൽ ((r = hostkeys_foreach(file, hostkeys_find_by_താക്കോൽ_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_താക്കോൽ, 0)) != 0) {
		എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			തിരികെ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		തിരികെ r;
	}
	തിരികെ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
സ്ഥിതം ശൂന്യം
hostkeys_find_by_താക്കോൽ(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    അക്ഷരം **user_hostfiles, u_int അക്കം_user_hostfiles,
    അക്ഷരം **system_hostfiles, u_int അക്കം_system_hostfiles,
    അക്ഷരം ***names, u_int *nnames)
{
	ഘടന find_by_താക്കോൽ_ctx ctx = {ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ, 0};
	u_int i;

	*names = ശൂന്യ;
	*nnames = 0;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || sshkey_is_cert(താക്കോൽ))
		തിരികെ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.താക്കോൽ = താക്കോൽ;

	വേണ്ടി (i = 0; i < അക്കം_user_hostfiles; i++) {
		എങ്കിൽ (hostkeys_find_by_താക്കോൽ_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			പോകുക fail;
	}
	വേണ്ടി (i = 0; i < അക്കം_system_hostfiles; i++) {
		എങ്കിൽ (hostkeys_find_by_താക്കോൽ_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			പോകുക fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = ശൂന്യ;
	ctx.nnames = 0;
	തിരികെ;
 fail:
	വേണ്ടി (i = 0; i < ctx.nnames; i++)
		സ്വതന്ത്രം(ctx.names[i]);
	സ്വതന്ത്രം(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
സ്ഥിതം അക്ഷരം *
other_hostkeys_message(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip,
    സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    അക്ഷരം **user_hostfiles, u_int അക്കം_user_hostfiles,
    അക്ഷരം **system_hostfiles, u_int അക്കം_system_hostfiles)
{
	അക്ഷരം *ret = ശൂന്യ, **othernames = ശൂന്യ;
	u_int i, n, അക്കം_othernames = 0;

	hostkeys_find_by_താക്കോൽ(host, ip, താക്കോൽ,
	    user_hostfiles, അക്കം_user_hostfiles,
	    system_hostfiles, അക്കം_system_hostfiles,
	    &othernames, &അക്കം_othernames);
	എങ്കിൽ (അക്കം_othernames == 0)
		തിരികെ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = അക്കം_othernames;
	എങ്കിൽ (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	വേണ്ടി (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	എങ്കിൽ (n < അക്കം_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    അക്കം_othernames - n);
	}
	വേണ്ടി (i = 0; i < അക്കം_othernames; i++)
		സ്വതന്ത്രം(othernames[i]);
	സ്വതന്ത്രം(othernames);
	തിരികെ ret;
}

ശൂന്യം
load_hostkeys_command(ഘടന hostkeys *hostkeys, സ്ഥിരം അക്ഷരം *command_template,
    സ്ഥിരം അക്ഷരം *invocation, സ്ഥിരം ഘടന ssh_conn_info *cinfo,
    സ്ഥിരം ഘടന sshkey *host_താക്കോൽ, സ്ഥിരം അക്ഷരം *hostfile_hostname)
{
	പൂർണ്ണസംഖ്യ r, i, ac = 0;
	അക്ഷരം *താക്കോൽ_fp = ശൂന്യ, *keytext = ശൂന്യ, *tmp;
	അക്ഷരം *command = ശൂന്യ, *tag = ശൂന്യ, **av = ശൂന്യ;
	FILE *f = ശൂന്യ;
	pid_t pid;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	എങ്കിൽ (host_താക്കോൽ != ശൂന്യ) {
		എങ്കിൽ ((താക്കോൽ_fp = sshkey_fingerprint(host_താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint failed");
		എങ്കിൽ ((r = sshkey_to_base64(host_താക്കോൽ, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	എങ്കിൽ (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		പോകുക out;
	}
	എങ്കിൽ (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		പോകുക out;
	}
	വേണ്ടി (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_താക്കോൽ == ശൂന്യ ? "NONE" : sshkey_ssh_name(host_താക്കോൽ),
		    "f", താക്കോൽ_fp == ശൂന്യ ? "NONE" : താക്കോൽ_fp,
		    "K", keytext == ശൂന്യ ? "NONE" : keytext,
		    (അക്ഷരം *)ശൂന്യ);
		എങ്കിൽ (tmp == ശൂന്യ)
			fatal_f("percent_expand failed");
		സ്വതന്ത്രം(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	എങ്കിൽ ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, ശൂന്യ, ശൂന്യ, ശൂന്യ)) == 0)
		പോകുക out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	എങ്കിൽ (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	എങ്കിൽ (f != ശൂന്യ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	വേണ്ടി (i = 0; i < ac; i++)
		സ്വതന്ത്രം(av[i]);
	സ്വതന്ത്രം(av);
	സ്വതന്ത്രം(tag);
	സ്വതന്ത്രം(command);
	സ്വതന്ത്രം(താക്കോൽ_fp);
	സ്വതന്ത്രം(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_host_താക്കോൽ(അക്ഷരം *hostname, സ്ഥിരം ഘടന ssh_conn_info *cinfo,
    ഘടന sockaddr *hostaddr, u_short port,
    ഘടന sshkey *host_താക്കോൽ, പൂർണ്ണസംഖ്യ readonly, പൂർണ്ണസംഖ്യ clobber_port,
    അക്ഷരം **user_hostfiles, u_int അക്കം_user_hostfiles,
    അക്ഷരം **system_hostfiles, u_int അക്കം_system_hostfiles,
    സ്ഥിരം അക്ഷരം *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	ഘടന sshkey *raw_താക്കോൽ = ശൂന്യ;
	അക്ഷരം *ip = ശൂന്യ, *host = ശൂന്യ;
	അക്ഷരം hostline[1000], *hostp, *fp, *ra;
	അക്ഷരം സന്ദേശം[1024];
	സ്ഥിരം അക്ഷരം *type, *fail_reason = ശൂന്യ;
	സ്ഥിരം ഘടന hostkey_entry *host_found = ശൂന്യ, *ip_found = ശൂന്യ;
	പൂർണ്ണസംഖ്യ len, cancelled_forwarding = 0, confirmed;
	പൂർണ്ണസംഖ്യ local = sockaddr_is_local(hostaddr);
	പൂർണ്ണസംഖ്യ r, want_cert = sshkey_is_cert(host_താക്കോൽ), host_ip_differ = 0;
	പൂർണ്ണസംഖ്യ hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ഘടന hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	എങ്കിൽ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_താക്കോൽ_alias == ശൂന്യ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		തിരികെ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	എങ്കിൽ (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	എങ്കിൽ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ശൂന്യ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	വേണ്ടി (i = 0; i < അക്കം_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	വേണ്ടി (i = 0; i < അക്കം_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	എങ്കിൽ (hostfile_command != ശൂന്യ && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_താക്കോൽ, host);
	}

	ip_hostkeys = ശൂന്യ;
	എങ്കിൽ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		വേണ്ടി (i = 0; i < അക്കം_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		വേണ്ടി (i = 0; i < അക്കം_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		എങ്കിൽ (hostfile_command != ശൂന്യ && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_താക്കോൽ, ip);
		}
	}

 retry:
	എങ്കിൽ (!hostkey_accepted_by_hostkeyalgs(host_താക്കോൽ)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_താക്കോൽ));
		പോകുക fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_താക്കോൽ);
	type = sshkey_type(host_താക്കോൽ);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_താക്കോൽ_in_hostkeys(host_hostkeys, host_താക്കോൽ,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	എങ്കിൽ (!readonly && (അക്കം_user_hostfiles == 0 ||
	    (host_found != ശൂന്യ && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	എങ്കിൽ (!want_cert && ip_hostkeys != ശൂന്യ) {
		ip_status = check_താക്കോൽ_in_hostkeys(ip_hostkeys, host_താക്കോൽ,
		    &ip_found);
		എങ്കിൽ (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != ശൂന്യ &&
		    !sshkey_equal(ip_found->താക്കോൽ, host_found->താക്കോൽ))))
			host_ip_differ = 1;
	} അല്ലെങ്കിൽ
		ip_status = host_status;

	തിരഞ്ഞെടുപ്പ് (host_status) {
	അവസ്ഥ HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->വരി);
		എങ്കിൽ (want_cert) {
			എങ്കിൽ (sshkey_cert_check_host(host_താക്കോൽ,
			    options.host_താക്കോൽ_alias == ശൂന്യ ?
			    hostname : options.host_താക്കോൽ_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				പോകുക fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			എങ്കിൽ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		എങ്കിൽ (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, അക്കം_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != ശൂന്യ &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, അക്കം_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		എങ്കിൽ (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		എങ്കിൽ (options.check_host_ip && ip_status == HOST_NEW) {
			എങ്കിൽ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			അല്ലെങ്കിൽ എങ്കിൽ (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_താക്കോൽ, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			അല്ലെങ്കിൽ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} അല്ലെങ്കിൽ എങ്കിൽ (options.visual_host_താക്കോൽ) {
			fp = sshkey_fingerprint(host_താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			സ്വതന്ത്രം(ra);
			സ്വതന്ത്രം(fp);
		}
		hostkey_trusted = 1;
		നിർത്തുക;
	അവസ്ഥ HOST_NEW:
		എങ്കിൽ (options.host_താക്കോൽ_alias == ശൂന്യ && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			എങ്കിൽ (check_host_താക്കോൽ(hostname, cinfo, hostaddr, 0,
			    host_താക്കോൽ, ROQUIET, 1,
			    user_hostfiles, അക്കം_user_hostfiles,
			    system_hostfiles, അക്കം_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				നിർത്തുക;
			}
		}
		എങ്കിൽ (readonly || want_cert)
			പോകുക fail;
		/* The host is new. */
		എങ്കിൽ (options.strict_host_താക്കോൽ_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (options.strict_host_താക്കോൽ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			അക്ഷരം *msg1 = ശൂന്യ, *msg2 = ശൂന്യ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			എങ്കിൽ (show_other_താക്കോലുകൾ(host_hostkeys, host_താക്കോൽ)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} അല്ലെങ്കിൽ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_താക്കോൽ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			എങ്കിൽ (options.visual_host_താക്കോൽ)
				xextendf(&msg1, "\n", "%s", ra);
			എങ്കിൽ (options.verify_host_താക്കോൽ_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_താക്കോൽ_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			എങ്കിൽ ((msg2 = other_hostkeys_message(host, ip, host_താക്കോൽ,
			    user_hostfiles, അക്കം_user_hostfiles,
			    system_hostfiles, അക്കം_system_hostfiles)) != ശൂന്യ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			സ്വതന്ത്രം(ra);
			സ്വതന്ത്രം(fp);
			സ്വതന്ത്രം(msg1);
			സ്വതന്ത്രം(msg2);
			എങ്കിൽ (!confirmed)
				പോകുക fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		എങ്കിൽ (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, വലുപ്പം(hostline), "%s,%s", host, ip);
			hostp = hostline;
			എങ്കിൽ (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_താക്കോൽ, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_താക്കോൽ, options.hash_known_hosts);
			} അല്ലെങ്കിൽ {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_താക്കോൽ,
				    options.hash_known_hosts);
			}
		} അല്ലെങ്കിൽ {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_താക്കോൽ, options.hash_known_hosts);
			hostp = host;
		}

		എങ്കിൽ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		അല്ലെങ്കിൽ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		നിർത്തുക;
	അവസ്ഥ HOST_REVOKED:
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
		എങ്കിൽ (options.strict_host_താക്കോൽ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			പോകുക fail;
		}
		പോകുക continue_unsafe;

	അവസ്ഥ HOST_CHANGED:
		എങ്കിൽ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->വരി);
			പോകുക fail;
		}
		എങ്കിൽ (readonly == ROQUIET)
			പോകുക fail;
		എങ്കിൽ (options.check_host_ip && host_ip_differ) {
			അക്ഷരം *താക്കോൽ_സന്ദേശം;
			എങ്കിൽ (ip_status == HOST_NEW)
				താക്കോൽ_സന്ദേശം = "is unknown";
			അല്ലെങ്കിൽ എങ്കിൽ (ip_status == HOST_OK)
				താക്കോൽ_സന്ദേശം = "is unchanged";
			അല്ലെങ്കിൽ
				താക്കോൽ_സന്ദേശം = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", താക്കോൽ_സന്ദേശം);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			എങ്കിൽ (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->വരി);
		}
		/* The host key has changed. */
		warn_changed_താക്കോൽ(host_താക്കോൽ);
		എങ്കിൽ (അക്കം_user_hostfiles > 0 || അക്കം_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", അക്കം_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->താക്കോൽ),
		    host_found->file, host_found->വരി);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		എങ്കിൽ (options.strict_host_താക്കോൽ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			പോകുക fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		എങ്കിൽ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.അക്കം_local_forwards > 0 ||
		    options.അക്കം_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.അക്കം_local_forwards =
			    options.അക്കം_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		എങ്കിൽ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		എങ്കിൽ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		നിർത്തുക;
	അവസ്ഥ HOST_FOUND:
		fatal("internal error");
		നിർത്തുക;
	}

	എങ്കിൽ (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(സന്ദേശം, വലുപ്പം(സന്ദേശം),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->വരി);
		എങ്കിൽ (host_status == HOST_OK) {
			len = strlen(സന്ദേശം);
			snprintf(സന്ദേശം + len, വലുപ്പം(സന്ദേശം) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->വരി);
		}
		എങ്കിൽ (options.strict_host_താക്കോൽ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(സന്ദേശം, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", വലുപ്പം(സന്ദേശം));
			എങ്കിൽ (!confirm(സന്ദേശം, ശൂന്യ))
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (options.strict_host_താക്കോൽ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", സന്ദേശം);
			error("Exiting, you have requested strict checking.");
			പോകുക fail;
		} അല്ലെങ്കിൽ {
			logit("%s", സന്ദേശം);
		}
	}

	എങ്കിൽ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_താക്കോൽ);
	സ്വതന്ത്രം(ip);
	സ്വതന്ത്രം(host);
	എങ്കിൽ (host_hostkeys != ശൂന്യ)
		free_hostkeys(host_hostkeys);
	എങ്കിൽ (ip_hostkeys != ശൂന്യ)
		free_hostkeys(ip_hostkeys);
	തിരികെ 0;

fail:
	എങ്കിൽ (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		എങ്കിൽ ((r = sshkey_from_private(host_താക്കോൽ, &raw_താക്കോൽ)) != 0)
			fatal_fr(r, "decode key");
		എങ്കിൽ ((r = sshkey_drop_cert(raw_താക്കോൽ)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_താക്കോൽ = raw_താക്കോൽ;
		പോകുക retry;
	}
	sshkey_free(raw_താക്കോൽ);
	സ്വതന്ത്രം(ip);
	സ്വതന്ത്രം(host);
	എങ്കിൽ (host_hostkeys != ശൂന്യ)
		free_hostkeys(host_hostkeys);
	എങ്കിൽ (ip_hostkeys != ശൂന്യ)
		free_hostkeys(ip_hostkeys);
	തിരികെ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
പൂർണ്ണസംഖ്യ
verify_host_താക്കോൽ(അക്ഷരം *host, ഘടന sockaddr *hostaddr, ഘടന sshkey *host_താക്കോൽ,
    സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	u_int i;
	പൂർണ്ണസംഖ്യ r = -1, flags = 0;
	അക്ഷരം valid[64], *fp = ശൂന്യ, *cafp = ശൂന്യ;
	ഘടന sshkey *plain = ശൂന്യ;

	എങ്കിൽ ((fp = sshkey_fingerprint(host_താക്കോൽ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		പോകുക out;
	}

	എങ്കിൽ (sshkey_is_cert(host_താക്കോൽ)) {
		എങ്കിൽ ((cafp = sshkey_fingerprint(host_താക്കോൽ->cert->signature_താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			പോകുക out;
		}
		sshkey_format_cert_validity(host_താക്കോൽ->cert,
		    valid, വലുപ്പം(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_താക്കോൽ), fp,
		    (unsigned long long)host_താക്കോൽ->cert->serial,
		    host_താക്കോൽ->cert->താക്കോൽ_id,
		    sshkey_ssh_name(host_താക്കോൽ->cert->signature_താക്കോൽ), cafp,
		    valid);
		വേണ്ടി (i = 0; i < host_താക്കോൽ->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_താക്കോൽ->cert->principals[i]);
		}
	} അല്ലെങ്കിൽ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_താക്കോൽ), fp);
	}

	എങ്കിൽ (sshkey_equal(previous_host_താക്കോൽ, host_താക്കോൽ)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_താക്കോൽ), fp);
		r = 0;
		പോകുക out;
	}

	/* Check in RevokedHostKeys files if specified */
	വേണ്ടി (i = 0; i < options.അക്കം_revoked_host_താക്കോലുകൾ; i++) {
		r = sshkey_check_revoked(host_താക്കോൽ,
		    options.revoked_host_താക്കോലുകൾ[i]);
		തിരഞ്ഞെടുപ്പ് (r) {
		അവസ്ഥ 0:
			നിർത്തുക; /* not revoked */
		അവസ്ഥ SSH_ERR_താക്കോൽ_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_താക്കോൽ), fp,
			    options.revoked_host_താക്കോലുകൾ[i]);
			r = -1;
			പോകുക out;
		സ്ഥിരസ്ഥിതി:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_താക്കോൽ),
			    fp, options.revoked_host_താക്കോലുകൾ[i]);
			r = -1;
			പോകുക out;
		}
	}

	എങ്കിൽ (options.verify_host_താക്കോൽ_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		എങ്കിൽ ((r = sshkey_from_private(host_താക്കോൽ, &plain)) != 0)
			പോകുക out;
		എങ്കിൽ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		എങ്കിൽ (verify_host_താക്കോൽ_dns(host, hostaddr, plain, &flags) == 0) {
			എങ്കിൽ (flags & DNS_VERIFY_FOUND) {
				എങ്കിൽ (options.verify_host_താക്കോൽ_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					പോകുക out;
				}
				എങ്കിൽ (flags & DNS_VERIFY_MATCH) {
					matching_host_താക്കോൽ_dns = 1;
				} അല്ലെങ്കിൽ {
					warn_changed_താക്കോൽ(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_താക്കോൽ(host, cinfo, hostaddr, options.port, host_താക്കോൽ,
	    RDRW, 0, options.user_hostfiles, options.അക്കം_user_hostfiles,
	    options.system_hostfiles, options.അക്കം_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	സ്വതന്ത്രം(fp);
	സ്വതന്ത്രം(cafp);
	എങ്കിൽ (r == 0 && host_താക്കോൽ != ശൂന്യ) {
		sshkey_free(previous_host_താക്കോൽ);
		r = sshkey_from_private(host_താക്കോൽ, &previous_host_താക്കോൽ);
	}

	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
warn_nonpq_kex(ശൂന്യം)
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
ശൂന്യം
ssh_login(ഘടന ssh *ssh, Sensitive *sensitive, സ്ഥിരം അക്ഷരം *orighost,
    ഘടന sockaddr_storage *hostaddr, u_short port, ഘടന passwd *pw,
    പൂർണ്ണസംഖ്യ timeout_ms, സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	അക്ഷരം *host;
	അക്ഷരം *server_user, *local_user;
	പൂർണ്ണസംഖ്യ r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	എങ്കിൽ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	എങ്കിൽ ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	എങ്കിൽ (!options.kex_algorithms_set && ssh->kex != ശൂന്യ &&
	    ssh->kex->name != ശൂന്യ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	സ്വതന്ത്രം(local_user);
	സ്വതന്ത്രം(host);
}

/* print all known host keys for a given host, but skip keys of given type */
സ്ഥിതം പൂർണ്ണസംഖ്യ
show_other_താക്കോലുകൾ(ഘടന hostkeys *hostkeys, ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ type[] = {
		താക്കോൽ_RSA,
		താക്കോൽ_ECDSA,
		താക്കോൽ_ED25519,
		താക്കോൽ_MLDSA44_ED25519,
		-1
	};
	പൂർണ്ണസംഖ്യ i, ret = 0;
	അക്ഷരം *fp, *ra;
	സ്ഥിരം ഘടന hostkey_entry *found;

	വേണ്ടി (i = 0; type[i] != -1; i++) {
		എങ്കിൽ (type[i] == താക്കോൽ->type)
			തുടരുക;
		എങ്കിൽ (!lookup_താക്കോൽ_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			തുടരുക;
		fp = sshkey_fingerprint(found->താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->താക്കോൽ),
		    found->host, found->file, found->വരി,
		    sshkey_type(found->താക്കോൽ), fp);
		എങ്കിൽ (options.visual_host_താക്കോൽ)
			logit("%s", ra);
		സ്വതന്ത്രം(ra);
		സ്വതന്ത്രം(fp);
		ret = 1;
	}
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
warn_changed_താക്കോൽ(ഘടന sshkey *host_താക്കോൽ)
{
	അക്ഷരം *fp;

	fp = sshkey_fingerprint(host_താക്കോൽ, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	എങ്കിൽ (fp == ശൂന്യ)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_താക്കോൽ), fp);
	error("Please contact your system administrator.");

	സ്വതന്ത്രം(fp);
}

/*
 * Execute a local command
 */
പൂർണ്ണസംഖ്യ
ssh_local_cmd(സ്ഥിരം അക്ഷരം *args)
{
	അക്ഷരം *shell;
	pid_t pid;
	പൂർണ്ണസംഖ്യ status;
	ശൂന്യം (*osighand)(പൂർണ്ണസംഖ്യ);

	എങ്കിൽ (!options.permit_local_command ||
	    args == ശൂന്യ || !*args)
		തിരികെ (1);

	എങ്കിൽ ((shell = getenv("SHELL")) == ശൂന്യ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	എങ്കിൽ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (അക്ഷരം *)ശൂന്യ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} അല്ലെങ്കിൽ എങ്കിൽ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	എങ്കിൽ (!WIFEXITED(status))
		തിരികെ (1);

	തിരികെ (WEXITSTATUS(status));
}

ശൂന്യം
maybe_add_താക്കോൽ_to_agent(സ്ഥിരം അക്ഷരം *authfile, ഘടന sshkey *സ്വകാര്യ,
    സ്ഥിരം അക്ഷരം *comment, സ്ഥിരം അക്ഷരം *passphrase)
{
	പൂർണ്ണസംഖ്യ auth_sock = -1, r;
	സ്ഥിരം അക്ഷരം *skprovider = ശൂന്യ;

	എങ്കിൽ (options.add_താക്കോലുകൾ_to_agent == 0)
		തിരികെ;

	എങ്കിൽ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		തിരികെ;
	}

	എങ്കിൽ (options.add_താക്കോലുകൾ_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		തിരികെ;
	}
	എങ്കിൽ (sshkey_is_sk(സ്വകാര്യ))
		skprovider = options.sk_provider;
	എങ്കിൽ ((r = ssh_add_identity_constrained(auth_sock, സ്വകാര്യ,
	    comment == ശൂന്യ ? authfile : comment,
	    options.add_താക്കോലുകൾ_to_agent_lifespan,
	    (options.add_താക്കോലുകൾ_to_agent == 3), skprovider, ശൂന്യ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	അല്ലെങ്കിൽ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
