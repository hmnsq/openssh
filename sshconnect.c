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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <net/if.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <ifaddrs.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshconnect.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "dns.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "kex.h"

ಸಂರಚನಾ sshkey *previous_host_ಕೀಲಿ = ರಿಕ್ತ;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ matching_host_ಕೀಲಿ_dns = 0;

ಸ್ಥಿರ pid_t proxy_command_pid = 0;

/* import */
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ debug_flag;
ಬಾಹ್ಯ Options options;
ಬಾಹ್ಯ ವರ್ಣ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ show_other_ಕೀಲಿಗಳು(ಸಂರಚನಾ hostkeys *, ಸಂರಚನಾ sshkey *);
ಸ್ಥಿರ ಶೂನ್ಯ warn_changed_ಕೀಲಿ(ಸಂರಚನಾ sshkey *);

ಶೂನ್ಯ
ssh_conn_info_free(ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ಯದಿ (cinfo == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(cinfo->conn_hash_hex);
	ಮುಕ್ತ(cinfo->shorthost);
	ಮುಕ್ತ(cinfo->uidstr);
	ಮುಕ್ತ(cinfo->keyalias);
	ಮುಕ್ತ(cinfo->thishost);
	ಮುಕ್ತ(cinfo->host_arg);
	ಮುಕ್ತ(cinfo->portstr);
	ಮುಕ್ತ(cinfo->remhost);
	ಮುಕ್ತ(cinfo->remuser);
	ಮುಕ್ತ(cinfo->homedir);
	ಮುಕ್ತ(cinfo->locuser);
	ಮುಕ್ತ(cinfo->jmphost);
	freezero(cinfo, ಪರಿಮಾಣ(*cinfo));
}

ಸಂರಚನಾ ssh_conn_info *
ssh_conn_info_dup(ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ಸಂರಚನಾ ssh_conn_info *ret;

	ಯದಿ (cinfo == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret = xcalloc(1, ಪರಿಮಾಣ(*ret));
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
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* Expand a proxy command */
ಸ್ಥಿರ ವರ್ಣ *
expand_proxy_command(ಧ್ರುವ ವರ್ಣ *proxy_command, ಧ್ರುವ ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *host_arg, ಪೂರ್ಣಾಙ್ಕ port)
{
	ವರ್ಣ *tmp, *ret, strport[NI_MAXSERV];
	ಧ್ರುವ ವರ್ಣ *keyalias = options.host_ಕೀಲಿ_alias ?
	    options.host_ಕೀಲಿ_alias : host_arg;

	snprintf(strport, ಪರಿಮಾಣ strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (ವರ್ಣ *)ರಿಕ್ತ);
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_proxy_fdpass_connect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *host_arg, u_short port, ಧ್ರುವ ವರ್ಣ *proxy_command)
{
	ವರ್ಣ *command_string;
	ಪೂರ್ಣಾಙ್ಕ sp[2], sock;
	pid_t pid;
	ವರ್ಣ *shell;

	ಯದಿ ((shell = getenv("SHELL")) == ರಿಕ್ತ)
		shell = _PATH_BSHELL;

	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ಯದಿ ((pid = fork()) == 0) {
		ವರ್ಣ *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ಯದಿ (sp[0] != 0) {
			ಯದಿ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ಯದಿ (sp[0] != 1) {
			ಯದಿ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ಯದಿ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ಯದಿ (!debug_flag && options.control_path != ರಿಕ್ತ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ರಿಕ್ತ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	ಯದಿ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	ಮುಕ್ತ(command_string);

	ಯದಿ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ಯಾವತ್ (waitpid(pid, ರಿಕ್ತ, 0) == -1)
		ಯದಿ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ಯದಿ (ssh_packet_set_connection(ssh, sock, sock) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1; /* ssh_packet_set_connection logs error */

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_proxy_connect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *host_arg,
    u_short port, ಧ್ರುವ ವರ್ಣ *proxy_command)
{
	ವರ್ಣ *command_string;
	ಪೂರ್ಣಾಙ್ಕ pin[2], pout[2];
	pid_t pid;
	ವರ್ಣ *shell;

	ಯದಿ ((shell = getenv("SHELL")) == ರಿಕ್ತ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ಯದಿ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ಯದಿ ((pid = fork()) == 0) {
		ವರ್ಣ *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ಯದಿ (pin[0] != 0) {
			ಯದಿ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ಯದಿ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ಯದಿ (!debug_flag && options.control_path != ರಿಕ್ತ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ರಿಕ್ತ;

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
	ಯದಿ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ಅನ್ಯಥಾ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	ಮುಕ್ತ(command_string);

	/* Set the connection file descriptors. */
	ಯದಿ (ssh_packet_set_connection(ssh, pout[0], pin[1]) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1; /* ssh_packet_set_connection logs error */

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_kill_proxy_command(ಶೂನ್ಯ)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ಯದಿ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_ifaddrs(ಧ್ರುವ ವರ್ಣ *ifname, ಪೂರ್ಣಾಙ್ಕ af, ಧ್ರುವ ಸಂರಚನಾ ifaddrs *ifaddrs,
    ಸಂರಚನಾ sockaddr_storage *resultp, socklen_t *rlenp)
{
	ಸಂರಚನಾ sockaddr_in6 *sa6;
	ಸಂರಚನಾ sockaddr_in *sa;
	ಸಂರಚನಾ in6_addr *v6addr;
	ಧ್ರುವ ಸಂರಚನಾ ifaddrs *ifa;
	ಪೂರ್ಣಾಙ್ಕ allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	ಪ್ರತಿ (allow_local = 0; allow_local < 2; allow_local++) {
		ಪ್ರತಿ (ifa = ifaddrs; ifa != ರಿಕ್ತ; ifa = ifa->ifa_next) {
			ಯದಿ (ifa->ifa_addr == ರಿಕ್ತ || ifa->ifa_name == ರಿಕ್ತ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ಅನುವರ್ತ;
			ವಿಕಲ್ಪ (ifa->ifa_addr->sa_family) {
			ಪಕ್ಷ AF_INET:
				sa = (ಸಂರಚನಾ sockaddr_in *)ifa->ifa_addr;
				ಯದಿ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ಅನುವರ್ತ;
				ಯದಿ (*rlenp < ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ಪ್ರತ್ಯಾಗಮ -1;
				}
				*rlenp = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				ಪ್ರತ್ಯಾಗಮ 0;
			ಪಕ್ಷ AF_INET6:
				sa6 = (ಸಂರಚನಾ sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ಯದಿ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ಅನುವರ್ತ;
				ಯದಿ (*rlenp < ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ಪ್ರತ್ಯಾಗಮ -1;
				}
				*rlenp = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				ಪ್ರತ್ಯಾಗಮ 0;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_create_socket(ಸಂರಚನಾ addrinfo *ai)
{
	ಪೂರ್ಣಾಙ್ಕ sock, r;
	ಸಂರಚನಾ sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ಸಂರಚನಾ addrinfo hints, *res = ರಿಕ್ತ;
#ifdef HAVE_IFADDRS_H
	ಸಂರಚನಾ ifaddrs *ifaddrs = ರಿಕ್ತ;
#endif
	ವರ್ಣ ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ಯದಿ (sock == -1) {
		error("socket: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	(ಶೂನ್ಯ)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ಯದಿ (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ಯದಿ (options.bind_address == ರಿಕ್ತ && options.bind_interface == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ sock;

	ಯದಿ (options.bind_address != ರಿಕ್ತ) {
		memset(&hints, 0, ಪರಿಮಾಣ(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ಯದಿ ((r = getaddrinfo(options.bind_address, ರಿಕ್ತ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			ಗಚ್ಛ fail;
		}
		ಯದಿ (res == ರಿಕ್ತ) {
			error("getaddrinfo: no addrs");
			ಗಚ್ಛ fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ಅನ್ಯಥಾ ಯದಿ (options.bind_interface != ರಿಕ್ತ) {
#ifdef HAVE_IFADDRS_H
		ಯದಿ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			ಗಚ್ಛ fail;
		}
		bindaddrlen = ಪರಿಮಾಣ(bindaddr);
		ಯದಿ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			ಗಚ್ಛ fail;
		}
#ಅನ್ಯಥಾ
		error("BindInterface not supported on this platform.");
#endif
	}
	ಯದಿ ((r = getnameinfo((ಸಂರಚನಾ sockaddr *)&bindaddr, bindaddrlen,
	    ntop, ಪರಿಮಾಣ(ntop), ರಿಕ್ತ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		ಗಚ್ಛ fail;
	}
	ಯದಿ (bind(sock, (ಸಂರಚನಾ sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		ಗಚ್ಛ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	ಗಚ್ಛ out;
fail:
	close(sock);
	sock = -1;
 out:
	ಯದಿ (res != ರಿಕ್ತ)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	ಯದಿ (ifaddrs != ರಿಕ್ತ)
		freeifaddrs(ifaddrs);
#endif
	ಪ್ರತ್ಯಾಗಮ sock;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_connect_direct(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host, ಸಂರಚನಾ addrinfo *aitop,
    ಸಂರಚನಾ sockaddr_storage *hostaddr, u_short port, ಪೂರ್ಣಾಙ್ಕ connection_attempts,
    ಪೂರ್ಣಾಙ್ಕ *timeout_ms, ಪೂರ್ಣಾಙ್ಕ want_keepalive)
{
	ಪೂರ್ಣಾಙ್ಕ saved_timeout_ms = *timeout_ms;
	ಪೂರ್ಣಾಙ್ಕ oerrno, sock = -1, attempt;
	ವರ್ಣ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ಸಂರಚನಾ addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, ಪರಿಮಾಣ(ntop));
	memset(strport, 0, ಪರಿಮಾಣ(strport));

	ಪ್ರತಿ (attempt = 0; attempt < connection_attempts; attempt++) {
		ಯದಿ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		ಪ್ರತಿ (ai = aitop; ai; ai = ai->ai_next) {
			ಯದಿ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ಅನುವರ್ತ;
			}
			ಯದಿ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, ಪರಿಮಾಣ(ntop), strport, ಪರಿಮಾಣ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ಅನುವರ್ತ;
			}
			ಯದಿ (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ಅನುವರ್ತ;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ಯದಿ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ಅನುವರ್ತ;
			}

			*timeout_ms = saved_timeout_ms;
			ಯದಿ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				ಭಙ್ಗ;
			} ಅನ್ಯಥಾ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ಯದಿ (sock != -1)
			ಭಙ್ಗ;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ಯದಿ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ಯದಿ (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ಯದಿ (ssh_packet_set_connection(ssh, sock, sock) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1; /* ssh_packet_set_connection logs error */

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_connect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *host_arg,
    ಸಂರಚನಾ addrinfo *addrs, ಸಂರಚನಾ sockaddr_storage *hostaddr, u_short port,
    ಪೂರ್ಣಾಙ್ಕ connection_attempts, ಪೂರ್ಣಾಙ್ಕ *timeout_ms, ಪೂರ್ಣಾಙ್ಕ want_keepalive)
{
	ಪೂರ್ಣಾಙ್ಕ in, out;

	ಯದಿ (options.proxy_command == ರಿಕ್ತ) {
		ಪ್ರತ್ಯಾಗಮ ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(options.proxy_command, "-") == 0) {
		ಯದಿ ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			ಯದಿ (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			ಪ್ರತ್ಯಾಗಮ -1; /* ssh_packet_set_connection logs error */
		}
		ಯದಿ ((ssh_packet_set_connection(ssh, in, out)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1; /* ssh_packet_set_connection logs error */
		ಪ್ರತ್ಯಾಗಮ 0;
	} ಅನ್ಯಥಾ ಯದಿ (options.proxy_use_fdpass) {
		ಪ್ರತ್ಯಾಗಮ ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	ಪ್ರತ್ಯಾಗಮ ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
confirm(ಧ್ರುವ ವರ್ಣ *prompt, ಧ್ರುವ ವರ್ಣ *fingerprint)
{
	ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ, *again = "Please type 'yes' or 'no': ";
	ಧ್ರುವ ವರ್ಣ *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	ವರ್ಣ *p, *cp;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (options.batch_mode)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (ಸಂದೇಶ = prompt;;ಸಂದೇಶ = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(ಸಂದೇಶ, RP_ECHO);
		ಯದಿ (p == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ಯದಿ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ಅನ್ಯಥಾ ಯದಿ (strcasecmp(p, "yes") == 0 || (fingerprint != ರಿಕ್ತ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		ಮುಕ್ತ(cp);
		ಯದಿ (ret != -1)
			ಪ್ರತ್ಯಾಗಮ ret;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sockaddr_is_local(ಸಂರಚನಾ sockaddr *hostaddr)
{
	ವಿಕಲ್ಪ (hostaddr->sa_family) {
	ಪಕ್ಷ AF_INET:
		ಪ್ರತ್ಯಾಗಮ (ntohl(((ಸಂರಚನಾ sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತ್ಯಾಗಮ IN6_IS_ADDR_LOOPBACK(
		    &(((ಸಂರಚನಾ sockaddr_in6 *)hostaddr)->sin6_addr));
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
ಶೂನ್ಯ
get_hostfile_hostname_ipaddr(ವರ್ಣ *hostname, ಸಂರಚನಾ sockaddr *hostaddr,
    u_short port, ವರ್ಣ **hostfile_hostname, ವರ್ಣ **hostfile_ipaddr)
{
	ವರ್ಣ ntop[NI_MAXHOST];
	socklen_t addrlen;

	ವಿಕಲ್ಪ (hostaddr == ರಿಕ್ತ ? -1 : hostaddr->sa_family) {
	ಪಕ್ಷ -1:
		addrlen = 0;
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET:
		addrlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
		addrlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		addrlen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr);
		ಭಙ್ಗ;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ಯದಿ (hostfile_ipaddr != ರಿಕ್ತ) {
		ಯದಿ (options.proxy_command == ರಿಕ್ತ) {
			ಯದಿ (getnameinfo(hostaddr, addrlen,
			    ntop, ಪರಿಮಾಣ(ntop), ರಿಕ್ತ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} ಅನ್ಯಥಾ {
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
	ಯದಿ (hostfile_hostname != ರಿಕ್ತ) {
		ಯದಿ (options.host_ಕೀಲಿ_alias != ರಿಕ್ತ) {
			*hostfile_hostname = xstrdup(options.host_ಕೀಲಿ_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ಅನ್ಯಥಾ {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
path_in_hostfiles(ಧ್ರುವ ವರ್ಣ *path, ವರ್ಣ **hostfiles, u_int ಅಂಕೆ_hostfiles)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_hostfiles; i++) {
		ಯದಿ (strcmp(path, hostfiles[i]) == 0)
			ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ find_by_ಕೀಲಿ_ctx {
	ಧ್ರುವ ವರ್ಣ *host, *ip;
	ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ವರ್ಣ **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ಸ್ಥಿರ ವರ್ಣ *
try_tilde_unexpand(ಧ್ರುವ ವರ್ಣ *path)
{
	ವರ್ಣ *home, *ret = ರಿಕ್ತ;
	size_t l;

	ಯದಿ (*path != '/')
		ಪ್ರತ್ಯಾಗಮ xstrdup(path);
	ಯದಿ ((home = getenv("HOME")) == ರಿಕ್ತ || (l = strlen(home)) == 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup(path);
	ಯದಿ (strncmp(path, home, l) != 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ಯದಿ (home[l - 1] != '/' && path[l] != '/')
		ಪ್ರತ್ಯಾಗಮ xstrdup(path);
	ಯದಿ (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
ಪೂರ್ಣಾಙ್ಕ
hostkey_accepted_by_hostkeyalgs(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಧ್ರುವ ವರ್ಣ *ktype = sshkey_ssh_name(ಕೀಲಿ);
	ಧ್ರುವ ವರ್ಣ *hostkeyalgs = options.hostkeyalgorithms;

	ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_UNSPEC)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ಪ್ರತ್ಯಾಗಮ 1;
	ಪ್ರತ್ಯಾಗಮ match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
hostkeys_find_by_ಕೀಲಿ_cb(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ find_by_ಕೀಲಿ_ctx *ctx = (ಸಂರಚನಾ find_by_ಕೀಲಿ_ctx *)_ctx;
	ವರ್ಣ *path;

	/* we are looking for keys with names that *do not* match */
	ಯದಿ ((l->match & HKF_MATCH_HOST) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* not interested in marker lines */
	ಯದಿ (l->marker != MRK_NONE)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* we are only interested in exact key matches */
	ಯದಿ (l->ಕೀಲಿ == ರಿಕ್ತ || !sshkey_equal(ctx->ಕೀಲಿ, l->ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, ಪರಿಮಾಣ(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
hostkeys_find_by_ಕೀಲಿ_hostfile(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *which,
    ಸಂರಚನಾ find_by_ಕೀಲಿ_ctx *ctx)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ಯದಿ ((r = hostkeys_foreach(file, hostkeys_find_by_ಕೀಲಿ_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
		ಯದಿ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
hostkeys_find_by_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ವರ್ಣ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ವರ್ಣ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles,
    ವರ್ಣ ***names, u_int *nnames)
{
	ಸಂರಚನಾ find_by_ಕೀಲಿ_ctx ctx = {ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, 0};
	u_int i;

	*names = ರಿಕ್ತ;
	*nnames = 0;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || sshkey_is_cert(ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.ಕೀಲಿ = ಕೀಲಿ;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++) {
		ಯದಿ (hostkeys_find_by_ಕೀಲಿ_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			ಗಚ್ಛ fail;
	}
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++) {
		ಯದಿ (hostkeys_find_by_ಕೀಲಿ_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			ಗಚ್ಛ fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = ರಿಕ್ತ;
	ctx.nnames = 0;
	ಪ್ರತ್ಯಾಗಮ;
 fail:
	ಪ್ರತಿ (i = 0; i < ctx.nnames; i++)
		ಮುಕ್ತ(ctx.names[i]);
	ಮುಕ್ತ(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
ಸ್ಥಿರ ವರ್ಣ *
other_hostkeys_message(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ವರ್ಣ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ವರ್ಣ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles)
{
	ವರ್ಣ *ret = ರಿಕ್ತ, **othernames = ರಿಕ್ತ;
	u_int i, n, ಅಂಕೆ_othernames = 0;

	hostkeys_find_by_ಕೀಲಿ(host, ip, ಕೀಲಿ,
	    user_hostfiles, ಅಂಕೆ_user_hostfiles,
	    system_hostfiles, ಅಂಕೆ_system_hostfiles,
	    &othernames, &ಅಂಕೆ_othernames);
	ಯದಿ (ಅಂಕೆ_othernames == 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = ಅಂಕೆ_othernames;
	ಯದಿ (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	ಪ್ರತಿ (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ಯದಿ (n < ಅಂಕೆ_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    ಅಂಕೆ_othernames - n);
	}
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_othernames; i++)
		ಮುಕ್ತ(othernames[i]);
	ಮುಕ್ತ(othernames);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
load_hostkeys_command(ಸಂರಚನಾ hostkeys *hostkeys, ಧ್ರುವ ವರ್ಣ *command_template,
    ಧ್ರುವ ವರ್ಣ *invocation, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *host_ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hostfile_hostname)
{
	ಪೂರ್ಣಾಙ್ಕ r, i, ac = 0;
	ವರ್ಣ *ಕೀಲಿ_fp = ರಿಕ್ತ, *keytext = ರಿಕ್ತ, *tmp;
	ವರ್ಣ *command = ರಿಕ್ತ, *tag = ರಿಕ್ತ, **av = ರಿಕ್ತ;
	FILE *f = ರಿಕ್ತ;
	pid_t pid;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	ಯದಿ (host_ಕೀಲಿ != ರಿಕ್ತ) {
		ಯದಿ ((ಕೀಲಿ_fp = sshkey_fingerprint(host_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("sshkey_fingerprint failed");
		ಯದಿ ((r = sshkey_to_base64(host_ಕೀಲಿ, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ಯದಿ (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		ಗಚ್ಛ out;
	}
	ಯದಿ (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_ಕೀಲಿ == ರಿಕ್ತ ? "NONE" : sshkey_ssh_name(host_ಕೀಲಿ),
		    "f", ಕೀಲಿ_fp == ರಿಕ್ತ ? "NONE" : ಕೀಲಿ_fp,
		    "K", keytext == ರಿಕ್ತ ? "NONE" : keytext,
		    (ವರ್ಣ *)ರಿಕ್ತ);
		ಯದಿ (tmp == ರಿಕ್ತ)
			fatal_f("percent_expand failed");
		ಮುಕ್ತ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ಯದಿ ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ)) == 0)
		ಗಚ್ಛ out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	ಯದಿ (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	ಯದಿ (f != ರಿಕ್ತ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಪ್ರತಿ (i = 0; i < ac; i++)
		ಮುಕ್ತ(av[i]);
	ಮುಕ್ತ(av);
	ಮುಕ್ತ(tag);
	ಮುಕ್ತ(command);
	ಮುಕ್ತ(ಕೀಲಿ_fp);
	ಮುಕ್ತ(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_host_ಕೀಲಿ(ವರ್ಣ *hostname, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo,
    ಸಂರಚನಾ sockaddr *hostaddr, u_short port,
    ಸಂರಚನಾ sshkey *host_ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ readonly, ಪೂರ್ಣಾಙ್ಕ clobber_port,
    ವರ್ಣ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ವರ್ಣ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles,
    ಧ್ರುವ ವರ್ಣ *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	ಸಂರಚನಾ sshkey *raw_ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *ip = ರಿಕ್ತ, *host = ರಿಕ್ತ;
	ವರ್ಣ hostline[1000], *hostp, *fp, *ra;
	ವರ್ಣ ಸಂದೇಶ[1024];
	ಧ್ರುವ ವರ್ಣ *type, *fail_reason = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ hostkey_entry *host_found = ರಿಕ್ತ, *ip_found = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ len, cancelled_forwarding = 0, confirmed;
	ಪೂರ್ಣಾಙ್ಕ local = sockaddr_is_local(hostaddr);
	ಪೂರ್ಣಾಙ್ಕ r, want_cert = sshkey_is_cert(host_ಕೀಲಿ), host_ip_differ = 0;
	ಪೂರ್ಣಾಙ್ಕ hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ಸಂರಚನಾ hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ಯದಿ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_ಕೀಲಿ_alias == ರಿಕ್ತ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ಯದಿ (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	ಯದಿ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ರಿಕ್ತ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ಯದಿ (hostfile_command != ರಿಕ್ತ && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_ಕೀಲಿ, host);
	}

	ip_hostkeys = ರಿಕ್ತ;
	ಯದಿ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ಯದಿ (hostfile_command != ರಿಕ್ತ && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_ಕೀಲಿ, ip);
		}
	}

 retry:
	ಯದಿ (!hostkey_accepted_by_hostkeyalgs(host_ಕೀಲಿ)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_ಕೀಲಿ));
		ಗಚ್ಛ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_ಕೀಲಿ);
	type = sshkey_type(host_ಕೀಲಿ);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_ಕೀಲಿ_in_hostkeys(host_hostkeys, host_ಕೀಲಿ,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ಯದಿ (!readonly && (ಅಂಕೆ_user_hostfiles == 0 ||
	    (host_found != ರಿಕ್ತ && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ಯದಿ (!want_cert && ip_hostkeys != ರಿಕ್ತ) {
		ip_status = check_ಕೀಲಿ_in_hostkeys(ip_hostkeys, host_ಕೀಲಿ,
		    &ip_found);
		ಯದಿ (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != ರಿಕ್ತ &&
		    !sshkey_equal(ip_found->ಕೀಲಿ, host_found->ಕೀಲಿ))))
			host_ip_differ = 1;
	} ಅನ್ಯಥಾ
		ip_status = host_status;

	ವಿಕಲ್ಪ (host_status) {
	ಪಕ್ಷ HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->ಸಾಲು);
		ಯದಿ (want_cert) {
			ಯದಿ (sshkey_cert_check_host(host_ಕೀಲಿ,
			    options.host_ಕೀಲಿ_alias == ರಿಕ್ತ ?
			    hostname : options.host_ಕೀಲಿ_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				ಗಚ್ಛ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ಯದಿ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ಯದಿ (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, ಅಂಕೆ_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != ರಿಕ್ತ &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, ಅಂಕೆ_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ಯದಿ (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ಯದಿ (options.check_host_ip && ip_status == HOST_NEW) {
			ಯದಿ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ಅನ್ಯಥಾ ಯದಿ (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_ಕೀಲಿ, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ಅನ್ಯಥಾ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ಅನ್ಯಥಾ ಯದಿ (options.visual_host_ಕೀಲಿ) {
			fp = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			ಮುಕ್ತ(ra);
			ಮುಕ್ತ(fp);
		}
		hostkey_trusted = 1;
		ಭಙ್ಗ;
	ಪಕ್ಷ HOST_NEW:
		ಯದಿ (options.host_ಕೀಲಿ_alias == ರಿಕ್ತ && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			ಯದಿ (check_host_ಕೀಲಿ(hostname, cinfo, hostaddr, 0,
			    host_ಕೀಲಿ, ROQUIET, 1,
			    user_hostfiles, ಅಂಕೆ_user_hostfiles,
			    system_hostfiles, ಅಂಕೆ_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (readonly || want_cert)
			ಗಚ್ಛ fail;
		/* The host is new. */
		ಯದಿ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			ವರ್ಣ *msg1 = ರಿಕ್ತ, *msg2 = ರಿಕ್ತ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ಯದಿ (show_other_ಕೀಲಿಗಳು(host_hostkeys, host_ಕೀಲಿ)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ಅನ್ಯಥಾ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ಯದಿ (options.visual_host_ಕೀಲಿ)
				xextendf(&msg1, "\n", "%s", ra);
			ಯದಿ (options.verify_host_ಕೀಲಿ_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_ಕೀಲಿ_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ಯದಿ ((msg2 = other_hostkeys_message(host, ip, host_ಕೀಲಿ,
			    user_hostfiles, ಅಂಕೆ_user_hostfiles,
			    system_hostfiles, ಅಂಕೆ_system_hostfiles)) != ರಿಕ್ತ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			ಮುಕ್ತ(ra);
			ಮುಕ್ತ(fp);
			ಮುಕ್ತ(msg1);
			ಮುಕ್ತ(msg2);
			ಯದಿ (!confirmed)
				ಗಚ್ಛ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ಯದಿ (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, ಪರಿಮಾಣ(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ಯದಿ (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_ಕೀಲಿ, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_ಕೀಲಿ, options.hash_known_hosts);
			} ಅನ್ಯಥಾ {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_ಕೀಲಿ,
				    options.hash_known_hosts);
			}
		} ಅನ್ಯಥಾ {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_ಕೀಲಿ, options.hash_known_hosts);
			hostp = host;
		}

		ಯದಿ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ಅನ್ಯಥಾ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		ಭಙ್ಗ;
	ಪಕ್ಷ HOST_REVOKED:
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
		ಯದಿ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			ಗಚ್ಛ fail;
		}
		ಗಚ್ಛ continue_unsafe;

	ಪಕ್ಷ HOST_CHANGED:
		ಯದಿ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->ಸಾಲು);
			ಗಚ್ಛ fail;
		}
		ಯದಿ (readonly == ROQUIET)
			ಗಚ್ಛ fail;
		ಯದಿ (options.check_host_ip && host_ip_differ) {
			ವರ್ಣ *ಕೀಲಿ_ಸಂದೇಶ;
			ಯದಿ (ip_status == HOST_NEW)
				ಕೀಲಿ_ಸಂದೇಶ = "is unknown";
			ಅನ್ಯಥಾ ಯದಿ (ip_status == HOST_OK)
				ಕೀಲಿ_ಸಂದೇಶ = "is unchanged";
			ಅನ್ಯಥಾ
				ಕೀಲಿ_ಸಂದೇಶ = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", ಕೀಲಿ_ಸಂದೇಶ);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ಯದಿ (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->ಸಾಲು);
		}
		/* The host key has changed. */
		warn_changed_ಕೀಲಿ(host_ಕೀಲಿ);
		ಯದಿ (ಅಂಕೆ_user_hostfiles > 0 || ಅಂಕೆ_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", ಅಂಕೆ_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->ಕೀಲಿ),
		    host_found->file, host_found->ಸಾಲು);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ಯದಿ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			ಗಚ್ಛ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ಯದಿ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.ಅಂಕೆ_local_forwards > 0 ||
		    options.ಅಂಕೆ_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.ಅಂಕೆ_local_forwards =
			    options.ಅಂಕೆ_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ಯದಿ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ಯದಿ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		ಭಙ್ಗ;
	ಪಕ್ಷ HOST_FOUND:
		fatal("internal error");
		ಭಙ್ಗ;
	}

	ಯದಿ (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->ಸಾಲು);
		ಯದಿ (host_status == HOST_OK) {
			len = strlen(ಸಂದೇಶ);
			snprintf(ಸಂದೇಶ + len, ಪರಿಮಾಣ(ಸಂದೇಶ) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->ಸಾಲು);
		}
		ಯದಿ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(ಸಂದೇಶ, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", ಪರಿಮಾಣ(ಸಂದೇಶ));
			ಯದಿ (!confirm(ಸಂದೇಶ, ರಿಕ್ತ))
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", ಸಂದೇಶ);
			error("Exiting, you have requested strict checking.");
			ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ {
			logit("%s", ಸಂದೇಶ);
		}
	}

	ಯದಿ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_ಕೀಲಿ);
	ಮುಕ್ತ(ip);
	ಮುಕ್ತ(host);
	ಯದಿ (host_hostkeys != ರಿಕ್ತ)
		free_hostkeys(host_hostkeys);
	ಯದಿ (ip_hostkeys != ರಿಕ್ತ)
		free_hostkeys(ip_hostkeys);
	ಪ್ರತ್ಯಾಗಮ 0;

fail:
	ಯದಿ (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ಯದಿ ((r = sshkey_from_private(host_ಕೀಲಿ, &raw_ಕೀಲಿ)) != 0)
			fatal_fr(r, "decode key");
		ಯದಿ ((r = sshkey_drop_cert(raw_ಕೀಲಿ)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_ಕೀಲಿ = raw_ಕೀಲಿ;
		ಗಚ್ಛ retry;
	}
	sshkey_free(raw_ಕೀಲಿ);
	ಮುಕ್ತ(ip);
	ಮುಕ್ತ(host);
	ಯದಿ (host_hostkeys != ರಿಕ್ತ)
		free_hostkeys(host_hostkeys);
	ಯದಿ (ip_hostkeys != ರಿಕ್ತ)
		free_hostkeys(ip_hostkeys);
	ಪ್ರತ್ಯಾಗಮ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
ಪೂರ್ಣಾಙ್ಕ
verify_host_ಕೀಲಿ(ವರ್ಣ *host, ಸಂರಚನಾ sockaddr *hostaddr, ಸಂರಚನಾ sshkey *host_ಕೀಲಿ,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r = -1, flags = 0;
	ವರ್ಣ valid[64], *fp = ರಿಕ್ತ, *cafp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *plain = ರಿಕ್ತ;

	ಯದಿ ((fp = sshkey_fingerprint(host_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		ಗಚ್ಛ out;
	}

	ಯದಿ (sshkey_is_cert(host_ಕೀಲಿ)) {
		ಯದಿ ((cafp = sshkey_fingerprint(host_ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			ಗಚ್ಛ out;
		}
		sshkey_format_cert_validity(host_ಕೀಲಿ->cert,
		    valid, ಪರಿಮಾಣ(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_ಕೀಲಿ), fp,
		    (unsigned long long)host_ಕೀಲಿ->cert->serial,
		    host_ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    sshkey_ssh_name(host_ಕೀಲಿ->cert->signature_ಕೀಲಿ), cafp,
		    valid);
		ಪ್ರತಿ (i = 0; i < host_ಕೀಲಿ->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_ಕೀಲಿ->cert->principals[i]);
		}
	} ಅನ್ಯಥಾ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_ಕೀಲಿ), fp);
	}

	ಯದಿ (sshkey_equal(previous_host_ಕೀಲಿ, host_ಕೀಲಿ)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_ಕೀಲಿ), fp);
		r = 0;
		ಗಚ್ಛ out;
	}

	/* Check in RevokedHostKeys files if specified */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು; i++) {
		r = sshkey_check_revoked(host_ಕೀಲಿ,
		    options.revoked_host_ಕೀಲಿಗಳು[i]);
		ವಿಕಲ್ಪ (r) {
		ಪಕ್ಷ 0:
			ಭಙ್ಗ; /* not revoked */
		ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_ಕೀಲಿ), fp,
			    options.revoked_host_ಕೀಲಿಗಳು[i]);
			r = -1;
			ಗಚ್ಛ out;
		ಸ್ವಭಾವ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_ಕೀಲಿ),
			    fp, options.revoked_host_ಕೀಲಿಗಳು[i]);
			r = -1;
			ಗಚ್ಛ out;
		}
	}

	ಯದಿ (options.verify_host_ಕೀಲಿ_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ಯದಿ ((r = sshkey_from_private(host_ಕೀಲಿ, &plain)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ಯದಿ (verify_host_ಕೀಲಿ_dns(host, hostaddr, plain, &flags) == 0) {
			ಯದಿ (flags & DNS_VERIFY_FOUND) {
				ಯದಿ (options.verify_host_ಕೀಲಿ_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					ಗಚ್ಛ out;
				}
				ಯದಿ (flags & DNS_VERIFY_MATCH) {
					matching_host_ಕೀಲಿ_dns = 1;
				} ಅನ್ಯಥಾ {
					warn_changed_ಕೀಲಿ(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_ಕೀಲಿ(host, cinfo, hostaddr, options.port, host_ಕೀಲಿ,
	    RDRW, 0, options.user_hostfiles, options.ಅಂಕೆ_user_hostfiles,
	    options.system_hostfiles, options.ಅಂಕೆ_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	ಮುಕ್ತ(fp);
	ಮುಕ್ತ(cafp);
	ಯದಿ (r == 0 && host_ಕೀಲಿ != ರಿಕ್ತ) {
		sshkey_free(previous_host_ಕೀಲಿ);
		r = sshkey_from_private(host_ಕೀಲಿ, &previous_host_ಕೀಲಿ);
	}

	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
warn_nonpq_kex(ಶೂನ್ಯ)
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
ಶೂನ್ಯ
ssh_login(ಸಂರಚನಾ ssh *ssh, Sensitive *sensitive, ಧ್ರುವ ವರ್ಣ *orighost,
    ಸಂರಚನಾ sockaddr_storage *hostaddr, u_short port, ಸಂರಚನಾ passwd *pw,
    ಪೂರ್ಣಾಙ್ಕ timeout_ms, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ವರ್ಣ *host;
	ವರ್ಣ *server_user, *local_user;
	ಪೂರ್ಣಾಙ್ಕ r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ಯದಿ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ಯದಿ ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	ಯದಿ (!options.kex_algorithms_set && ssh->kex != ರಿಕ್ತ &&
	    ssh->kex->name != ರಿಕ್ತ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	ಮುಕ್ತ(local_user);
	ಮುಕ್ತ(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
show_other_ಕೀಲಿಗಳು(ಸಂರಚನಾ hostkeys *hostkeys, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ type[] = {
		ಕೀಲಿ_RSA,
		ಕೀಲಿ_ECDSA,
		ಕೀಲಿ_ED25519,
		ಕೀಲಿ_MLDSA44_ED25519,
		-1
	};
	ಪೂರ್ಣಾಙ್ಕ i, ret = 0;
	ವರ್ಣ *fp, *ra;
	ಧ್ರುವ ಸಂರಚನಾ hostkey_entry *found;

	ಪ್ರತಿ (i = 0; type[i] != -1; i++) {
		ಯದಿ (type[i] == ಕೀಲಿ->type)
			ಅನುವರ್ತ;
		ಯದಿ (!lookup_ಕೀಲಿ_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			ಅನುವರ್ತ;
		fp = sshkey_fingerprint(found->ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->ಕೀಲಿ),
		    found->host, found->file, found->ಸಾಲು,
		    sshkey_type(found->ಕೀಲಿ), fp);
		ಯದಿ (options.visual_host_ಕೀಲಿ)
			logit("%s", ra);
		ಮುಕ್ತ(ra);
		ಮುಕ್ತ(fp);
		ret = 1;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
warn_changed_ಕೀಲಿ(ಸಂರಚನಾ sshkey *host_ಕೀಲಿ)
{
	ವರ್ಣ *fp;

	fp = sshkey_fingerprint(host_ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ಯದಿ (fp == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_ಕೀಲಿ), fp);
	error("Please contact your system administrator.");

	ಮುಕ್ತ(fp);
}

/*
 * Execute a local command
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_local_cmd(ಧ್ರುವ ವರ್ಣ *args)
{
	ವರ್ಣ *shell;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ status;
	ಶೂನ್ಯ (*osighand)(ಪೂರ್ಣಾಙ್ಕ);

	ಯದಿ (!options.permit_local_command ||
	    args == ರಿಕ್ತ || !*args)
		ಪ್ರತ್ಯಾಗಮ (1);

	ಯದಿ ((shell = getenv("SHELL")) == ರಿಕ್ತ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ಯದಿ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (ವರ್ಣ *)ರಿಕ್ತ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} ಅನ್ಯಥಾ ಯದಿ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ಯಾವತ್ (waitpid(pid, &status, 0) == -1)
		ಯದಿ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ಯದಿ (!WIFEXITED(status))
		ಪ್ರತ್ಯಾಗಮ (1);

	ಪ್ರತ್ಯಾಗಮ (WEXITSTATUS(status));
}

ಶೂನ್ಯ
maybe_add_ಕೀಲಿ_to_agent(ಧ್ರುವ ವರ್ಣ *authfile, ಸಂರಚನಾ sshkey *ಗುಪ್ತ,
    ಧ್ರುವ ವರ್ಣ *comment, ಧ್ರುವ ವರ್ಣ *passphrase)
{
	ಪೂರ್ಣಾಙ್ಕ auth_sock = -1, r;
	ಧ್ರುವ ವರ್ಣ *skprovider = ರಿಕ್ತ;

	ಯದಿ (options.add_ಕೀಲಿಗಳು_to_agent == 0)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (options.add_ಕೀಲಿಗಳು_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (sshkey_is_sk(ಗುಪ್ತ))
		skprovider = options.sk_provider;
	ಯದಿ ((r = ssh_add_identity_constrained(auth_sock, ಗುಪ್ತ,
	    comment == ರಿಕ್ತ ? authfile : comment,
	    options.add_ಕೀಲಿಗಳು_to_agent_lifespan,
	    (options.add_ಕೀಲಿಗಳು_to_agent == 3), skprovider, ರಿಕ್ತ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ಅನ್ಯಥಾ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
