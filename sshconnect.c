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

ರಚನೆ sshkey *ಹಿಂದಿನ_host_ಕೀಲಿ = ಖಾಲಿ;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ matching_host_ಕೀಲಿ_dns = 0;

ಸ್ಥಿರ pid_t proxy_command_pid = 0;

/* import */
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ debug_flag;
ಬಾಹ್ಯ Options options;
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ show_other_ಕೀಲಿಗಳು(ರಚನೆ hostkeys *, ರಚನೆ sshkey *);
ಸ್ಥಿರ ಶೂನ್ಯ warn_ಬದಲಾಯಿತು_ಕೀಲಿ(ರಚನೆ sshkey *);

ಶೂನ್ಯ
ssh_conn_info_free(ರಚನೆ ssh_conn_info *cinfo)
{
	ಆದರೆ (cinfo == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(cinfo->conn_hash_hex);
	ಬಿಡುಗಡೆ(cinfo->shorthost);
	ಬಿಡುಗಡೆ(cinfo->uidstr);
	ಬಿಡುಗಡೆ(cinfo->keyalias);
	ಬಿಡುಗಡೆ(cinfo->thishost);
	ಬಿಡುಗಡೆ(cinfo->host_arg);
	ಬಿಡುಗಡೆ(cinfo->portstr);
	ಬಿಡುಗಡೆ(cinfo->remhost);
	ಬಿಡುಗಡೆ(cinfo->remuser);
	ಬಿಡುಗಡೆ(cinfo->homedir);
	ಬಿಡುಗಡೆ(cinfo->locuser);
	ಬಿಡುಗಡೆ(cinfo->jmphost);
	freezero(cinfo, ಗಾತ್ರ(*cinfo));
}

ರಚನೆ ssh_conn_info *
ssh_conn_info_dup(ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ರಚನೆ ssh_conn_info *ret;

	ಆದರೆ (cinfo == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret = xcalloc(1, ಗಾತ್ರ(*ret));
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
	ಹಿಂತಿರುಗಿ ret;
}

/* Expand a proxy command */
ಸ್ಥಿರ ಅಕ್ಷರ *
expand_proxy_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxy_command, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ಅಕ್ಷರ *tmp, *ret, strport[NI_MAXSERV];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keyalias = options.host_ಕೀಲಿ_alias ?
	    options.host_ಕೀಲಿ_alias : host_arg;

	snprintf(strport, ಗಾತ್ರ strport, "%d", ಪೋರ್ಟ್);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (ಅಕ್ಷರ *)ಖಾಲಿ);
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_proxy_fdpass_connect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg, u_short ಪೋರ್ಟ್, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxy_command)
{
	ಅಕ್ಷರ *command_string;
	ಪೂರ್ಣಾಂಕ sp[2], sock;
	pid_t pid;
	ಅಕ್ಷರ *shell;

	ಆದರೆ ((shell = getenv("SHELL")) == ಖಾಲಿ)
		shell = _PATH_BSHELL;

	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, ಪೋರ್ಟ್);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ಆದರೆ ((pid = fork()) == 0) {
		ಅಕ್ಷರ *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ಆದರೆ (sp[0] != 0) {
			ಆದರೆ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ಆದರೆ (sp[0] != 1) {
			ಆದರೆ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ಆದರೆ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ಆದರೆ (!debug_flag && options.control_ಮಾರ್ಗ != ಖಾಲಿ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ಖಾಲಿ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		ನಿರ್ಗಮಿಸು(1);
	}
	/* Parent. */
	ಆದರೆ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	ಬಿಡುಗಡೆ(command_string);

	ಆದರೆ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ಆಗ (waitpid(pid, ಖಾಲಿ, 0) == -1)
		ಆದರೆ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ಆದರೆ (ssh_packet_ಗಣ_connection(ssh, sock, sock) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1; /* ssh_packet_set_connection logs error */

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_proxy_connect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg,
    u_short ಪೋರ್ಟ್, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proxy_command)
{
	ಅಕ್ಷರ *command_string;
	ಪೂರ್ಣಾಂಕ pin[2], pout[2];
	pid_t pid;
	ಅಕ್ಷರ *shell;

	ಆದರೆ ((shell = getenv("SHELL")) == ಖಾಲಿ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ಆದರೆ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, ಪೋರ್ಟ್);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ಆದರೆ ((pid = fork()) == 0) {
		ಅಕ್ಷರ *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ಆದರೆ (pin[0] != 0) {
			ಆದರೆ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ಆದರೆ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ಆದರೆ (!debug_flag && options.control_ಮಾರ್ಗ != ಖಾಲಿ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ಖಾಲಿ;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		ನಿರ್ಗಮಿಸು(1);
	}
	/* Parent. */
	ಆದರೆ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	ಬಿಡುಗಡೆ(command_string);

	/* Set the connection file descriptors. */
	ಆದರೆ (ssh_packet_ಗಣ_connection(ssh, pout[0], pin[1]) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1; /* ssh_packet_set_connection logs error */

	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_kill_proxy_command(ಶೂನ್ಯ)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ಆದರೆ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_ifaddrs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ifname, ಪೂರ್ಣಾಂಕ af, ಸ್ಥಿರಾಂಕ ರಚನೆ ifaddrs *ifaddrs,
    ರಚನೆ sockaddr_storage *resultp, socklen_t *rlenp)
{
	ರಚನೆ sockaddr_in6 *sa6;
	ರಚನೆ sockaddr_in *sa;
	ರಚನೆ in6_addr *v6addr;
	ಸ್ಥಿರಾಂಕ ರಚನೆ ifaddrs *ifa;
	ಪೂರ್ಣಾಂಕ allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	ಗಾಗಿ (allow_local = 0; allow_local < 2; allow_local++) {
		ಗಾಗಿ (ifa = ifaddrs; ifa != ಖಾಲಿ; ifa = ifa->ifa_ಮುಂದಿನ) {
			ಆದರೆ (ifa->ifa_addr == ಖಾಲಿ || ifa->ifa_name == ಖಾಲಿ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ಮುಂದುವರಿ;
			ಆಯ್ಕೆ (ifa->ifa_addr->sa_family) {
			ಸ್ಥಿತಿ AF_INET:
				sa = (ರಚನೆ sockaddr_in *)ifa->ifa_addr;
				ಆದರೆ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ಮುಂದುವರಿ;
				ಆದರೆ (*rlenp < ಗಾತ್ರ(ರಚನೆ sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ಹಿಂತಿರುಗಿ -1;
				}
				*rlenp = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
				ಸ್ಮರಣೆ_ನಕಲು(resultp, sa, *rlenp);
				ಹಿಂತಿರುಗಿ 0;
			ಸ್ಥಿತಿ AF_INET6:
				sa6 = (ರಚನೆ sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ಆದರೆ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ಮುಂದುವರಿ;
				ಆದರೆ (*rlenp < ಗಾತ್ರ(ರಚನೆ sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ಹಿಂತಿರುಗಿ -1;
				}
				*rlenp = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
				ಸ್ಮರಣೆ_ನಕಲು(resultp, sa6, *rlenp);
				ಹಿಂತಿರುಗಿ 0;
			}
		}
	}
	ಹಿಂತಿರುಗಿ -1;
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Creates a socket for use as the ssh connection.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_create_socket(ರಚನೆ addrinfo *ai)
{
	ಪೂರ್ಣಾಂಕ sock, r;
	ರಚನೆ sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ರಚನೆ addrinfo hints, *res = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IFADDRS_H
	ರಚನೆ ifaddrs *ifaddrs = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ
	ಅಕ್ಷರ ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ಆದರೆ (sock == -1) {
		error("socket: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	(ಶೂನ್ಯ)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ಆದರೆ (options.ip_qos_interactive != ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಗಣ_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ಆದರೆ (options.bind_ವಿಳಾಸ == ಖಾಲಿ && options.bind_interface == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ sock;

	ಆದರೆ (options.bind_ವಿಳಾಸ != ಖಾಲಿ) {
		memset(&hints, 0, ಗಾತ್ರ(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ಆದರೆ ((r = getaddrinfo(options.bind_ವಿಳಾಸ, ಖಾಲಿ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_ವಿಳಾಸ,
			    ssh_gai_strerror(r));
			ಹೋಗು fail;
		}
		ಆದರೆ (res == ಖಾಲಿ) {
			error("getaddrinfo: no addrs");
			ಹೋಗು fail;
		}
		ಸ್ಮರಣೆ_ನಕಲು(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.bind_interface != ಖಾಲಿ) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IFADDRS_H
		ಆದರೆ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			ಹೋಗು fail;
		}
		bindaddrlen = ಗಾತ್ರ(bindaddr);
		ಆದರೆ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			ಹೋಗು fail;
		}
#ಇಲ್ಲದಿದ್ದರೆ
		error("BindInterface not supported on this platform.");
#ಆದರೆ_ಅಂತ್ಯ
	}
	ಆದರೆ ((r = getnameinfo((ರಚನೆ sockaddr *)&bindaddr, bindaddrlen,
	    ntop, ಗಾತ್ರ(ntop), ಖಾಲಿ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		ಹೋಗು fail;
	}
	ಆದರೆ (bind(sock, (ರಚನೆ sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		ಹೋಗು fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	ಹೋಗು ಹೊರಹೋಗು;
fail:
	close(sock);
	sock = -1;
 ಹೊರಹೋಗು:
	ಆದರೆ (res != ಖಾಲಿ)
		freeaddrinfo(res);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IFADDRS_H
	ಆದರೆ (ifaddrs != ಖಾಲಿ)
		freeifaddrs(ifaddrs);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ sock;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_connect_ನೇರ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ addrinfo *aitop,
    ರಚನೆ sockaddr_storage *hostaddr, u_short ಪೋರ್ಟ್, ಪೂರ್ಣಾಂಕ connection_attempts,
    ಪೂರ್ಣಾಂಕ *timeout_ms, ಪೂರ್ಣಾಂಕ want_keepalive)
{
	ಪೂರ್ಣಾಂಕ saved_timeout_ms = *timeout_ms;
	ಪೂರ್ಣಾಂಕ oerrno, sock = -1, attempt;
	ಅಕ್ಷರ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ರಚನೆ addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, ಗಾತ್ರ(ntop));
	memset(strport, 0, ಗಾತ್ರ(strport));

	ಗಾಗಿ (attempt = 0; attempt < connection_attempts; attempt++) {
		ಆದರೆ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		ಗಾಗಿ (ai = aitop; ai; ai = ai->ai_next) {
			ಆದರೆ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, ಗಾತ್ರ(ntop), strport, ಗಾತ್ರ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (options.ವಿಳಾಸ_family != AF_UNSPEC &&
			    ai->ai_family != options.ವಿಳಾಸ_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ಮುಂದುವರಿ;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ಆದರೆ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ಮುಂದುವರಿ;
			}

			*timeout_ms = saved_timeout_ms;
			ಆದರೆ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				ಸ್ಮರಣೆ_ನಕಲು(hostaddr, ai->ai_addr, ai->ai_addrlen);
				ನಿಲ್ಲಿಸು;
			} ಇಲ್ಲದಿದ್ದರೆ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ಆದರೆ (sock != -1)
			ನಿಲ್ಲಿಸು;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ಆದರೆ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ಆದರೆ (want_keepalive)
		ಗಣ_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ಆದರೆ (ssh_packet_ಗಣ_connection(ssh, sock, sock) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1; /* ssh_packet_set_connection logs error */

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_connect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg,
    ರಚನೆ addrinfo *addrs, ರಚನೆ sockaddr_storage *hostaddr, u_short ಪೋರ್ಟ್,
    ಪೂರ್ಣಾಂಕ connection_attempts, ಪೂರ್ಣಾಂಕ *timeout_ms, ಪೂರ್ಣಾಂಕ want_keepalive)
{
	ಪೂರ್ಣಾಂಕ ಒಳ, ಹೊರಹೋಗು;

	ಆದರೆ (options.proxy_command == ಖಾಲಿ) {
		ಹಿಂತಿರುಗಿ ssh_connect_ನೇರ(ssh, host, addrs, hostaddr, ಪೋರ್ಟ್,
		    connection_attempts, timeout_ms, want_keepalive);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(options.proxy_command, "-") == 0) {
		ಆದರೆ ((ಒಳ = dup(STDIN_FILENO)) == -1 ||
		    (ಹೊರಹೋಗು = dup(STDOUT_FILENO)) == -1) {
			ಆದರೆ (ಒಳ >= 0)
				close(ಒಳ);
			error_f("dup() in/out failed");
			ಹಿಂತಿರುಗಿ -1; /* ssh_packet_set_connection logs error */
		}
		ಆದರೆ ((ssh_packet_ಗಣ_connection(ssh, ಒಳ, ಹೊರಹೋಗು)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1; /* ssh_packet_set_connection logs error */
		ಹಿಂತಿರುಗಿ 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.proxy_use_fdpass) {
		ಹಿಂತಿರುಗಿ ssh_proxy_fdpass_connect(ssh, host, host_arg, ಪೋರ್ಟ್,
		    options.proxy_command);
	}
	ಹಿಂತಿರುಗಿ ssh_proxy_connect(ssh, host, host_arg, ಪೋರ್ಟ್,
	    options.proxy_command);
}

/* defaults to 'no' */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
confirm(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fingerprint)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ, *again = "Please type 'yes' or 'no': ";
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	ಅಕ್ಷರ *p, *cp;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (options.batch_ಬಹುಲಕ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (ಸಂದೇಶ = prompt;;ಸಂದೇಶ = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(ಸಂದೇಶ, RP_ECHO);
		ಆದರೆ (p == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ಆದರೆ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(p, "yes") == 0 || (fingerprint != ಖಾಲಿ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		ಬಿಡುಗಡೆ(cp);
		ಆದರೆ (ret != -1)
			ಹಿಂತಿರುಗಿ ret;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sockaddr_is_local(ರಚನೆ sockaddr *hostaddr)
{
	ಆಯ್ಕೆ (hostaddr->sa_family) {
	ಸ್ಥಿತಿ AF_INET:
		ಹಿಂತಿರುಗಿ (ntohl(((ರಚನೆ sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	ಸ್ಥಿತಿ AF_INET6:
		ಹಿಂತಿರುಗಿ IN6_IS_ADDR_LOOPBACK(
		    &(((ರಚನೆ sockaddr_in6 *)hostaddr)->sin6_addr));
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
ಶೂನ್ಯ
get_hostfile_hostname_ipaddr(ಅಕ್ಷರ *hostname, ರಚನೆ sockaddr *hostaddr,
    u_short ಪೋರ್ಟ್, ಅಕ್ಷರ **hostfile_hostname, ಅಕ್ಷರ **hostfile_ipaddr)
{
	ಅಕ್ಷರ ntop[NI_MAXHOST];
	socklen_t addrlen;

	ಆಯ್ಕೆ (hostaddr == ಖಾಲಿ ? -1 : hostaddr->sa_family) {
	ಸ್ಥಿತಿ -1:
		addrlen = 0;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET:
		addrlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
		addrlen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		addrlen = ಗಾತ್ರ(ರಚನೆ sockaddr);
		ನಿಲ್ಲಿಸು;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ಆದರೆ (hostfile_ipaddr != ಖಾಲಿ) {
		ಆದರೆ (options.proxy_command == ಖಾಲಿ) {
			ಆದರೆ (getnameinfo(hostaddr, addrlen,
			    ntop, ಗಾತ್ರ(ntop), ಖಾಲಿ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_ಪೋರ್ಟ್(ntop, ಪೋರ್ಟ್);
		} ಇಲ್ಲದಿದ್ದರೆ {
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
	ಆದರೆ (hostfile_hostname != ಖಾಲಿ) {
		ಆದರೆ (options.host_ಕೀಲಿ_alias != ಖಾಲಿ) {
			*hostfile_hostname = xstrdup(options.host_ಕೀಲಿ_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ಇಲ್ಲದಿದ್ದರೆ {
			*hostfile_hostname = put_host_ಪೋರ್ಟ್(hostname, ಪೋರ್ಟ್);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಮಾರ್ಗ_ಒಳ_hostfiles(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಅಕ್ಷರ **hostfiles, u_int ಅಂಕೆ_hostfiles)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_hostfiles; i++) {
		ಆದರೆ (strcmp(ಮಾರ್ಗ, hostfiles[i]) == 0)
			ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_ctx {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, *ip;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ;
	ಅಕ್ಷರ **ಹೆಸರುಗಳು;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ಸ್ಥಿರ ಅಕ್ಷರ *
try_tilde_unexpand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಅಕ್ಷರ *home, *ret = ಖಾಲಿ;
	ಗಾತ್ರ_t l;

	ಆದರೆ (*ಮಾರ್ಗ != '/')
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ);
	ಆದರೆ ((home = getenv("HOME")) == ಖಾಲಿ || (l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(home)) == 0)
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ);
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಮಾರ್ಗ, home, l) != 0)
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ಆದರೆ (home[l - 1] != '/' && ಮಾರ್ಗ[l] != '/')
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ);
	ಆದರೆ (ಮಾರ್ಗ[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", ಮಾರ್ಗ + l);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
ಪೂರ್ಣಾಂಕ
hostkey_accepted_by_hostkeyalgs(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype = sshkey_ssh_name(ಕೀಲಿ);
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostkeyalgs = options.hostkeyalgorithms;

	ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_UNSPEC)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_RSA &&
	    (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT &&
	    (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ಹಿಂತಿರುಗಿ 1;
	ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ktype, hostkeyalgs, 0) == 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_cb(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_ctx *ctx = (ರಚನೆ ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_ctx *)_ctx;
	ಅಕ್ಷರ *ಮಾರ್ಗ;

	/* we are looking for keys with names that *do not* match */
	ಆದರೆ ((l->ಹೊಂದಿಕೆ & HKF_ಹೊಂದಿಕೆ_HOST) != 0)
		ಹಿಂತಿರುಗಿ 0;
	/* not interested in marker lines */
	ಆದರೆ (l->marker != MRK_NONE)
		ಹಿಂತಿರುಗಿ 0;
	/* we are only interested in exact key matches */
	ಆದರೆ (l->ಕೀಲಿ == ಖಾಲಿ || !sshkey_equal(ctx->ಕೀಲಿ, l->ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ 0;
	ಮಾರ್ಗ = try_tilde_unexpand(l->ಮಾರ್ಗ);
	debug_f("found matching key in %s:%lu", ಮಾರ್ಗ, l->linenum);
	ctx->ಹೆಸರುಗಳು = xrecallocarray(ctx->ಹೆಸರುಗಳು,
	    ctx->nnames, ctx->nnames + 1, ಗಾತ್ರ(*ctx->ಹೆಸರುಗಳು));
	xasprintf(&ctx->ಹೆಸರುಗಳು[ctx->nnames], "%s:%lu: %s", ಮಾರ್ಗ, l->linenum,
	    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(l->hosts, HASH_MAGIC, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_hostfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *which,
    ರಚನೆ ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_ctx *ctx)
{
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ಆದರೆ ((r = hostkeys_foreach(file, hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
		ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ಹಿಂತಿರುಗಿ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಅಕ್ಷರ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ಅಕ್ಷರ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles,
    ಅಕ್ಷರ ***ಹೆಸರುಗಳು, u_int *nnames)
{
	ರಚನೆ ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_ctx ctx = {ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, 0};
	u_int i;

	*ಹೆಸರುಗಳು = ಖಾಲಿ;
	*nnames = 0;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || sshkey_is_cert(ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.ಕೀಲಿ = ಕೀಲಿ;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++) {
		ಆದರೆ (hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			ಹೋಗು fail;
	}
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++) {
		ಆದರೆ (hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			ಹೋಗು fail;
	}
	/* success */
	*ಹೆಸರುಗಳು = ctx.ಹೆಸರುಗಳು;
	*nnames = ctx.nnames;
	ctx.ಹೆಸರುಗಳು = ಖಾಲಿ;
	ctx.nnames = 0;
	ಹಿಂತಿರುಗಿ;
 fail:
	ಗಾಗಿ (i = 0; i < ctx.nnames; i++)
		ಬಿಡುಗಡೆ(ctx.ಹೆಸರುಗಳು[i]);
	ಬಿಡುಗಡೆ(ctx.ಹೆಸರುಗಳು);
}

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_OTHER_ಹೆಸರುಗಳು	8 /* Maximum number of names to list */
ಸ್ಥಿರ ಅಕ್ಷರ *
other_hostkeys_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಅಕ್ಷರ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ಅಕ್ಷರ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ, **othernames = ಖಾಲಿ;
	u_int i, n, ಅಂಕೆ_othernames = 0;

	hostkeys_ಕಂಡುಹಿಡಿ_by_ಕೀಲಿ(host, ip, ಕೀಲಿ,
	    user_hostfiles, ಅಂಕೆ_user_hostfiles,
	    system_hostfiles, ಅಂಕೆ_system_hostfiles,
	    &othernames, &ಅಂಕೆ_othernames);
	ಆದರೆ (ಅಂಕೆ_othernames == 0)
		ಹಿಂತಿರುಗಿ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = ಅಂಕೆ_othernames;
	ಆದರೆ (n > MAX_OTHER_ಹೆಸರುಗಳು)
		n = MAX_OTHER_ಹೆಸರುಗಳು;
	ಗಾಗಿ (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ಆದರೆ (n < ಅಂಕೆ_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    ಅಂಕೆ_othernames - n);
	}
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_othernames; i++)
		ಬಿಡುಗಡೆ(othernames[i]);
	ಬಿಡುಗಡೆ(othernames);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
ತುಂಬು_hostkeys_command(ರಚನೆ hostkeys *hostkeys, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command_template,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *invocation, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *host_ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostfile_hostname)
{
	ಪೂರ್ಣಾಂಕ r, i, ac = 0;
	ಅಕ್ಷರ *ಕೀಲಿ_fp = ಖಾಲಿ, *keytext = ಖಾಲಿ, *tmp;
	ಅಕ್ಷರ *command = ಖಾಲಿ, *ಟ್ಯಾಗ್ = ಖಾಲಿ, **av = ಖಾಲಿ;
	FILE *f = ಖಾಲಿ;
	pid_t pid;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);

	xasprintf(&ಟ್ಯಾಗ್, "KnownHostsCommand-%s", invocation);

	ಆದರೆ (host_ಕೀಲಿ != ಖಾಲಿ) {
		ಆದರೆ ((ಕೀಲಿ_fp = sshkey_fingerprint(host_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint failed");
		ಆದರೆ ((r = sshkey_ಗಮ್ಯ_base64(host_ಕೀಲಿ, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ಆದರೆ (argv_ವಿಭಜಿಸು(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", ಟ್ಯಾಗ್,
		    command_template);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ac == 0) {
		error("%s \"%s\" yielded no arguments", ಟ್ಯಾಗ್,
		    command_template);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_ಕೀಲಿ == ಖಾಲಿ ? "NONE" : sshkey_ssh_name(host_ಕೀಲಿ),
		    "f", ಕೀಲಿ_fp == ಖಾಲಿ ? "NONE" : ಕೀಲಿ_fp,
		    "K", keytext == ಖಾಲಿ ? "NONE" : keytext,
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
		ಆದರೆ (tmp == ಖಾಲಿ)
			fatal_f("percent_expand failed");
		ಬಿಡುಗಡೆ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ಆದರೆ ((pid = subprocess(ಟ್ಯಾಗ್, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_ಮಾರ್ಗ|
	    SSH_SUBPROCESS_PRESERVE_ENV, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ತುಂಬು_hostkeys_file(hostkeys, hostfile_hostname, ಟ್ಯಾಗ್, f, 1);

	ಆದರೆ (exited_cleanly(pid, ಟ್ಯಾಗ್, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 ಹೊರಹೋಗು:
	ಆದರೆ (f != ಖಾಲಿ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ಗಾಗಿ (i = 0; i < ac; i++)
		ಬಿಡುಗಡೆ(av[i]);
	ಬಿಡುಗಡೆ(av);
	ಬಿಡುಗಡೆ(ಟ್ಯಾಗ್);
	ಬಿಡುಗಡೆ(command);
	ಬಿಡುಗಡೆ(ಕೀಲಿ_fp);
	ಬಿಡುಗಡೆ(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು RDRW	0
#ವ್ಯಾಖ್ಯಾನಿಸು RDONLY	1
#ವ್ಯಾಖ್ಯಾನಿಸು ROQUIET	2
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_host_ಕೀಲಿ(ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo,
    ರಚನೆ sockaddr *hostaddr, u_short ಪೋರ್ಟ್,
    ರಚನೆ sshkey *host_ಕೀಲಿ, ಪೂರ್ಣಾಂಕ readonly, ಪೂರ್ಣಾಂಕ clobber_ಪೋರ್ಟ್,
    ಅಕ್ಷರ **user_hostfiles, u_int ಅಂಕೆ_user_hostfiles,
    ಅಕ್ಷರ **system_hostfiles, u_int ಅಂಕೆ_system_hostfiles,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostfile_command)
{
	Host_ಸ್ಥಿತಿ host_ಸ್ಥಿತಿ = -1, ip_ಸ್ಥಿತಿ = -1;
	ರಚನೆ sshkey *raw_ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *ip = ಖಾಲಿ, *host = ಖಾಲಿ;
	ಅಕ್ಷರ hostline[1000], *hostp, *fp, *ra;
	ಅಕ್ಷರ ಸಂದೇಶ[1024];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *type, *fail_reason = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು *host_ಸಿಕ್ಕಿತು = ಖಾಲಿ, *ip_ಸಿಕ್ಕಿತು = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ len, cancelled_forwarding = 0, confirmed;
	ಪೂರ್ಣಾಂಕ local = sockaddr_is_local(hostaddr);
	ಪೂರ್ಣಾಂಕ r, want_cert = sshkey_is_cert(host_ಕೀಲಿ), host_ip_ವ್ಯತ್ಯಾಸ = 0;
	ಪೂರ್ಣಾಂಕ hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ರಚನೆ hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ಆದರೆ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_ಕೀಲಿ_alias == ಖಾಲಿ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ಆದರೆ (strcspn(hostname, "@?*#[]|'\'\"\\") != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_ಪೋರ್ಟ್ ? 0 : ಪೋರ್ಟ್, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	ಆದರೆ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ಖಾಲಿ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++)
		ತುಂಬು_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++)
		ತುಂಬು_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ಆದರೆ (hostfile_command != ಖಾಲಿ && !clobber_ಪೋರ್ಟ್) {
		ತುಂಬು_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_ಕೀಲಿ, host);
	}

	ip_hostkeys = ಖಾಲಿ;
	ಆದರೆ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_user_hostfiles; i++)
			ತುಂಬು_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_system_hostfiles; i++)
			ತುಂಬು_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ಆದರೆ (hostfile_command != ಖಾಲಿ && !clobber_ಪೋರ್ಟ್) {
			ತುಂಬು_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_ಕೀಲಿ, ip);
		}
	}

 retry:
	ಆದರೆ (!hostkey_accepted_by_hostkeyalgs(host_ಕೀಲಿ)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_ಕೀಲಿ));
		ಹೋಗು fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_ಕೀಲಿ);
	type = sshkey_type(host_ಕೀಲಿ);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_ಸ್ಥಿತಿ = check_ಕೀಲಿ_ಒಳ_hostkeys(host_hostkeys, host_ಕೀಲಿ,
	    &host_ಸಿಕ್ಕಿತು);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ಆದರೆ (!readonly && (ಅಂಕೆ_user_hostfiles == 0 ||
	    (host_ಸಿಕ್ಕಿತು != ಖಾಲಿ && host_ಸಿಕ್ಕಿತು->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ಆದರೆ (!want_cert && ip_hostkeys != ಖಾಲಿ) {
		ip_ಸ್ಥಿತಿ = check_ಕೀಲಿ_ಒಳ_hostkeys(ip_hostkeys, host_ಕೀಲಿ,
		    &ip_ಸಿಕ್ಕಿತು);
		ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_ಬದಲಾಯಿತು &&
		    (ip_ಸ್ಥಿತಿ != HOST_ಬದಲಾಯಿತು ||
		    (ip_ಸಿಕ್ಕಿತು != ಖಾಲಿ &&
		    !sshkey_equal(ip_ಸಿಕ್ಕಿತು->ಕೀಲಿ, host_ಸಿಕ್ಕಿತು->ಕೀಲಿ))))
			host_ip_ವ್ಯತ್ಯಾಸ = 1;
	} ಇಲ್ಲದಿದ್ದರೆ
		ip_ಸ್ಥಿತಿ = host_ಸ್ಥಿತಿ;

	ಆಯ್ಕೆ (host_ಸ್ಥಿತಿ) {
	ಸ್ಥಿತಿ HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_ಸಿಕ್ಕಿತು->file, host_ಸಿಕ್ಕಿತು->ಸಾಲು);
		ಆದರೆ (want_cert) {
			ಆದರೆ (sshkey_cert_check_host(host_ಕೀಲಿ,
			    options.host_ಕೀಲಿ_alias == ಖಾಲಿ ?
			    hostname : options.host_ಕೀಲಿ_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				ಹೋಗು fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ಆದರೆ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ಆದರೆ (options.update_hostkeys != 0 &&
		    (ಮಾರ್ಗ_ಒಳ_hostfiles(host_ಸಿಕ್ಕಿತು->file,
		    system_hostfiles, ಅಂಕೆ_system_hostfiles) ||
		    (ip_ಸ್ಥಿತಿ == HOST_OK && ip_ಸಿಕ್ಕಿತು != ಖಾಲಿ &&
		    ಮಾರ್ಗ_ಒಳ_hostfiles(ip_ಸಿಕ್ಕಿತು->file,
		    system_hostfiles, ಅಂಕೆ_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ಆದರೆ (options.update_hostkeys != 0 && host_ಸಿಕ್ಕಿತು->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ಆದರೆ (options.check_host_ip && ip_ಸ್ಥಿತಿ == HOST_NEW) {
			ಆದರೆ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(user_hostfiles[0], ip,
			    host_ಕೀಲಿ, options.hash_ತಿಳಿದ_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ಇಲ್ಲದಿದ್ದರೆ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.visual_host_ಕೀಲಿ) {
			fp = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			ಬಿಡುಗಡೆ(ra);
			ಬಿಡುಗಡೆ(fp);
		}
		hostkey_trusted = 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ HOST_NEW:
		ಆದರೆ (options.host_ಕೀಲಿ_alias == ಖಾಲಿ && ಪೋರ್ಟ್ != 0 &&
		    ಪೋರ್ಟ್ != SSH_DEFAULT_ಪೋರ್ಟ್ && !clobber_ಪೋರ್ಟ್) {
			debug("checking without port identifier");
			ಆದರೆ (check_host_ಕೀಲಿ(hostname, cinfo, hostaddr, 0,
			    host_ಕೀಲಿ, ROQUIET, 1,
			    user_hostfiles, ಅಂಕೆ_user_hostfiles,
			    system_hostfiles, ಅಂಕೆ_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (readonly || want_cert)
			ಹೋಗು fail;
		/* The host is new. */
		ಆದರೆ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			ಅಕ್ಷರ *msg1 = ಖಾಲಿ, *msg2 = ಖಾಲಿ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ಆದರೆ (show_other_ಕೀಲಿಗಳು(host_hostkeys, host_ಕೀಲಿ)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ಇಲ್ಲದಿದ್ದರೆ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ಕೀಲಿ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ಆದರೆ (options.visual_host_ಕೀಲಿ)
				xextendf(&msg1, "\n", "%s", ra);
			ಆದರೆ (options.verify_host_ಕೀಲಿ_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_ಕೀಲಿ_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ಆದರೆ ((msg2 = other_hostkeys_ಸಂದೇಶ(host, ip, host_ಕೀಲಿ,
			    user_hostfiles, ಅಂಕೆ_user_hostfiles,
			    system_hostfiles, ಅಂಕೆ_system_hostfiles)) != ಖಾಲಿ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			ಬಿಡುಗಡೆ(ra);
			ಬಿಡುಗಡೆ(fp);
			ಬಿಡುಗಡೆ(msg1);
			ಬಿಡುಗಡೆ(msg2);
			ಆದರೆ (!confirmed)
				ಹೋಗು fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ಆದರೆ (options.check_host_ip && ip_ಸ್ಥಿತಿ == HOST_NEW) {
			snprintf(hostline, ಗಾತ್ರ(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ಆದರೆ (options.hash_ತಿಳಿದ_hosts) {
				/* Add hash of host and IP separately */
				r = ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(user_hostfiles[0],
				    host, host_ಕೀಲಿ, options.hash_ತಿಳಿದ_hosts) &&
				    ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(user_hostfiles[0], ip,
				    host_ಕೀಲಿ, options.hash_ತಿಳಿದ_hosts);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Add unhashed "host,ip" */
				r = ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(user_hostfiles[0],
				    hostline, host_ಕೀಲಿ,
				    options.hash_ತಿಳಿದ_hosts);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			r = ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(user_hostfiles[0], host,
			    host_ಕೀಲಿ, options.hash_ತಿಳಿದ_hosts);
			hostp = host;
		}

		ಆದರೆ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ಇಲ್ಲದಿದ್ದರೆ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ HOST_REVOKED:
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
		ಆದರೆ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			ಹೋಗು fail;
		}
		ಹೋಗು continue_unsafe;

	ಸ್ಥಿತಿ HOST_ಬದಲಾಯಿತು:
		ಆದರೆ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_ಸಿಕ್ಕಿತು->file, host_ಸಿಕ್ಕಿತು->ಸಾಲು);
			ಹೋಗು fail;
		}
		ಆದರೆ (readonly == ROQUIET)
			ಹೋಗು fail;
		ಆದರೆ (options.check_host_ip && host_ip_ವ್ಯತ್ಯಾಸ) {
			ಅಕ್ಷರ *ಕೀಲಿ_ಸಂದೇಶ;
			ಆದರೆ (ip_ಸ್ಥಿತಿ == HOST_NEW)
				ಕೀಲಿ_ಸಂದೇಶ = "is unknown";
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ip_ಸ್ಥಿತಿ == HOST_OK)
				ಕೀಲಿ_ಸಂದೇಶ = "is unchanged";
			ಇಲ್ಲದಿದ್ದರೆ
				ಕೀಲಿ_ಸಂದೇಶ = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", ಕೀಲಿ_ಸಂದೇಶ);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ಆದರೆ (ip_ಸ್ಥಿತಿ != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_ಸಿಕ್ಕಿತು->file, ip_ಸಿಕ್ಕಿತು->ಸಾಲು);
		}
		/* The host key has changed. */
		warn_ಬದಲಾಯಿತು_ಕೀಲಿ(host_ಕೀಲಿ);
		ಆದರೆ (ಅಂಕೆ_user_hostfiles > 0 || ಅಂಕೆ_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", ಅಂಕೆ_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_ಸಿಕ್ಕಿತು->ಕೀಲಿ),
		    host_ಸಿಕ್ಕಿತು->file, host_ಸಿಕ್ಕಿತು->ಸಾಲು);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ಆದರೆ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			ಹೋಗು fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ಆದರೆ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.ಅಂಕೆ_local_forwards > 0 ||
		    options.ಅಂಕೆ_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.ಅಂಕೆ_local_forwards =
			    options.ಅಂಕೆ_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ಆದರೆ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ಆದರೆ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ HOST_ಸಿಕ್ಕಿತು:
		fatal("internal error");
		ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (options.check_host_ip && host_ಸ್ಥಿತಿ != HOST_ಬದಲಾಯಿತು &&
	    ip_ಸ್ಥಿತಿ == HOST_ಬದಲಾಯಿತು) {
		snprintf(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_ಸಿಕ್ಕಿತು->file, ip_ಸಿಕ್ಕಿತು->ಸಾಲು);
		ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_OK) {
			len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ);
			snprintf(ಸಂದೇಶ + len, ಗಾತ್ರ(ಸಂದೇಶ) - len,
			    "\nMatching host key in %s:%lu",
			    host_ಸಿಕ್ಕಿತು->file, host_ಸಿಕ್ಕಿತು->ಸಾಲು);
		}
		ಆದರೆ (options.strict_host_ಕೀಲಿ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(ಸಂದೇಶ, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", ಗಾತ್ರ(ಸಂದೇಶ));
			ಆದರೆ (!confirm(ಸಂದೇಶ, ಖಾಲಿ))
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.strict_host_ಕೀಲಿ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", ಸಂದೇಶ);
			error("Exiting, you have requested strict checking.");
			ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ {
			logit("%s", ಸಂದೇಶ);
		}
	}

	ಆದರೆ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(ip);
	ಬಿಡುಗಡೆ(host);
	ಆದರೆ (host_hostkeys != ಖಾಲಿ)
		free_hostkeys(host_hostkeys);
	ಆದರೆ (ip_hostkeys != ಖಾಲಿ)
		free_hostkeys(ip_hostkeys);
	ಹಿಂತಿರುಗಿ 0;

fail:
	ಆದರೆ (want_cert && host_ಸ್ಥಿತಿ != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(host_ಕೀಲಿ, &raw_ಕೀಲಿ)) != 0)
			fatal_fr(r, "decode key");
		ಆದರೆ ((r = sshkey_drop_cert(raw_ಕೀಲಿ)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_ಕೀಲಿ = raw_ಕೀಲಿ;
		ಹೋಗು retry;
	}
	sshkey_free(raw_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(ip);
	ಬಿಡುಗಡೆ(host);
	ಆದರೆ (host_hostkeys != ಖಾಲಿ)
		free_hostkeys(host_hostkeys);
	ಆದರೆ (ip_hostkeys != ಖಾಲಿ)
		free_hostkeys(ip_hostkeys);
	ಹಿಂತಿರುಗಿ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
ಪೂರ್ಣಾಂಕ
verify_host_ಕೀಲಿ(ಅಕ್ಷರ *host, ರಚನೆ sockaddr *hostaddr, ರಚನೆ sshkey *host_ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ r = -1, flags = 0;
	ಅಕ್ಷರ valid[64], *fp = ಖಾಲಿ, *cafp = ಖಾಲಿ;
	ರಚನೆ sshkey *plain = ಖಾಲಿ;

	ಆದರೆ ((fp = sshkey_fingerprint(host_ಕೀಲಿ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (sshkey_is_cert(host_ಕೀಲಿ)) {
		ಆದರೆ ((cafp = sshkey_fingerprint(host_ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		sshkey_format_cert_validity(host_ಕೀಲಿ->cert,
		    valid, ಗಾತ್ರ(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_ಕೀಲಿ), fp,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)host_ಕೀಲಿ->cert->serial,
		    host_ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    sshkey_ssh_name(host_ಕೀಲಿ->cert->signature_ಕೀಲಿ), cafp,
		    valid);
		ಗಾಗಿ (i = 0; i < host_ಕೀಲಿ->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_ಕೀಲಿ->cert->principals[i]);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_ಕೀಲಿ), fp);
	}

	ಆದರೆ (sshkey_equal(ಹಿಂದಿನ_host_ಕೀಲಿ, host_ಕೀಲಿ)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_ಕೀಲಿ), fp);
		r = 0;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Check in RevokedHostKeys files if specified */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು; i++) {
		r = sshkey_check_revoked(host_ಕೀಲಿ,
		    options.revoked_host_ಕೀಲಿಗಳು[i]);
		ಆಯ್ಕೆ (r) {
		ಸ್ಥಿತಿ 0:
			ನಿಲ್ಲಿಸು; /* not revoked */
		ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_ಕೀಲಿ), fp,
			    options.revoked_host_ಕೀಲಿಗಳು[i]);
			r = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_ಕೀಲಿ),
			    fp, options.revoked_host_ಕೀಲಿಗಳು[i]);
			r = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಆದರೆ (options.verify_host_ಕೀಲಿ_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(host_ಕೀಲಿ, &plain)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ಆದರೆ (verify_host_ಕೀಲಿ_dns(host, hostaddr, plain, &flags) == 0) {
			ಆದರೆ (flags & DNS_VERIFY_ಸಿಕ್ಕಿತು) {
				ಆದರೆ (options.verify_host_ಕೀಲಿ_dns == 1 &&
				    flags & DNS_VERIFY_ಹೊಂದಿಕೆ &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					ಹೋಗು ಹೊರಹೋಗು;
				}
				ಆದರೆ (flags & DNS_VERIFY_ಹೊಂದಿಕೆ) {
					matching_host_ಕೀಲಿ_dns = 1;
				} ಇಲ್ಲದಿದ್ದರೆ {
					warn_ಬದಲಾಯಿತು_ಕೀಲಿ(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_ಕೀಲಿ(host, cinfo, hostaddr, options.ಪೋರ್ಟ್, host_ಕೀಲಿ,
	    RDRW, 0, options.user_hostfiles, options.ಅಂಕೆ_user_hostfiles,
	    options.system_hostfiles, options.ಅಂಕೆ_system_hostfiles,
	    options.ತಿಳಿದ_hosts_command);

ಹೊರಹೋಗು:
	sshkey_free(plain);
	ಬಿಡುಗಡೆ(fp);
	ಬಿಡುಗಡೆ(cafp);
	ಆದರೆ (r == 0 && host_ಕೀಲಿ != ಖಾಲಿ) {
		sshkey_free(ಹಿಂದಿನ_host_ಕೀಲಿ);
		r = sshkey_from_ಖಾಸಗಿ(host_ಕೀಲಿ, &ಹಿಂದಿನ_host_ಕೀಲಿ);
	}

	ಹಿಂತಿರುಗಿ r;
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
ssh_login(ರಚನೆ ssh *ssh, Sensitive *sensitive, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *orighost,
    ರಚನೆ sockaddr_storage *hostaddr, u_short ಪೋರ್ಟ್, ರಚನೆ passwd *pw,
    ಪೂರ್ಣಾಂಕ timeout_ms, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಅಕ್ಷರ *host;
	ಅಕ್ಷರ *server_user, *local_user;
	ಪೂರ್ಣಾಂಕ r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ಆದರೆ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.ಆವೃತ್ತಿ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ಆದರೆ ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_ಗಣ_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, ಪೋರ್ಟ್, server_user);
	ssh_kex2(ssh, host, hostaddr, ಪೋರ್ಟ್, cinfo);
	kex_ಗಣ_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_ಗಣ);
	ಆದರೆ (!options.kex_algorithms_ಗಣ && ssh->kex != ಖಾಲಿ &&
	    ssh->kex->name != ಖಾಲಿ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	ಬಿಡುಗಡೆ(local_user);
	ಬಿಡುಗಡೆ(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
show_other_ಕೀಲಿಗಳು(ರಚನೆ hostkeys *hostkeys, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ type[] = {
		ಕೀಲಿ_RSA,
		ಕೀಲಿ_ECDSA,
		ಕೀಲಿ_ED25519,
		ಕೀಲಿ_MLDSA44_ED25519,
		-1
	};
	ಪೂರ್ಣಾಂಕ i, ret = 0;
	ಅಕ್ಷರ *fp, *ra;
	ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು *ಸಿಕ್ಕಿತು;

	ಗಾಗಿ (i = 0; type[i] != -1; i++) {
		ಆದರೆ (type[i] == ಕೀಲಿ->type)
			ಮುಂದುವರಿ;
		ಆದರೆ (!lookup_ಕೀಲಿ_ಒಳ_hostkeys_by_type(hostkeys, type[i],
		    -1, &ಸಿಕ್ಕಿತು))
			ಮುಂದುವರಿ;
		fp = sshkey_fingerprint(ಸಿಕ್ಕಿತು->ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ಸಿಕ್ಕಿತು->ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(ಸಿಕ್ಕಿತು->ಕೀಲಿ),
		    ಸಿಕ್ಕಿತು->host, ಸಿಕ್ಕಿತು->file, ಸಿಕ್ಕಿತು->ಸಾಲು,
		    sshkey_type(ಸಿಕ್ಕಿತು->ಕೀಲಿ), fp);
		ಆದರೆ (options.visual_host_ಕೀಲಿ)
			logit("%s", ra);
		ಬಿಡುಗಡೆ(ra);
		ಬಿಡುಗಡೆ(fp);
		ret = 1;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
warn_ಬದಲಾಯಿತು_ಕೀಲಿ(ರಚನೆ sshkey *host_ಕೀಲಿ)
{
	ಅಕ್ಷರ *fp;

	fp = sshkey_fingerprint(host_ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ಆದರೆ (fp == ಖಾಲಿ)
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

	ಬಿಡುಗಡೆ(fp);
}

/*
 * Execute a local command
 */
ಪೂರ್ಣಾಂಕ
ssh_local_cmd(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಾದಗಳು)
{
	ಅಕ್ಷರ *shell;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;
	ಶೂನ್ಯ (*osighand)(ಪೂರ್ಣಾಂಕ);

	ಆದರೆ (!options.permit_local_command ||
	    ವಾದಗಳು == ಖಾಲಿ || !*ವಾದಗಳು)
		ಹಿಂತಿರುಗಿ (1);

	ಆದರೆ ((shell = getenv("SHELL")) == ಖಾಲಿ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ಆದರೆ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, ವಾದಗಳು);
		execl(shell, shell, "-c", ವಾದಗಳು, (ಅಕ್ಷರ *)ಖಾಲಿ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, ವಾದಗಳು, strerror(errno));
		_exit(1);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1)
		ಆದರೆ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2))
		ಹಿಂತಿರುಗಿ (1);

	ಹಿಂತಿರುಗಿ (WEXITSTATUS(ಸ್ಥಿತಿ_2));
}

ಶೂನ್ಯ
maybe_ಕೂಡಿಸು_ಕೀಲಿ_ಗಮ್ಯ_agent(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *authfile, ರಚನೆ sshkey *ಖಾಸಗಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase)
{
	ಪೂರ್ಣಾಂಕ auth_sock = -1, r;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *skprovider = ಖಾಲಿ;

	ಆದರೆ (options.ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == 0)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (options.ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (sshkey_is_sk(ಖಾಸಗಿ))
		skprovider = options.sk_provider;
	ಆದರೆ ((r = ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(auth_sock, ಖಾಸಗಿ,
	    comment == ಖಾಲಿ ? authfile : comment,
	    options.ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan,
	    (options.ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == 3), skprovider, ಖಾಲಿ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ಇಲ್ಲದಿದ್ದರೆ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
