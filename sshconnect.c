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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <net/if.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ifaddrs.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshconnect.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dns.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_fdpass.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"

ਬਣਤਰ sshkey *ਪਿਛਲਾ_host_ਕੁੰਜੀ = ਨਿਰਾ;

ਸਥਿਰ ਪੂਰਨ matching_host_ਕੁੰਜੀ_dns = 0;

ਸਥਿਰ pid_t proxy_command_pid = 0;

/* import */
ਬਾਹਰੀ ਪੂਰਨ debug_flag;
ਬਾਹਰੀ Options options;
ਬਾਹਰੀ ਅੱਖਰ *__progname;

ਸਥਿਰ ਪੂਰਨ show_other_ਕੁੰਜੀਆਂ(ਬਣਤਰ hostkeys *, ਬਣਤਰ sshkey *);
ਸਥਿਰ ਖਾਲੀ warn_ਬਦਲਿਆ_ਕੁੰਜੀ(ਬਣਤਰ sshkey *);

ਖਾਲੀ
ssh_conn_info_free(ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਜੇ (cinfo == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(cinfo->conn_hash_hex);
	ਮੁਕਤ(cinfo->shorthost);
	ਮੁਕਤ(cinfo->uidstr);
	ਮੁਕਤ(cinfo->keyalias);
	ਮੁਕਤ(cinfo->thishost);
	ਮੁਕਤ(cinfo->host_arg);
	ਮੁਕਤ(cinfo->portstr);
	ਮੁਕਤ(cinfo->remhost);
	ਮੁਕਤ(cinfo->remuser);
	ਮੁਕਤ(cinfo->homedir);
	ਮੁਕਤ(cinfo->locuser);
	ਮੁਕਤ(cinfo->jmphost);
	freezero(cinfo, ਆਕਾਰ(*cinfo));
}

ਬਣਤਰ ssh_conn_info *
ssh_conn_info_dup(ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਬਣਤਰ ssh_conn_info *ret;

	ਜੇ (cinfo == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ret = xcalloc(1, ਆਕਾਰ(*ret));
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
	ਵਾਪਸ ret;
}

/* Expand a proxy command */
ਸਥਿਰ ਅੱਖਰ *
expand_proxy_command(ਅਚਲ ਅੱਖਰ *proxy_command, ਅਚਲ ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *host_arg, ਪੂਰਨ ਪੋਰਟ)
{
	ਅੱਖਰ *tmp, *ret, strport[NI_MAXSERV];
	ਅਚਲ ਅੱਖਰ *keyalias = options.host_ਕੁੰਜੀ_alias ?
	    options.host_ਕੁੰਜੀ_alias : host_arg;

	snprintf(strport, ਆਕਾਰ strport, "%d", ਪੋਰਟ);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (ਅੱਖਰ *)ਨਿਰਾ);
	ਮੁਕਤ(tmp);
	ਵਾਪਸ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ਸਥਿਰ ਪੂਰਨ
ssh_proxy_fdpass_connect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *host_arg, u_short ਪੋਰਟ, ਅਚਲ ਅੱਖਰ *proxy_command)
{
	ਅੱਖਰ *command_string;
	ਪੂਰਨ sp[2], sock;
	pid_t pid;
	ਅੱਖਰ *shell;

	ਜੇ ((shell = getenv("SHELL")) == ਨਿਰਾ)
		shell = _PATH_BSHELL;

	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, ਪੋਰਟ);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ਜੇ ((pid = fork()) == 0) {
		ਅੱਖਰ *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ਜੇ (sp[0] != 0) {
			ਜੇ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ਜੇ (sp[0] != 1) {
			ਜੇ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ਜੇ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ਜੇ (!debug_flag && options.control_ਰਸਤਾ != ਨਿਰਾ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ਨਿਰਾ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/* Parent. */
	ਜੇ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	ਮੁਕਤ(command_string);

	ਜੇ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ਜਦੋਂ (waitpid(pid, ਨਿਰਾ, 0) == -1)
		ਜੇ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ਜੇ (ssh_packet_ਸੈੱਟ_connection(ssh, sock, sock) == ਨਿਰਾ)
		ਵਾਪਸ -1; /* ssh_packet_set_connection logs error */

	ਵਾਪਸ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ਸਥਿਰ ਪੂਰਨ
ssh_proxy_connect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *host_arg,
    u_short ਪੋਰਟ, ਅਚਲ ਅੱਖਰ *proxy_command)
{
	ਅੱਖਰ *command_string;
	ਪੂਰਨ pin[2], pout[2];
	pid_t pid;
	ਅੱਖਰ *shell;

	ਜੇ ((shell = getenv("SHELL")) == ਨਿਰਾ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ਜੇ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, ਪੋਰਟ);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ਜੇ ((pid = fork()) == 0) {
		ਅੱਖਰ *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ਜੇ (pin[0] != 0) {
			ਜੇ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ਜੇ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ਜੇ (!debug_flag && options.control_ਰਸਤਾ != ਨਿਰਾ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ਨਿਰਾ;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/* Parent. */
	ਜੇ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ਨਹੀਂਤਾਂ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	ਮੁਕਤ(command_string);

	/* Set the connection file descriptors. */
	ਜੇ (ssh_packet_ਸੈੱਟ_connection(ssh, pout[0], pin[1]) == ਨਿਰਾ)
		ਵਾਪਸ -1; /* ssh_packet_set_connection logs error */

	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_kill_proxy_command(ਖਾਲੀ)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ਜੇ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ਸਥਿਰ ਪੂਰਨ
check_ifaddrs(ਅਚਲ ਅੱਖਰ *ifname, ਪੂਰਨ af, ਅਚਲ ਬਣਤਰ ifaddrs *ifaddrs,
    ਬਣਤਰ sockaddr_storage *resultp, socklen_t *rlenp)
{
	ਬਣਤਰ sockaddr_in6 *sa6;
	ਬਣਤਰ sockaddr_in *sa;
	ਬਣਤਰ in6_addr *v6addr;
	ਅਚਲ ਬਣਤਰ ifaddrs *ifa;
	ਪੂਰਨ allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	ਲਈ (allow_local = 0; allow_local < 2; allow_local++) {
		ਲਈ (ifa = ifaddrs; ifa != ਨਿਰਾ; ifa = ifa->ifa_ਅਗਲਾ) {
			ਜੇ (ifa->ifa_addr == ਨਿਰਾ || ifa->ifa_name == ਨਿਰਾ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ਜਾਰੀ;
			ਚੋਣ (ifa->ifa_addr->sa_family) {
			ਹਾਲਤ AF_INET:
				sa = (ਬਣਤਰ sockaddr_in *)ifa->ifa_addr;
				ਜੇ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ਜਾਰੀ;
				ਜੇ (*rlenp < ਆਕਾਰ(ਬਣਤਰ sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ਵਾਪਸ -1;
				}
				*rlenp = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(resultp, sa, *rlenp);
				ਵਾਪਸ 0;
			ਹਾਲਤ AF_INET6:
				sa6 = (ਬਣਤਰ sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ਜੇ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ਜਾਰੀ;
				ਜੇ (*rlenp < ਆਕਾਰ(ਬਣਤਰ sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ਵਾਪਸ -1;
				}
				*rlenp = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(resultp, sa6, *rlenp);
				ਵਾਪਸ 0;
			}
		}
	}
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ

/*
 * Creates a socket for use as the ssh connection.
 */
ਸਥਿਰ ਪੂਰਨ
ssh_create_socket(ਬਣਤਰ addrinfo *ai)
{
	ਪੂਰਨ sock, r;
	ਬਣਤਰ sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ਬਣਤਰ addrinfo hints, *res = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IFADDRS_H
	ਬਣਤਰ ifaddrs *ifaddrs = ਨਿਰਾ;
#ਜੇ_ਅੰਤ
	ਅੱਖਰ ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ਜੇ (sock == -1) {
		error("socket: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	(ਖਾਲੀ)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ਜੇ (options.ip_qos_interactive != ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਸੈੱਟ_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ਜੇ (options.bind_ਪਤਾ == ਨਿਰਾ && options.bind_interface == ਨਿਰਾ)
		ਵਾਪਸ sock;

	ਜੇ (options.bind_ਪਤਾ != ਨਿਰਾ) {
		memset(&hints, 0, ਆਕਾਰ(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ਜੇ ((r = getaddrinfo(options.bind_ਪਤਾ, ਨਿਰਾ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_ਪਤਾ,
			    ssh_gai_strerror(r));
			ਜਾਓ fail;
		}
		ਜੇ (res == ਨਿਰਾ) {
			error("getaddrinfo: no addrs");
			ਜਾਓ fail;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ਨਹੀਂਤਾਂ ਜੇ (options.bind_interface != ਨਿਰਾ) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IFADDRS_H
		ਜੇ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			ਜਾਓ fail;
		}
		bindaddrlen = ਆਕਾਰ(bindaddr);
		ਜੇ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			ਜਾਓ fail;
		}
#ਨਹੀਂਤਾਂ
		error("BindInterface not supported on this platform.");
#ਜੇ_ਅੰਤ
	}
	ਜੇ ((r = getnameinfo((ਬਣਤਰ sockaddr *)&bindaddr, bindaddrlen,
	    ntop, ਆਕਾਰ(ntop), ਨਿਰਾ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		ਜਾਓ fail;
	}
	ਜੇ (bind(sock, (ਬਣਤਰ sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		ਜਾਓ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	ਜਾਓ ਬਾਹਰਲਾ;
fail:
	close(sock);
	sock = -1;
 ਬਾਹਰਲਾ:
	ਜੇ (res != ਨਿਰਾ)
		freeaddrinfo(res);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IFADDRS_H
	ਜੇ (ifaddrs != ਨਿਰਾ)
		freeifaddrs(ifaddrs);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ sock;
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
ਸਥਿਰ ਪੂਰਨ
ssh_connect_ਸਿੱਧਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ addrinfo *aitop,
    ਬਣਤਰ sockaddr_storage *hostaddr, u_short ਪੋਰਟ, ਪੂਰਨ connection_attempts,
    ਪੂਰਨ *timeout_ms, ਪੂਰਨ want_keepalive)
{
	ਪੂਰਨ saved_timeout_ms = *timeout_ms;
	ਪੂਰਨ oerrno, sock = -1, attempt;
	ਅੱਖਰ ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ਬਣਤਰ addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, ਆਕਾਰ(ntop));
	memset(strport, 0, ਆਕਾਰ(strport));

	ਲਈ (attempt = 0; attempt < connection_attempts; attempt++) {
		ਜੇ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		ਲਈ (ai = aitop; ai; ai = ai->ai_next) {
			ਜੇ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ਜਾਰੀ;
			}
			ਜੇ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, ਆਕਾਰ(ntop), strport, ਆਕਾਰ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ਜਾਰੀ;
			}
			ਜੇ (options.ਪਤਾ_family != AF_UNSPEC &&
			    ai->ai_family != options.ਪਤਾ_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ਜਾਰੀ;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ਜੇ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ਜਾਰੀ;
			}

			*timeout_ms = saved_timeout_ms;
			ਜੇ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(hostaddr, ai->ai_addr, ai->ai_addrlen);
				ਰੋਕੋ;
			} ਨਹੀਂਤਾਂ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ਜੇ (sock != -1)
			ਰੋਕੋ;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ਜੇ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ਵਾਪਸ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ਜੇ (want_keepalive)
		ਸੈੱਟ_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ਜੇ (ssh_packet_ਸੈੱਟ_connection(ssh, sock, sock) == ਨਿਰਾ)
		ਵਾਪਸ -1; /* ssh_packet_set_connection logs error */

	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_connect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *host_arg,
    ਬਣਤਰ addrinfo *addrs, ਬਣਤਰ sockaddr_storage *hostaddr, u_short ਪੋਰਟ,
    ਪੂਰਨ connection_attempts, ਪੂਰਨ *timeout_ms, ਪੂਰਨ want_keepalive)
{
	ਪੂਰਨ ਵਿੱਚ, ਬਾਹਰਲਾ;

	ਜੇ (options.proxy_command == ਨਿਰਾ) {
		ਵਾਪਸ ssh_connect_ਸਿੱਧਾ(ssh, host, addrs, hostaddr, ਪੋਰਟ,
		    connection_attempts, timeout_ms, want_keepalive);
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(options.proxy_command, "-") == 0) {
		ਜੇ ((ਵਿੱਚ = dup(STDIN_FILENO)) == -1 ||
		    (ਬਾਹਰਲਾ = dup(STDOUT_FILENO)) == -1) {
			ਜੇ (ਵਿੱਚ >= 0)
				close(ਵਿੱਚ);
			error_f("dup() in/out failed");
			ਵਾਪਸ -1; /* ssh_packet_set_connection logs error */
		}
		ਜੇ ((ssh_packet_ਸੈੱਟ_connection(ssh, ਵਿੱਚ, ਬਾਹਰਲਾ)) == ਨਿਰਾ)
			ਵਾਪਸ -1; /* ssh_packet_set_connection logs error */
		ਵਾਪਸ 0;
	} ਨਹੀਂਤਾਂ ਜੇ (options.proxy_use_fdpass) {
		ਵਾਪਸ ssh_proxy_fdpass_connect(ssh, host, host_arg, ਪੋਰਟ,
		    options.proxy_command);
	}
	ਵਾਪਸ ssh_proxy_connect(ssh, host, host_arg, ਪੋਰਟ,
	    options.proxy_command);
}

/* defaults to 'no' */
ਸਥਿਰ ਪੂਰਨ
confirm(ਅਚਲ ਅੱਖਰ *prompt, ਅਚਲ ਅੱਖਰ *fingerprint)
{
	ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ, *again = "Please type 'yes' or 'no': ";
	ਅਚਲ ਅੱਖਰ *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	ਅੱਖਰ *p, *cp;
	ਪੂਰਨ ret = -1;

	ਜੇ (options.batch_ਬਹੁਲਕ)
		ਵਾਪਸ 0;
	ਲਈ (ਸੁਨੇਹਾ = prompt;;ਸੁਨੇਹਾ = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(ਸੁਨੇਹਾ, RP_ECHO);
		ਜੇ (p == ਨਿਰਾ)
			ਵਾਪਸ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ਜੇ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(p, "yes") == 0 || (fingerprint != ਨਿਰਾ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		ਮੁਕਤ(cp);
		ਜੇ (ret != -1)
			ਵਾਪਸ ret;
	}
}

ਸਥਿਰ ਪੂਰਨ
sockaddr_is_local(ਬਣਤਰ sockaddr *hostaddr)
{
	ਚੋਣ (hostaddr->sa_family) {
	ਹਾਲਤ AF_INET:
		ਵਾਪਸ (ntohl(((ਬਣਤਰ sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	ਹਾਲਤ AF_INET6:
		ਵਾਪਸ IN6_IS_ADDR_LOOPBACK(
		    &(((ਬਣਤਰ sockaddr_in6 *)hostaddr)->sin6_addr));
	ਮੂਲ:
		ਵਾਪਸ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
ਖਾਲੀ
get_hostfile_hostname_ipaddr(ਅੱਖਰ *hostname, ਬਣਤਰ sockaddr *hostaddr,
    u_short ਪੋਰਟ, ਅੱਖਰ **hostfile_hostname, ਅੱਖਰ **hostfile_ipaddr)
{
	ਅੱਖਰ ntop[NI_MAXHOST];
	socklen_t addrlen;

	ਚੋਣ (hostaddr == ਨਿਰਾ ? -1 : hostaddr->sa_family) {
	ਹਾਲਤ -1:
		addrlen = 0;
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET:
		addrlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
		addrlen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
		ਰੋਕੋ;
	ਮੂਲ:
		addrlen = ਆਕਾਰ(ਬਣਤਰ sockaddr);
		ਰੋਕੋ;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ਜੇ (hostfile_ipaddr != ਨਿਰਾ) {
		ਜੇ (options.proxy_command == ਨਿਰਾ) {
			ਜੇ (getnameinfo(hostaddr, addrlen,
			    ntop, ਆਕਾਰ(ntop), ਨਿਰਾ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_ਪੋਰਟ(ntop, ਪੋਰਟ);
		} ਨਹੀਂਤਾਂ {
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
	ਜੇ (hostfile_hostname != ਨਿਰਾ) {
		ਜੇ (options.host_ਕੁੰਜੀ_alias != ਨਿਰਾ) {
			*hostfile_hostname = xstrdup(options.host_ਕੁੰਜੀ_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ਨਹੀਂਤਾਂ {
			*hostfile_hostname = put_host_ਪੋਰਟ(hostname, ਪੋਰਟ);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ਸਥਿਰ ਪੂਰਨ
ਰਸਤਾ_ਵਿੱਚ_hostfiles(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅੱਖਰ **hostfiles, u_int ਅੰਕ_hostfiles)
{
	u_int i;

	ਲਈ (i = 0; i < ਅੰਕ_hostfiles; i++) {
		ਜੇ (strcmp(ਰਸਤਾ, hostfiles[i]) == 0)
			ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਬਣਤਰ ਲੱਭੋ_by_ਕੁੰਜੀ_ctx {
	ਅਚਲ ਅੱਖਰ *host, *ip;
	ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਅੱਖਰ **ਨਾਂ;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ਸਥਿਰ ਅੱਖਰ *
try_tilde_unexpand(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅੱਖਰ *home, *ret = ਨਿਰਾ;
	ਮਾਪ_t l;

	ਜੇ (*ਰਸਤਾ != '/')
		ਵਾਪਸ xstrdup(ਰਸਤਾ);
	ਜੇ ((home = getenv("HOME")) == ਨਿਰਾ || (l = ਲੜੀ_ਲੰਬਾਈ(home)) == 0)
		ਵਾਪਸ xstrdup(ਰਸਤਾ);
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਰਸਤਾ, home, l) != 0)
		ਵਾਪਸ xstrdup(ਰਸਤਾ);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ਜੇ (home[l - 1] != '/' && ਰਸਤਾ[l] != '/')
		ਵਾਪਸ xstrdup(ਰਸਤਾ);
	ਜੇ (ਰਸਤਾ[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", ਰਸਤਾ + l);
	ਵਾਪਸ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
ਪੂਰਨ
hostkey_accepted_by_hostkeyalgs(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅਚਲ ਅੱਖਰ *ktype = sshkey_ssh_name(ਕੁੰਜੀ);
	ਅਚਲ ਅੱਖਰ *hostkeyalgs = options.hostkeyalgorithms;

	ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_UNSPEC)
		ਵਾਪਸ 0;
	ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA &&
	    (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ਵਾਪਸ 1;
	ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA_CERT &&
	    (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ਵਾਪਸ 1;
	ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list(ktype, hostkeyalgs, 0) == 1;
}

ਸਥਿਰ ਪੂਰਨ
hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ_cb(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ ਲੱਭੋ_by_ਕੁੰਜੀ_ctx *ctx = (ਬਣਤਰ ਲੱਭੋ_by_ਕੁੰਜੀ_ctx *)_ctx;
	ਅੱਖਰ *ਰਸਤਾ;

	/* we are looking for keys with names that *do not* match */
	ਜੇ ((l->ਮੇਲ & HKF_ਮੇਲ_HOST) != 0)
		ਵਾਪਸ 0;
	/* not interested in marker lines */
	ਜੇ (l->marker != MRK_NONE)
		ਵਾਪਸ 0;
	/* we are only interested in exact key matches */
	ਜੇ (l->ਕੁੰਜੀ == ਨਿਰਾ || !sshkey_equal(ctx->ਕੁੰਜੀ, l->ਕੁੰਜੀ))
		ਵਾਪਸ 0;
	ਰਸਤਾ = try_tilde_unexpand(l->ਰਸਤਾ);
	debug_f("found matching key in %s:%lu", ਰਸਤਾ, l->linenum);
	ctx->ਨਾਂ = xrecallocarray(ctx->ਨਾਂ,
	    ctx->nnames, ctx->nnames + 1, ਆਕਾਰ(*ctx->ਨਾਂ));
	xasprintf(&ctx->ਨਾਂ[ctx->nnames], "%s:%lu: %s", ਰਸਤਾ, l->linenum,
	    ਲੜੀ_ਤੁਲਨਾ(l->hosts, HASH_MAGIC, ਲੜੀ_ਲੰਬਾਈ(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ_hostfile(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *which,
    ਬਣਤਰ ਲੱਭੋ_by_ਕੁੰਜੀ_ctx *ctx)
{
	ਪੂਰਨ r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ਜੇ ((r = hostkeys_foreach(file, hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_ਕੁੰਜੀ, 0)) != 0) {
		ਜੇ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ਵਾਪਸ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ਸਥਿਰ ਖਾਲੀ
hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅੱਖਰ **user_hostfiles, u_int ਅੰਕ_user_hostfiles,
    ਅੱਖਰ **system_hostfiles, u_int ਅੰਕ_system_hostfiles,
    ਅੱਖਰ ***ਨਾਂ, u_int *nnames)
{
	ਬਣਤਰ ਲੱਭੋ_by_ਕੁੰਜੀ_ctx ctx = {ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, 0};
	u_int i;

	*ਨਾਂ = ਨਿਰਾ;
	*nnames = 0;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || sshkey_is_cert(ਕੁੰਜੀ))
		ਵਾਪਸ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.ਕੁੰਜੀ = ਕੁੰਜੀ;

	ਲਈ (i = 0; i < ਅੰਕ_user_hostfiles; i++) {
		ਜੇ (hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			ਜਾਓ fail;
	}
	ਲਈ (i = 0; i < ਅੰਕ_system_hostfiles; i++) {
		ਜੇ (hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			ਜਾਓ fail;
	}
	/* success */
	*ਨਾਂ = ctx.ਨਾਂ;
	*nnames = ctx.nnames;
	ctx.ਨਾਂ = ਨਿਰਾ;
	ctx.nnames = 0;
	ਵਾਪਸ;
 fail:
	ਲਈ (i = 0; i < ctx.nnames; i++)
		ਮੁਕਤ(ctx.ਨਾਂ[i]);
	ਮੁਕਤ(ctx.ਨਾਂ);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_OTHER_ਨਾਂ	8 /* Maximum number of names to list */
ਸਥਿਰ ਅੱਖਰ *
other_hostkeys_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip,
    ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅੱਖਰ **user_hostfiles, u_int ਅੰਕ_user_hostfiles,
    ਅੱਖਰ **system_hostfiles, u_int ਅੰਕ_system_hostfiles)
{
	ਅੱਖਰ *ret = ਨਿਰਾ, **othernames = ਨਿਰਾ;
	u_int i, n, ਅੰਕ_othernames = 0;

	hostkeys_ਲੱਭੋ_by_ਕੁੰਜੀ(host, ip, ਕੁੰਜੀ,
	    user_hostfiles, ਅੰਕ_user_hostfiles,
	    system_hostfiles, ਅੰਕ_system_hostfiles,
	    &othernames, &ਅੰਕ_othernames);
	ਜੇ (ਅੰਕ_othernames == 0)
		ਵਾਪਸ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = ਅੰਕ_othernames;
	ਜੇ (n > MAX_OTHER_ਨਾਂ)
		n = MAX_OTHER_ਨਾਂ;
	ਲਈ (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ਜੇ (n < ਅੰਕ_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    ਅੰਕ_othernames - n);
	}
	ਲਈ (i = 0; i < ਅੰਕ_othernames; i++)
		ਮੁਕਤ(othernames[i]);
	ਮੁਕਤ(othernames);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
ਲੱਦੋ_hostkeys_command(ਬਣਤਰ hostkeys *hostkeys, ਅਚਲ ਅੱਖਰ *command_template,
    ਅਚਲ ਅੱਖਰ *invocation, ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo,
    ਅਚਲ ਬਣਤਰ sshkey *host_ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hostfile_hostname)
{
	ਪੂਰਨ r, i, ac = 0;
	ਅੱਖਰ *ਕੁੰਜੀ_fp = ਨਿਰਾ, *keytext = ਨਿਰਾ, *tmp;
	ਅੱਖਰ *command = ਨਿਰਾ, *ਟੈਗ = ਨਿਰਾ, **av = ਨਿਰਾ;
	FILE *f = ਨਿਰਾ;
	pid_t pid;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);

	xasprintf(&ਟੈਗ, "KnownHostsCommand-%s", invocation);

	ਜੇ (host_ਕੁੰਜੀ != ਨਿਰਾ) {
		ਜੇ ((ਕੁੰਜੀ_fp = sshkey_fingerprint(host_ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint failed");
		ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_base64(host_ਕੁੰਜੀ, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ਜੇ (argv_ਵੰਡੋ(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", ਟੈਗ,
		    command_template);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ac == 0) {
		error("%s \"%s\" yielded no arguments", ਟੈਗ,
		    command_template);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_ਕੁੰਜੀ == ਨਿਰਾ ? "NONE" : sshkey_ssh_name(host_ਕੁੰਜੀ),
		    "f", ਕੁੰਜੀ_fp == ਨਿਰਾ ? "NONE" : ਕੁੰਜੀ_fp,
		    "K", keytext == ਨਿਰਾ ? "NONE" : keytext,
		    (ਅੱਖਰ *)ਨਿਰਾ);
		ਜੇ (tmp == ਨਿਰਾ)
			fatal_f("percent_expand failed");
		ਮੁਕਤ(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ਜੇ ((pid = subprocess(ਟੈਗ, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_ਰਸਤਾ|
	    SSH_SUBPROCESS_PRESERVE_ENV, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਲੱਦੋ_hostkeys_file(hostkeys, hostfile_hostname, ਟੈਗ, f, 1);

	ਜੇ (exited_cleanly(pid, ਟੈਗ, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 ਬਾਹਰਲਾ:
	ਜੇ (f != ਨਿਰਾ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	ਲਈ (i = 0; i < ac; i++)
		ਮੁਕਤ(av[i]);
	ਮੁਕਤ(av);
	ਮੁਕਤ(ਟੈਗ);
	ਮੁਕਤ(command);
	ਮੁਕਤ(ਕੁੰਜੀ_fp);
	ਮੁਕਤ(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RDRW	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RDONLY	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ROQUIET	2
ਸਥਿਰ ਪੂਰਨ
check_host_ਕੁੰਜੀ(ਅੱਖਰ *hostname, ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo,
    ਬਣਤਰ sockaddr *hostaddr, u_short ਪੋਰਟ,
    ਬਣਤਰ sshkey *host_ਕੁੰਜੀ, ਪੂਰਨ readonly, ਪੂਰਨ clobber_ਪੋਰਟ,
    ਅੱਖਰ **user_hostfiles, u_int ਅੰਕ_user_hostfiles,
    ਅੱਖਰ **system_hostfiles, u_int ਅੰਕ_system_hostfiles,
    ਅਚਲ ਅੱਖਰ *hostfile_command)
{
	Host_ਸਥਿਤੀ host_ਸਥਿਤੀ = -1, ip_ਸਥਿਤੀ = -1;
	ਬਣਤਰ sshkey *raw_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *ip = ਨਿਰਾ, *host = ਨਿਰਾ;
	ਅੱਖਰ hostline[1000], *hostp, *fp, *ra;
	ਅੱਖਰ ਸੁਨੇਹਾ[1024];
	ਅਚਲ ਅੱਖਰ *type, *fail_reason = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *host_ਮਿਲਿਆ = ਨਿਰਾ, *ip_ਮਿਲਿਆ = ਨਿਰਾ;
	ਪੂਰਨ len, cancelled_forwarding = 0, confirmed;
	ਪੂਰਨ local = sockaddr_is_local(hostaddr);
	ਪੂਰਨ r, want_cert = sshkey_is_cert(host_ਕੁੰਜੀ), host_ip_ਫਰਕ = 0;
	ਪੂਰਨ hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ਬਣਤਰ hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ਜੇ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_ਕੁੰਜੀ_alias == ਨਿਰਾ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ਵਾਪਸ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ਜੇ (strcspn(hostname, "@?*#[]|'\'\"\\") != ਲੜੀ_ਲੰਬਾਈ(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_ਪੋਰਟ ? 0 : ਪੋਰਟ, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	ਜੇ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ਨਿਰਾ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	ਲਈ (i = 0; i < ਅੰਕ_user_hostfiles; i++)
		ਲੱਦੋ_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	ਲਈ (i = 0; i < ਅੰਕ_system_hostfiles; i++)
		ਲੱਦੋ_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ਜੇ (hostfile_command != ਨਿਰਾ && !clobber_ਪੋਰਟ) {
		ਲੱਦੋ_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_ਕੁੰਜੀ, host);
	}

	ip_hostkeys = ਨਿਰਾ;
	ਜੇ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		ਲਈ (i = 0; i < ਅੰਕ_user_hostfiles; i++)
			ਲੱਦੋ_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		ਲਈ (i = 0; i < ਅੰਕ_system_hostfiles; i++)
			ਲੱਦੋ_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ਜੇ (hostfile_command != ਨਿਰਾ && !clobber_ਪੋਰਟ) {
			ਲੱਦੋ_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_ਕੁੰਜੀ, ip);
		}
	}

 retry:
	ਜੇ (!hostkey_accepted_by_hostkeyalgs(host_ਕੁੰਜੀ)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_ਕੁੰਜੀ));
		ਜਾਓ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_ਕੁੰਜੀ);
	type = sshkey_type(host_ਕੁੰਜੀ);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_ਸਥਿਤੀ = check_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys(host_hostkeys, host_ਕੁੰਜੀ,
	    &host_ਮਿਲਿਆ);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ਜੇ (!readonly && (ਅੰਕ_user_hostfiles == 0 ||
	    (host_ਮਿਲਿਆ != ਨਿਰਾ && host_ਮਿਲਿਆ->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ਜੇ (!want_cert && ip_hostkeys != ਨਿਰਾ) {
		ip_ਸਥਿਤੀ = check_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys(ip_hostkeys, host_ਕੁੰਜੀ,
		    &ip_ਮਿਲਿਆ);
		ਜੇ (host_ਸਥਿਤੀ == HOST_ਬਦਲਿਆ &&
		    (ip_ਸਥਿਤੀ != HOST_ਬਦਲਿਆ ||
		    (ip_ਮਿਲਿਆ != ਨਿਰਾ &&
		    !sshkey_equal(ip_ਮਿਲਿਆ->ਕੁੰਜੀ, host_ਮਿਲਿਆ->ਕੁੰਜੀ))))
			host_ip_ਫਰਕ = 1;
	} ਨਹੀਂਤਾਂ
		ip_ਸਥਿਤੀ = host_ਸਥਿਤੀ;

	ਚੋਣ (host_ਸਥਿਤੀ) {
	ਹਾਲਤ HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_ਮਿਲਿਆ->file, host_ਮਿਲਿਆ->ਸਤਰ);
		ਜੇ (want_cert) {
			ਜੇ (sshkey_cert_check_host(host_ਕੁੰਜੀ,
			    options.host_ਕੁੰਜੀ_alias == ਨਿਰਾ ?
			    hostname : options.host_ਕੁੰਜੀ_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				ਜਾਓ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ਜੇ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ਜੇ (options.update_hostkeys != 0 &&
		    (ਰਸਤਾ_ਵਿੱਚ_hostfiles(host_ਮਿਲਿਆ->file,
		    system_hostfiles, ਅੰਕ_system_hostfiles) ||
		    (ip_ਸਥਿਤੀ == HOST_OK && ip_ਮਿਲਿਆ != ਨਿਰਾ &&
		    ਰਸਤਾ_ਵਿੱਚ_hostfiles(ip_ਮਿਲਿਆ->file,
		    system_hostfiles, ਅੰਕ_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ਜੇ (options.update_hostkeys != 0 && host_ਮਿਲਿਆ->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ਜੇ (options.check_host_ip && ip_ਸਥਿਤੀ == HOST_NEW) {
			ਜੇ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ਨਹੀਂਤਾਂ ਜੇ (!ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(user_hostfiles[0], ip,
			    host_ਕੁੰਜੀ, options.hash_ਗਿਆਤ_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ਨਹੀਂਤਾਂ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ਨਹੀਂਤਾਂ ਜੇ (options.visual_host_ਕੁੰਜੀ) {
			fp = sshkey_fingerprint(host_ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			ਮੁਕਤ(ra);
			ਮੁਕਤ(fp);
		}
		hostkey_trusted = 1;
		ਰੋਕੋ;
	ਹਾਲਤ HOST_NEW:
		ਜੇ (options.host_ਕੁੰਜੀ_alias == ਨਿਰਾ && ਪੋਰਟ != 0 &&
		    ਪੋਰਟ != SSH_DEFAULT_ਪੋਰਟ && !clobber_ਪੋਰਟ) {
			debug("checking without port identifier");
			ਜੇ (check_host_ਕੁੰਜੀ(hostname, cinfo, hostaddr, 0,
			    host_ਕੁੰਜੀ, ROQUIET, 1,
			    user_hostfiles, ਅੰਕ_user_hostfiles,
			    system_hostfiles, ਅੰਕ_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				ਰੋਕੋ;
			}
		}
		ਜੇ (readonly || want_cert)
			ਜਾਓ fail;
		/* The host is new. */
		ਜੇ (options.strict_host_ਕੁੰਜੀ_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (options.strict_host_ਕੁੰਜੀ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			ਅੱਖਰ *msg1 = ਨਿਰਾ, *msg2 = ਨਿਰਾ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ਜੇ (show_other_ਕੁੰਜੀਆਂ(host_hostkeys, host_ਕੁੰਜੀ)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ਨਹੀਂਤਾਂ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ਕੁੰਜੀ,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ਜੇ (options.visual_host_ਕੁੰਜੀ)
				xextendf(&msg1, "\n", "%s", ra);
			ਜੇ (options.verify_host_ਕੁੰਜੀ_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_ਕੁੰਜੀ_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ਜੇ ((msg2 = other_hostkeys_ਸੁਨੇਹਾ(host, ip, host_ਕੁੰਜੀ,
			    user_hostfiles, ਅੰਕ_user_hostfiles,
			    system_hostfiles, ਅੰਕ_system_hostfiles)) != ਨਿਰਾ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			ਮੁਕਤ(ra);
			ਮੁਕਤ(fp);
			ਮੁਕਤ(msg1);
			ਮੁਕਤ(msg2);
			ਜੇ (!confirmed)
				ਜਾਓ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ਜੇ (options.check_host_ip && ip_ਸਥਿਤੀ == HOST_NEW) {
			snprintf(hostline, ਆਕਾਰ(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ਜੇ (options.hash_ਗਿਆਤ_hosts) {
				/* Add hash of host and IP separately */
				r = ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(user_hostfiles[0],
				    host, host_ਕੁੰਜੀ, options.hash_ਗਿਆਤ_hosts) &&
				    ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(user_hostfiles[0], ip,
				    host_ਕੁੰਜੀ, options.hash_ਗਿਆਤ_hosts);
			} ਨਹੀਂਤਾਂ {
				/* Add unhashed "host,ip" */
				r = ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(user_hostfiles[0],
				    hostline, host_ਕੁੰਜੀ,
				    options.hash_ਗਿਆਤ_hosts);
			}
		} ਨਹੀਂਤਾਂ {
			r = ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(user_hostfiles[0], host,
			    host_ਕੁੰਜੀ, options.hash_ਗਿਆਤ_hosts);
			hostp = host;
		}

		ਜੇ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ਨਹੀਂਤਾਂ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		ਰੋਕੋ;
	ਹਾਲਤ HOST_REVOKED:
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
		ਜੇ (options.strict_host_ਕੁੰਜੀ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			ਜਾਓ fail;
		}
		ਜਾਓ continue_unsafe;

	ਹਾਲਤ HOST_ਬਦਲਿਆ:
		ਜੇ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_ਮਿਲਿਆ->file, host_ਮਿਲਿਆ->ਸਤਰ);
			ਜਾਓ fail;
		}
		ਜੇ (readonly == ROQUIET)
			ਜਾਓ fail;
		ਜੇ (options.check_host_ip && host_ip_ਫਰਕ) {
			ਅੱਖਰ *ਕੁੰਜੀ_ਸੁਨੇਹਾ;
			ਜੇ (ip_ਸਥਿਤੀ == HOST_NEW)
				ਕੁੰਜੀ_ਸੁਨੇਹਾ = "is unknown";
			ਨਹੀਂਤਾਂ ਜੇ (ip_ਸਥਿਤੀ == HOST_OK)
				ਕੁੰਜੀ_ਸੁਨੇਹਾ = "is unchanged";
			ਨਹੀਂਤਾਂ
				ਕੁੰਜੀ_ਸੁਨੇਹਾ = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", ਕੁੰਜੀ_ਸੁਨੇਹਾ);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ਜੇ (ip_ਸਥਿਤੀ != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_ਮਿਲਿਆ->file, ip_ਮਿਲਿਆ->ਸਤਰ);
		}
		/* The host key has changed. */
		warn_ਬਦਲਿਆ_ਕੁੰਜੀ(host_ਕੁੰਜੀ);
		ਜੇ (ਅੰਕ_user_hostfiles > 0 || ਅੰਕ_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", ਅੰਕ_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_ਮਿਲਿਆ->ਕੁੰਜੀ),
		    host_ਮਿਲਿਆ->file, host_ਮਿਲਿਆ->ਸਤਰ);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ਜੇ (options.strict_host_ਕੁੰਜੀ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			ਜਾਓ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ਜੇ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.ਅੰਕ_local_forwards > 0 ||
		    options.ਅੰਕ_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.ਅੰਕ_local_forwards =
			    options.ਅੰਕ_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ਜੇ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ਜੇ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		ਰੋਕੋ;
	ਹਾਲਤ HOST_ਮਿਲਿਆ:
		fatal("internal error");
		ਰੋਕੋ;
	}

	ਜੇ (options.check_host_ip && host_ਸਥਿਤੀ != HOST_ਬਦਲਿਆ &&
	    ip_ਸਥਿਤੀ == HOST_ਬਦਲਿਆ) {
		snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_ਮਿਲਿਆ->file, ip_ਮਿਲਿਆ->ਸਤਰ);
		ਜੇ (host_ਸਥਿਤੀ == HOST_OK) {
			len = ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ);
			snprintf(ਸੁਨੇਹਾ + len, ਆਕਾਰ(ਸੁਨੇਹਾ) - len,
			    "\nMatching host key in %s:%lu",
			    host_ਮਿਲਿਆ->file, host_ਮਿਲਿਆ->ਸਤਰ);
		}
		ਜੇ (options.strict_host_ਕੁੰਜੀ_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(ਸੁਨੇਹਾ, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", ਆਕਾਰ(ਸੁਨੇਹਾ));
			ਜੇ (!confirm(ਸੁਨੇਹਾ, ਨਿਰਾ))
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (options.strict_host_ਕੁੰਜੀ_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", ਸੁਨੇਹਾ);
			error("Exiting, you have requested strict checking.");
			ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ {
			logit("%s", ਸੁਨੇਹਾ);
		}
	}

	ਜੇ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_ਕੁੰਜੀ);
	ਮੁਕਤ(ip);
	ਮੁਕਤ(host);
	ਜੇ (host_hostkeys != ਨਿਰਾ)
		free_hostkeys(host_hostkeys);
	ਜੇ (ip_hostkeys != ਨਿਰਾ)
		free_hostkeys(ip_hostkeys);
	ਵਾਪਸ 0;

fail:
	ਜੇ (want_cert && host_ਸਥਿਤੀ != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(host_ਕੁੰਜੀ, &raw_ਕੁੰਜੀ)) != 0)
			fatal_fr(r, "decode key");
		ਜੇ ((r = sshkey_drop_cert(raw_ਕੁੰਜੀ)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_ਕੁੰਜੀ = raw_ਕੁੰਜੀ;
		ਜਾਓ retry;
	}
	sshkey_free(raw_ਕੁੰਜੀ);
	ਮੁਕਤ(ip);
	ਮੁਕਤ(host);
	ਜੇ (host_hostkeys != ਨਿਰਾ)
		free_hostkeys(host_hostkeys);
	ਜੇ (ip_hostkeys != ਨਿਰਾ)
		free_hostkeys(ip_hostkeys);
	ਵਾਪਸ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
ਪੂਰਨ
verify_host_ਕੁੰਜੀ(ਅੱਖਰ *host, ਬਣਤਰ sockaddr *hostaddr, ਬਣਤਰ sshkey *host_ਕੁੰਜੀ,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	u_int i;
	ਪੂਰਨ r = -1, flags = 0;
	ਅੱਖਰ valid[64], *fp = ਨਿਰਾ, *cafp = ਨਿਰਾ;
	ਬਣਤਰ sshkey *plain = ਨਿਰਾ;

	ਜੇ ((fp = sshkey_fingerprint(host_ਕੁੰਜੀ,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (sshkey_is_cert(host_ਕੁੰਜੀ)) {
		ਜੇ ((cafp = sshkey_fingerprint(host_ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		sshkey_format_cert_validity(host_ਕੁੰਜੀ->cert,
		    valid, ਆਕਾਰ(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_ਕੁੰਜੀ), fp,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)host_ਕੁੰਜੀ->cert->serial,
		    host_ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
		    sshkey_ssh_name(host_ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), cafp,
		    valid);
		ਲਈ (i = 0; i < host_ਕੁੰਜੀ->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_ਕੁੰਜੀ->cert->principals[i]);
		}
	} ਨਹੀਂਤਾਂ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_ਕੁੰਜੀ), fp);
	}

	ਜੇ (sshkey_equal(ਪਿਛਲਾ_host_ਕੁੰਜੀ, host_ਕੁੰਜੀ)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_ਕੁੰਜੀ), fp);
		r = 0;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Check in RevokedHostKeys files if specified */
	ਲਈ (i = 0; i < options.ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ; i++) {
		r = sshkey_check_revoked(host_ਕੁੰਜੀ,
		    options.revoked_host_ਕੁੰਜੀਆਂ[i]);
		ਚੋਣ (r) {
		ਹਾਲਤ 0:
			ਰੋਕੋ; /* not revoked */
		ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_ਕੁੰਜੀ), fp,
			    options.revoked_host_ਕੁੰਜੀਆਂ[i]);
			r = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		ਮੂਲ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_ਕੁੰਜੀ),
			    fp, options.revoked_host_ਕੁੰਜੀਆਂ[i]);
			r = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਜੇ (options.verify_host_ਕੁੰਜੀ_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(host_ਕੁੰਜੀ, &plain)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ਜੇ (verify_host_ਕੁੰਜੀ_dns(host, hostaddr, plain, &flags) == 0) {
			ਜੇ (flags & DNS_VERIFY_ਮਿਲਿਆ) {
				ਜੇ (options.verify_host_ਕੁੰਜੀ_dns == 1 &&
				    flags & DNS_VERIFY_ਮੇਲ &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				ਜੇ (flags & DNS_VERIFY_ਮੇਲ) {
					matching_host_ਕੁੰਜੀ_dns = 1;
				} ਨਹੀਂਤਾਂ {
					warn_ਬਦਲਿਆ_ਕੁੰਜੀ(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_ਕੁੰਜੀ(host, cinfo, hostaddr, options.ਪੋਰਟ, host_ਕੁੰਜੀ,
	    RDRW, 0, options.user_hostfiles, options.ਅੰਕ_user_hostfiles,
	    options.system_hostfiles, options.ਅੰਕ_system_hostfiles,
	    options.ਗਿਆਤ_hosts_command);

ਬਾਹਰਲਾ:
	sshkey_free(plain);
	ਮੁਕਤ(fp);
	ਮੁਕਤ(cafp);
	ਜੇ (r == 0 && host_ਕੁੰਜੀ != ਨਿਰਾ) {
		sshkey_free(ਪਿਛਲਾ_host_ਕੁੰਜੀ);
		r = sshkey_from_ਨਿੱਜੀ(host_ਕੁੰਜੀ, &ਪਿਛਲਾ_host_ਕੁੰਜੀ);
	}

	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
warn_nonpq_kex(ਖਾਲੀ)
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
ਖਾਲੀ
ssh_login(ਬਣਤਰ ssh *ssh, Sensitive *sensitive, ਅਚਲ ਅੱਖਰ *orighost,
    ਬਣਤਰ sockaddr_storage *hostaddr, u_short ਪੋਰਟ, ਬਣਤਰ passwd *pw,
    ਪੂਰਨ timeout_ms, ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਅੱਖਰ *host;
	ਅੱਖਰ *server_user, *local_user;
	ਪੂਰਨ r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ਜੇ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.ਸੰਸਕਰਣ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ਜੇ ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_ਸੈੱਟ_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, ਪੋਰਟ, server_user);
	ssh_kex2(ssh, host, hostaddr, ਪੋਰਟ, cinfo);
	kex_ਸੈੱਟ_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_ਸੈੱਟ);
	ਜੇ (!options.kex_algorithms_ਸੈੱਟ && ssh->kex != ਨਿਰਾ &&
	    ssh->kex->name != ਨਿਰਾ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	ਮੁਕਤ(local_user);
	ਮੁਕਤ(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ਸਥਿਰ ਪੂਰਨ
show_other_ਕੁੰਜੀਆਂ(ਬਣਤਰ hostkeys *hostkeys, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ type[] = {
		ਕੁੰਜੀ_RSA,
		ਕੁੰਜੀ_ECDSA,
		ਕੁੰਜੀ_ED25519,
		ਕੁੰਜੀ_MLDSA44_ED25519,
		-1
	};
	ਪੂਰਨ i, ret = 0;
	ਅੱਖਰ *fp, *ra;
	ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *ਮਿਲਿਆ;

	ਲਈ (i = 0; type[i] != -1; i++) {
		ਜੇ (type[i] == ਕੁੰਜੀ->type)
			ਜਾਰੀ;
		ਜੇ (!lookup_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys_by_type(hostkeys, type[i],
		    -1, &ਮਿਲਿਆ))
			ਜਾਰੀ;
		fp = sshkey_fingerprint(ਮਿਲਿਆ->ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ਮਿਲਿਆ->ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(ਮਿਲਿਆ->ਕੁੰਜੀ),
		    ਮਿਲਿਆ->host, ਮਿਲਿਆ->file, ਮਿਲਿਆ->ਸਤਰ,
		    sshkey_type(ਮਿਲਿਆ->ਕੁੰਜੀ), fp);
		ਜੇ (options.visual_host_ਕੁੰਜੀ)
			logit("%s", ra);
		ਮੁਕਤ(ra);
		ਮੁਕਤ(fp);
		ret = 1;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
warn_ਬਦਲਿਆ_ਕੁੰਜੀ(ਬਣਤਰ sshkey *host_ਕੁੰਜੀ)
{
	ਅੱਖਰ *fp;

	fp = sshkey_fingerprint(host_ਕੁੰਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ਜੇ (fp == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_ਕੁੰਜੀ), fp);
	error("Please contact your system administrator.");

	ਮੁਕਤ(fp);
}

/*
 * Execute a local command
 */
ਪੂਰਨ
ssh_local_cmd(ਅਚਲ ਅੱਖਰ *ਦਲੀਲਾਂ)
{
	ਅੱਖਰ *shell;
	pid_t pid;
	ਪੂਰਨ ਸਥਿਤੀ;
	ਖਾਲੀ (*osighand)(ਪੂਰਨ);

	ਜੇ (!options.permit_local_command ||
	    ਦਲੀਲਾਂ == ਨਿਰਾ || !*ਦਲੀਲਾਂ)
		ਵਾਪਸ (1);

	ਜੇ ((shell = getenv("SHELL")) == ਨਿਰਾ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ਜੇ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, ਦਲੀਲਾਂ);
		execl(shell, shell, "-c", ਦਲੀਲਾਂ, (ਅੱਖਰ *)ਨਿਰਾ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, ਦਲੀਲਾਂ, strerror(errno));
		_exit(1);
	} ਨਹੀਂਤਾਂ ਜੇ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1)
		ਜੇ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ਜੇ (!WIFEXITED(ਸਥਿਤੀ))
		ਵਾਪਸ (1);

	ਵਾਪਸ (WEXITSTATUS(ਸਥਿਤੀ));
}

ਖਾਲੀ
maybe_ਜੋੜੋ_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_agent(ਅਚਲ ਅੱਖਰ *authfile, ਬਣਤਰ sshkey *ਨਿਜੀ,
    ਅਚਲ ਅੱਖਰ *comment, ਅਚਲ ਅੱਖਰ *passphrase)
{
	ਪੂਰਨ auth_sock = -1, r;
	ਅਚਲ ਅੱਖਰ *skprovider = ਨਿਰਾ;

	ਜੇ (options.ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == 0)
		ਵਾਪਸ;

	ਜੇ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ਵਾਪਸ;
	}

	ਜੇ (options.ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ਵਾਪਸ;
	}
	ਜੇ (sshkey_is_sk(ਨਿਜੀ))
		skprovider = options.sk_provider;
	ਜੇ ((r = ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(auth_sock, ਨਿਜੀ,
	    comment == ਨਿਰਾ ? authfile : comment,
	    options.ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan,
	    (options.ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == 3), skprovider, ਨਿਰਾ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ਨਹੀਂਤਾਂ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
