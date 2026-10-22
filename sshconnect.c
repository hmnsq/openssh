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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <net/if.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <ifaddrs.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshconnect.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "dns.h"
#અન્તર્ભાવ "monitor_fdpass.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "kex.h"

સંરચના sshkey *previous_host_ચાવી = ખાલી;

સ્થિર પૂર્ણાંક matching_host_ચાવી_dns = 0;

સ્થિર pid_t proxy_command_pid = 0;

/* import */
બાહ્ય પૂર્ણાંક debug_flag;
બાહ્ય Options options;
બાહ્ય અક્ષર *__progname;

સ્થિર પૂર્ણાંક show_other_ચાવીઓ(સંરચના hostkeys *, સંરચના sshkey *);
સ્થિર શૂન્ય warn_changed_ચાવી(સંરચના sshkey *);

શૂન્ય
ssh_conn_info_free(સંરચના ssh_conn_info *cinfo)
{
	જો (cinfo == ખાલી)
		પાછા;
	મુક્ત(cinfo->conn_hash_hex);
	મુક્ત(cinfo->shorthost);
	મુક્ત(cinfo->uidstr);
	મુક્ત(cinfo->keyalias);
	મુક્ત(cinfo->thishost);
	મુક્ત(cinfo->host_arg);
	મુક્ત(cinfo->portstr);
	મુક્ત(cinfo->remhost);
	મુક્ત(cinfo->remuser);
	મુક્ત(cinfo->homedir);
	મુક્ત(cinfo->locuser);
	મુક્ત(cinfo->jmphost);
	freezero(cinfo, કદ(*cinfo));
}

સંરચના ssh_conn_info *
ssh_conn_info_dup(અચલ સંરચના ssh_conn_info *cinfo)
{
	સંરચના ssh_conn_info *ret;

	જો (cinfo == ખાલી)
		પાછા ખાલી;
	ret = xcalloc(1, કદ(*ret));
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
	પાછા ret;
}

/* Expand a proxy command */
સ્થિર અક્ષર *
expand_proxy_command(અચલ અક્ષર *proxy_command, અચલ અક્ષર *user,
    અચલ અક્ષર *host, અચલ અક્ષર *host_arg, પૂર્ણાંક port)
{
	અક્ષર *tmp, *ret, strport[NI_MAXSERV];
	અચલ અક્ષર *keyalias = options.host_ચાવી_alias ?
	    options.host_ચાવી_alias : host_arg;

	snprintf(strport, કદ strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (અક્ષર *)ખાલી);
	મુક્ત(tmp);
	પાછા ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
સ્થિર પૂર્ણાંક
ssh_proxy_fdpass_connect(સંરચના ssh *ssh, અચલ અક્ષર *host,
    અચલ અક્ષર *host_arg, u_short port, અચલ અક્ષર *proxy_command)
{
	અક્ષર *command_string;
	પૂર્ણાંક sp[2], sock;
	pid_t pid;
	અક્ષર *shell;

	જો ((shell = getenv("SHELL")) == ખાલી)
		shell = _PATH_BSHELL;

	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	જો ((pid = fork()) == 0) {
		અક્ષર *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		જો (sp[0] != 0) {
			જો (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		જો (sp[0] != 1) {
			જો (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		જો (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		જો (!debug_flag && options.control_path != ખાલી &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ખાલી;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	જો (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	મુક્ત(command_string);

	જો ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	જ્યારે (waitpid(pid, ખાલી, 0) == -1)
		જો (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	જો (ssh_packet_set_connection(ssh, sock, sock) == ખાલી)
		પાછા -1; /* ssh_packet_set_connection logs error */

	પાછા 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
સ્થિર પૂર્ણાંક
ssh_proxy_connect(સંરચના ssh *ssh, અચલ અક્ષર *host, અચલ અક્ષર *host_arg,
    u_short port, અચલ અક્ષર *proxy_command)
{
	અક્ષર *command_string;
	પૂર્ણાંક pin[2], pout[2];
	pid_t pid;
	અક્ષર *shell;

	જો ((shell = getenv("SHELL")) == ખાલી || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	જો (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	જો ((pid = fork()) == 0) {
		અક્ષર *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		જો (pin[0] != 0) {
			જો (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		જો (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		જો (!debug_flag && options.control_path != ખાલી &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = ખાલી;

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
	જો (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	નહીંતર
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	મુક્ત(command_string);

	/* Set the connection file descriptors. */
	જો (ssh_packet_set_connection(ssh, pout[0], pin[1]) == ખાલી)
		પાછા -1; /* ssh_packet_set_connection logs error */

	પાછા 0;
}

શૂન્ય
ssh_kill_proxy_command(શૂન્ય)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	જો (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
સ્થિર પૂર્ણાંક
check_ifaddrs(અચલ અક્ષર *ifname, પૂર્ણાંક af, અચલ સંરચના ifaddrs *ifaddrs,
    સંરચના sockaddr_storage *resultp, socklen_t *rlenp)
{
	સંરચના sockaddr_in6 *sa6;
	સંરચના sockaddr_in *sa;
	સંરચના in6_addr *v6addr;
	અચલ સંરચના ifaddrs *ifa;
	પૂર્ણાંક allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	માટે (allow_local = 0; allow_local < 2; allow_local++) {
		માટે (ifa = ifaddrs; ifa != ખાલી; ifa = ifa->ifa_next) {
			જો (ifa->ifa_addr == ખાલી || ifa->ifa_name == ખાલી ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ચાલુ;
			પસંદગી (ifa->ifa_addr->sa_family) {
			સ્થિતિ AF_INET:
				sa = (સંરચના sockaddr_in *)ifa->ifa_addr;
				જો (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ચાલુ;
				જો (*rlenp < કદ(સંરચના sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					પાછા -1;
				}
				*rlenp = કદ(સંરચના sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				પાછા 0;
			સ્થિતિ AF_INET6:
				sa6 = (સંરચના sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				જો (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ચાલુ;
				જો (*rlenp < કદ(સંરચના sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					પાછા -1;
				}
				*rlenp = કદ(સંરચના sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				પાછા 0;
			}
		}
	}
	પાછા -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
સ્થિર પૂર્ણાંક
ssh_create_socket(સંરચના addrinfo *ai)
{
	પૂર્ણાંક sock, r;
	સંરચના sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	સંરચના addrinfo hints, *res = ખાલી;
#ifdef HAVE_IFADDRS_H
	સંરચના ifaddrs *ifaddrs = ખાલી;
#endif
	અક્ષર ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	જો (sock == -1) {
		error("socket: %s", strerror(errno));
		પાછા -1;
	}
	(શૂન્ય)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	જો (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	જો (options.bind_address == ખાલી && options.bind_interface == ખાલી)
		પાછા sock;

	જો (options.bind_address != ખાલી) {
		memset(&hints, 0, કદ(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		જો ((r = getaddrinfo(options.bind_address, ખાલી,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			જાઓ fail;
		}
		જો (res == ખાલી) {
			error("getaddrinfo: no addrs");
			જાઓ fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} નહીંતર જો (options.bind_interface != ખાલી) {
#ifdef HAVE_IFADDRS_H
		જો ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			જાઓ fail;
		}
		bindaddrlen = કદ(bindaddr);
		જો (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			જાઓ fail;
		}
#નહીંતર
		error("BindInterface not supported on this platform.");
#endif
	}
	જો ((r = getnameinfo((સંરચના sockaddr *)&bindaddr, bindaddrlen,
	    ntop, કદ(ntop), ખાલી, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		જાઓ fail;
	}
	જો (bind(sock, (સંરચના sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		જાઓ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	જાઓ out;
fail:
	close(sock);
	sock = -1;
 out:
	જો (res != ખાલી)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	જો (ifaddrs != ખાલી)
		freeifaddrs(ifaddrs);
#endif
	પાછા sock;
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
સ્થિર પૂર્ણાંક
ssh_connect_direct(સંરચના ssh *ssh, અચલ અક્ષર *host, સંરચના addrinfo *aitop,
    સંરચના sockaddr_storage *hostaddr, u_short port, પૂર્ણાંક connection_attempts,
    પૂર્ણાંક *timeout_ms, પૂર્ણાંક want_keepalive)
{
	પૂર્ણાંક saved_timeout_ms = *timeout_ms;
	પૂર્ણાંક oerrno, sock = -1, attempt;
	અક્ષર ntop[NI_MAXHOST], strport[NI_MAXSERV];
	સંરચના addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, કદ(ntop));
	memset(strport, 0, કદ(strport));

	માટે (attempt = 0; attempt < connection_attempts; attempt++) {
		જો (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		માટે (ai = aitop; ai; ai = ai->ai_next) {
			જો (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ચાલુ;
			}
			જો (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, કદ(ntop), strport, કદ(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ચાલુ;
			}
			જો (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ચાલુ;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			જો (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ચાલુ;
			}

			*timeout_ms = saved_timeout_ms;
			જો (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				તોડો;
			} નહીંતર {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		જો (sock != -1)
			તોડો;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	જો (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		પાછા -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	જો (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	જો (ssh_packet_set_connection(ssh, sock, sock) == ખાલી)
		પાછા -1; /* ssh_packet_set_connection logs error */

	પાછા 0;
}

પૂર્ણાંક
ssh_connect(સંરચના ssh *ssh, અચલ અક્ષર *host, અચલ અક્ષર *host_arg,
    સંરચના addrinfo *addrs, સંરચના sockaddr_storage *hostaddr, u_short port,
    પૂર્ણાંક connection_attempts, પૂર્ણાંક *timeout_ms, પૂર્ણાંક want_keepalive)
{
	પૂર્ણાંક in, out;

	જો (options.proxy_command == ખાલી) {
		પાછા ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} નહીંતર જો (strcmp(options.proxy_command, "-") == 0) {
		જો ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			જો (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			પાછા -1; /* ssh_packet_set_connection logs error */
		}
		જો ((ssh_packet_set_connection(ssh, in, out)) == ખાલી)
			પાછા -1; /* ssh_packet_set_connection logs error */
		પાછા 0;
	} નહીંતર જો (options.proxy_use_fdpass) {
		પાછા ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	પાછા ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
સ્થિર પૂર્ણાંક
confirm(અચલ અક્ષર *prompt, અચલ અક્ષર *fingerprint)
{
	અચલ અક્ષર *સંદેશ, *again = "Please type 'yes' or 'no': ";
	અચલ અક્ષર *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	અક્ષર *p, *cp;
	પૂર્ણાંક ret = -1;

	જો (options.batch_mode)
		પાછા 0;
	માટે (સંદેશ = prompt;;સંદેશ = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(સંદેશ, RP_ECHO);
		જો (p == ખાલી)
			પાછા 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		જો (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		નહીંતર જો (strcasecmp(p, "yes") == 0 || (fingerprint != ખાલી &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		મુક્ત(cp);
		જો (ret != -1)
			પાછા ret;
	}
}

સ્થિર પૂર્ણાંક
sockaddr_is_local(સંરચના sockaddr *hostaddr)
{
	પસંદગી (hostaddr->sa_family) {
	સ્થિતિ AF_INET:
		પાછા (ntohl(((સંરચના sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	સ્થિતિ AF_INET6:
		પાછા IN6_IS_ADDR_LOOPBACK(
		    &(((સંરચના sockaddr_in6 *)hostaddr)->sin6_addr));
	મૂળભૂત:
		પાછા 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
શૂન્ય
get_hostfile_hostname_ipaddr(અક્ષર *hostname, સંરચના sockaddr *hostaddr,
    u_short port, અક્ષર **hostfile_hostname, અક્ષર **hostfile_ipaddr)
{
	અક્ષર ntop[NI_MAXHOST];
	socklen_t addrlen;

	પસંદગી (hostaddr == ખાલી ? -1 : hostaddr->sa_family) {
	સ્થિતિ -1:
		addrlen = 0;
		તોડો;
	સ્થિતિ AF_INET:
		addrlen = કદ(સંરચના sockaddr_in);
		તોડો;
	સ્થિતિ AF_INET6:
		addrlen = કદ(સંરચના sockaddr_in6);
		તોડો;
	મૂળભૂત:
		addrlen = કદ(સંરચના sockaddr);
		તોડો;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	જો (hostfile_ipaddr != ખાલી) {
		જો (options.proxy_command == ખાલી) {
			જો (getnameinfo(hostaddr, addrlen,
			    ntop, કદ(ntop), ખાલી, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} નહીંતર {
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
	જો (hostfile_hostname != ખાલી) {
		જો (options.host_ચાવી_alias != ખાલી) {
			*hostfile_hostname = xstrdup(options.host_ચાવી_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} નહીંતર {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
સ્થિર પૂર્ણાંક
path_in_hostfiles(અચલ અક્ષર *path, અક્ષર **hostfiles, u_int અંક_hostfiles)
{
	u_int i;

	માટે (i = 0; i < અંક_hostfiles; i++) {
		જો (strcmp(path, hostfiles[i]) == 0)
			પાછા 1;
	}
	પાછા 0;
}

સંરચના find_by_ચાવી_ctx {
	અચલ અક્ષર *host, *ip;
	અચલ સંરચના sshkey *ચાવી;
	અક્ષર **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
સ્થિર અક્ષર *
try_tilde_unexpand(અચલ અક્ષર *path)
{
	અક્ષર *home, *ret = ખાલી;
	size_t l;

	જો (*path != '/')
		પાછા xstrdup(path);
	જો ((home = getenv("HOME")) == ખાલી || (l = strlen(home)) == 0)
		પાછા xstrdup(path);
	જો (strncmp(path, home, l) != 0)
		પાછા xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	જો (home[l - 1] != '/' && path[l] != '/')
		પાછા xstrdup(path);
	જો (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	પાછા ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
પૂર્ણાંક
hostkey_accepted_by_hostkeyalgs(અચલ સંરચના sshkey *ચાવી)
{
	અચલ અક્ષર *ktype = sshkey_ssh_name(ચાવી);
	અચલ અક્ષર *hostkeyalgs = options.hostkeyalgorithms;

	જો (ચાવી->type == ચાવી_UNSPEC)
		પાછા 0;
	જો (ચાવી->type == ચાવી_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		પાછા 1;
	જો (ચાવી->type == ચાવી_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		પાછા 1;
	પાછા match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

સ્થિર પૂર્ણાંક
hostkeys_find_by_ચાવી_cb(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના find_by_ચાવી_ctx *ctx = (સંરચના find_by_ચાવી_ctx *)_ctx;
	અક્ષર *path;

	/* we are looking for keys with names that *do not* match */
	જો ((l->match & HKF_MATCH_HOST) != 0)
		પાછા 0;
	/* not interested in marker lines */
	જો (l->marker != MRK_NONE)
		પાછા 0;
	/* we are only interested in exact key matches */
	જો (l->ચાવી == ખાલી || !sshkey_equal(ctx->ચાવી, l->ચાવી))
		પાછા 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, કદ(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	મુક્ત(path);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
hostkeys_find_by_ચાવી_hostfile(અચલ અક્ષર *file, અચલ અક્ષર *which,
    સંરચના find_by_ચાવી_ctx *ctx)
{
	પૂર્ણાંક r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	જો ((r = hostkeys_foreach(file, hostkeys_find_by_ચાવી_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_ચાવી, 0)) != 0) {
		જો (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			પાછા 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		પાછા r;
	}
	પાછા 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
સ્થિર શૂન્ય
hostkeys_find_by_ચાવી(અચલ અક્ષર *host, અચલ અક્ષર *ip, અચલ સંરચના sshkey *ચાવી,
    અક્ષર **user_hostfiles, u_int અંક_user_hostfiles,
    અક્ષર **system_hostfiles, u_int અંક_system_hostfiles,
    અક્ષર ***names, u_int *nnames)
{
	સંરચના find_by_ચાવી_ctx ctx = {ખાલી, ખાલી, ખાલી, ખાલી, 0};
	u_int i;

	*names = ખાલી;
	*nnames = 0;

	જો (ચાવી == ખાલી || sshkey_is_cert(ચાવી))
		પાછા;

	ctx.host = host;
	ctx.ip = ip;
	ctx.ચાવી = ચાવી;

	માટે (i = 0; i < અંક_user_hostfiles; i++) {
		જો (hostkeys_find_by_ચાવી_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			જાઓ fail;
	}
	માટે (i = 0; i < અંક_system_hostfiles; i++) {
		જો (hostkeys_find_by_ચાવી_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			જાઓ fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = ખાલી;
	ctx.nnames = 0;
	પાછા;
 fail:
	માટે (i = 0; i < ctx.nnames; i++)
		મુક્ત(ctx.names[i]);
	મુક્ત(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
સ્થિર અક્ષર *
other_hostkeys_message(અચલ અક્ષર *host, અચલ અક્ષર *ip,
    અચલ સંરચના sshkey *ચાવી,
    અક્ષર **user_hostfiles, u_int અંક_user_hostfiles,
    અક્ષર **system_hostfiles, u_int અંક_system_hostfiles)
{
	અક્ષર *ret = ખાલી, **othernames = ખાલી;
	u_int i, n, અંક_othernames = 0;

	hostkeys_find_by_ચાવી(host, ip, ચાવી,
	    user_hostfiles, અંક_user_hostfiles,
	    system_hostfiles, અંક_system_hostfiles,
	    &othernames, &અંક_othernames);
	જો (અંક_othernames == 0)
		પાછા xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = અંક_othernames;
	જો (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	માટે (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	જો (n < અંક_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    અંક_othernames - n);
	}
	માટે (i = 0; i < અંક_othernames; i++)
		મુક્ત(othernames[i]);
	મુક્ત(othernames);
	પાછા ret;
}

શૂન્ય
load_hostkeys_command(સંરચના hostkeys *hostkeys, અચલ અક્ષર *command_template,
    અચલ અક્ષર *invocation, અચલ સંરચના ssh_conn_info *cinfo,
    અચલ સંરચના sshkey *host_ચાવી, અચલ અક્ષર *hostfile_hostname)
{
	પૂર્ણાંક r, i, ac = 0;
	અક્ષર *ચાવી_fp = ખાલી, *keytext = ખાલી, *tmp;
	અક્ષર *command = ખાલી, *tag = ખાલી, **av = ખાલી;
	FILE *f = ખાલી;
	pid_t pid;
	શૂન્ય (*osigchld)(પૂર્ણાંક);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	જો (host_ચાવી != ખાલી) {
		જો ((ચાવી_fp = sshkey_fingerprint(host_ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint failed");
		જો ((r = sshkey_to_base64(host_ચાવી, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	જો (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		જાઓ out;
	}
	જો (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		જાઓ out;
	}
	માટે (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_ચાવી == ખાલી ? "NONE" : sshkey_ssh_name(host_ચાવી),
		    "f", ચાવી_fp == ખાલી ? "NONE" : ચાવી_fp,
		    "K", keytext == ખાલી ? "NONE" : keytext,
		    (અક્ષર *)ખાલી);
		જો (tmp == ખાલી)
			fatal_f("percent_expand failed");
		મુક્ત(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	જો ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, ખાલી, ખાલી, ખાલી)) == 0)
		જાઓ out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	જો (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	જો (f != ખાલી)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	માટે (i = 0; i < ac; i++)
		મુક્ત(av[i]);
	મુક્ત(av);
	મુક્ત(tag);
	મુક્ત(command);
	મુક્ત(ચાવી_fp);
	મુક્ત(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
સ્થિર પૂર્ણાંક
check_host_ચાવી(અક્ષર *hostname, અચલ સંરચના ssh_conn_info *cinfo,
    સંરચના sockaddr *hostaddr, u_short port,
    સંરચના sshkey *host_ચાવી, પૂર્ણાંક readonly, પૂર્ણાંક clobber_port,
    અક્ષર **user_hostfiles, u_int અંક_user_hostfiles,
    અક્ષર **system_hostfiles, u_int અંક_system_hostfiles,
    અચલ અક્ષર *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	સંરચના sshkey *raw_ચાવી = ખાલી;
	અક્ષર *ip = ખાલી, *host = ખાલી;
	અક્ષર hostline[1000], *hostp, *fp, *ra;
	અક્ષર સંદેશ[1024];
	અચલ અક્ષર *type, *fail_reason = ખાલી;
	અચલ સંરચના hostkey_entry *host_found = ખાલી, *ip_found = ખાલી;
	પૂર્ણાંક len, cancelled_forwarding = 0, confirmed;
	પૂર્ણાંક local = sockaddr_is_local(hostaddr);
	પૂર્ણાંક r, want_cert = sshkey_is_cert(host_ચાવી), host_ip_differ = 0;
	પૂર્ણાંક hostkey_trusted = 0; /* Known or explicitly accepted by user */
	સંરચના hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	જો (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_ચાવી_alias == ખાલી) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		પાછા 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	જો (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	જો (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != ખાલી))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	માટે (i = 0; i < અંક_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	માટે (i = 0; i < અંક_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	જો (hostfile_command != ખાલી && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_ચાવી, host);
	}

	ip_hostkeys = ખાલી;
	જો (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		માટે (i = 0; i < અંક_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		માટે (i = 0; i < અંક_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		જો (hostfile_command != ખાલી && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_ચાવી, ip);
		}
	}

 retry:
	જો (!hostkey_accepted_by_hostkeyalgs(host_ચાવી)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_ચાવી));
		જાઓ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_ચાવી);
	type = sshkey_type(host_ચાવી);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_ચાવી_in_hostkeys(host_hostkeys, host_ચાવી,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	જો (!readonly && (અંક_user_hostfiles == 0 ||
	    (host_found != ખાલી && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	જો (!want_cert && ip_hostkeys != ખાલી) {
		ip_status = check_ચાવી_in_hostkeys(ip_hostkeys, host_ચાવી,
		    &ip_found);
		જો (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != ખાલી &&
		    !sshkey_equal(ip_found->ચાવી, host_found->ચાવી))))
			host_ip_differ = 1;
	} નહીંતર
		ip_status = host_status;

	પસંદગી (host_status) {
	સ્થિતિ HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->લીટી);
		જો (want_cert) {
			જો (sshkey_cert_check_host(host_ચાવી,
			    options.host_ચાવી_alias == ખાલી ?
			    hostname : options.host_ચાવી_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				જાઓ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			જો (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		જો (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, અંક_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != ખાલી &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, અંક_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		જો (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		જો (options.check_host_ip && ip_status == HOST_NEW) {
			જો (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			નહીંતર જો (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_ચાવી, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			નહીંતર
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} નહીંતર જો (options.visual_host_ચાવી) {
			fp = sshkey_fingerprint(host_ચાવી,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ચાવી,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			જો (fp == ખાલી || ra == ખાલી)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			મુક્ત(ra);
			મુક્ત(fp);
		}
		hostkey_trusted = 1;
		તોડો;
	સ્થિતિ HOST_NEW:
		જો (options.host_ચાવી_alias == ખાલી && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			જો (check_host_ચાવી(hostname, cinfo, hostaddr, 0,
			    host_ચાવી, ROQUIET, 1,
			    user_hostfiles, અંક_user_hostfiles,
			    system_hostfiles, અંક_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				તોડો;
			}
		}
		જો (readonly || want_cert)
			જાઓ fail;
		/* The host is new. */
		જો (options.strict_host_ચાવી_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			જાઓ fail;
		} નહીંતર જો (options.strict_host_ચાવી_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			અક્ષર *msg1 = ખાલી, *msg2 = ખાલી;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			જો (show_other_ચાવીઓ(host_hostkeys, host_ચાવી)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} નહીંતર
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_ચાવી,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_ચાવી,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			જો (fp == ખાલી || ra == ખાલી)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			જો (options.visual_host_ચાવી)
				xextendf(&msg1, "\n", "%s", ra);
			જો (options.verify_host_ચાવી_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_ચાવી_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			જો ((msg2 = other_hostkeys_message(host, ip, host_ચાવી,
			    user_hostfiles, અંક_user_hostfiles,
			    system_hostfiles, અંક_system_hostfiles)) != ખાલી)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			મુક્ત(ra);
			મુક્ત(fp);
			મુક્ત(msg1);
			મુક્ત(msg2);
			જો (!confirmed)
				જાઓ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		જો (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, કદ(hostline), "%s,%s", host, ip);
			hostp = hostline;
			જો (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_ચાવી, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_ચાવી, options.hash_known_hosts);
			} નહીંતર {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_ચાવી,
				    options.hash_known_hosts);
			}
		} નહીંતર {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_ચાવી, options.hash_known_hosts);
			hostp = host;
		}

		જો (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		નહીંતર
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		તોડો;
	સ્થિતિ HOST_REVOKED:
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
		જો (options.strict_host_ચાવી_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			જાઓ fail;
		}
		જાઓ continue_unsafe;

	સ્થિતિ HOST_CHANGED:
		જો (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->લીટી);
			જાઓ fail;
		}
		જો (readonly == ROQUIET)
			જાઓ fail;
		જો (options.check_host_ip && host_ip_differ) {
			અક્ષર *ચાવી_સંદેશ;
			જો (ip_status == HOST_NEW)
				ચાવી_સંદેશ = "is unknown";
			નહીંતર જો (ip_status == HOST_OK)
				ચાવી_સંદેશ = "is unchanged";
			નહીંતર
				ચાવી_સંદેશ = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", ચાવી_સંદેશ);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			જો (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->લીટી);
		}
		/* The host key has changed. */
		warn_changed_ચાવી(host_ચાવી);
		જો (અંક_user_hostfiles > 0 || અંક_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", અંક_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->ચાવી),
		    host_found->file, host_found->લીટી);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		જો (options.strict_host_ચાવી_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			જાઓ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		જો (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		જો (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		જો (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		જો (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		જો (options.અંક_local_forwards > 0 ||
		    options.અંક_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.અંક_local_forwards =
			    options.અંક_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		જો (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		જો (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		જો (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		તોડો;
	સ્થિતિ HOST_FOUND:
		fatal("internal error");
		તોડો;
	}

	જો (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(સંદેશ, કદ(સંદેશ),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->લીટી);
		જો (host_status == HOST_OK) {
			len = strlen(સંદેશ);
			snprintf(સંદેશ + len, કદ(સંદેશ) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->લીટી);
		}
		જો (options.strict_host_ચાવી_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(સંદેશ, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", કદ(સંદેશ));
			જો (!confirm(સંદેશ, ખાલી))
				જાઓ fail;
		} નહીંતર જો (options.strict_host_ચાવી_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", સંદેશ);
			error("Exiting, you have requested strict checking.");
			જાઓ fail;
		} નહીંતર {
			logit("%s", સંદેશ);
		}
	}

	જો (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_ચાવી);
	મુક્ત(ip);
	મુક્ત(host);
	જો (host_hostkeys != ખાલી)
		free_hostkeys(host_hostkeys);
	જો (ip_hostkeys != ખાલી)
		free_hostkeys(ip_hostkeys);
	પાછા 0;

fail:
	જો (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		જો ((r = sshkey_from_private(host_ચાવી, &raw_ચાવી)) != 0)
			fatal_fr(r, "decode key");
		જો ((r = sshkey_drop_cert(raw_ચાવી)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_ચાવી = raw_ચાવી;
		જાઓ retry;
	}
	sshkey_free(raw_ચાવી);
	મુક્ત(ip);
	મુક્ત(host);
	જો (host_hostkeys != ખાલી)
		free_hostkeys(host_hostkeys);
	જો (ip_hostkeys != ખાલી)
		free_hostkeys(ip_hostkeys);
	પાછા -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
પૂર્ણાંક
verify_host_ચાવી(અક્ષર *host, સંરચના sockaddr *hostaddr, સંરચના sshkey *host_ચાવી,
    અચલ સંરચના ssh_conn_info *cinfo)
{
	u_int i;
	પૂર્ણાંક r = -1, flags = 0;
	અક્ષર valid[64], *fp = ખાલી, *cafp = ખાલી;
	સંરચના sshkey *plain = ખાલી;

	જો ((fp = sshkey_fingerprint(host_ચાવી,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી) {
		error_fr(r, "fingerprint host key");
		r = -1;
		જાઓ out;
	}

	જો (sshkey_is_cert(host_ચાવી)) {
		જો ((cafp = sshkey_fingerprint(host_ચાવી->cert->signature_ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			જાઓ out;
		}
		sshkey_format_cert_validity(host_ચાવી->cert,
		    valid, કદ(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_ચાવી), fp,
		    (unsigned long long)host_ચાવી->cert->serial,
		    host_ચાવી->cert->ચાવી_id,
		    sshkey_ssh_name(host_ચાવી->cert->signature_ચાવી), cafp,
		    valid);
		માટે (i = 0; i < host_ચાવી->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_ચાવી->cert->principals[i]);
		}
	} નહીંતર {
		debug("Server host key: %s %s", sshkey_ssh_name(host_ચાવી), fp);
	}

	જો (sshkey_equal(previous_host_ચાવી, host_ચાવી)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_ચાવી), fp);
		r = 0;
		જાઓ out;
	}

	/* Check in RevokedHostKeys files if specified */
	માટે (i = 0; i < options.અંક_revoked_host_ચાવીઓ; i++) {
		r = sshkey_check_revoked(host_ચાવી,
		    options.revoked_host_ચાવીઓ[i]);
		પસંદગી (r) {
		સ્થિતિ 0:
			તોડો; /* not revoked */
		સ્થિતિ SSH_ERR_ચાવી_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_ચાવી), fp,
			    options.revoked_host_ચાવીઓ[i]);
			r = -1;
			જાઓ out;
		મૂળભૂત:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_ચાવી),
			    fp, options.revoked_host_ચાવીઓ[i]);
			r = -1;
			જાઓ out;
		}
	}

	જો (options.verify_host_ચાવી_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		જો ((r = sshkey_from_private(host_ચાવી, &plain)) != 0)
			જાઓ out;
		જો (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		જો (verify_host_ચાવી_dns(host, hostaddr, plain, &flags) == 0) {
			જો (flags & DNS_VERIFY_FOUND) {
				જો (options.verify_host_ચાવી_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					જાઓ out;
				}
				જો (flags & DNS_VERIFY_MATCH) {
					matching_host_ચાવી_dns = 1;
				} નહીંતર {
					warn_changed_ચાવી(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_ચાવી(host, cinfo, hostaddr, options.port, host_ચાવી,
	    RDRW, 0, options.user_hostfiles, options.અંક_user_hostfiles,
	    options.system_hostfiles, options.અંક_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	મુક્ત(fp);
	મુક્ત(cafp);
	જો (r == 0 && host_ચાવી != ખાલી) {
		sshkey_free(previous_host_ચાવી);
		r = sshkey_from_private(host_ચાવી, &previous_host_ચાવી);
	}

	પાછા r;
}

સ્થિર શૂન્ય
warn_nonpq_kex(શૂન્ય)
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
શૂન્ય
ssh_login(સંરચના ssh *ssh, Sensitive *sensitive, અચલ અક્ષર *orighost,
    સંરચના sockaddr_storage *hostaddr, u_short port, સંરચના passwd *pw,
    પૂર્ણાંક timeout_ms, અચલ સંરચના ssh_conn_info *cinfo)
{
	અક્ષર *host;
	અક્ષર *server_user, *local_user;
	પૂર્ણાંક r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	જો ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	જો ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	જો (!options.kex_algorithms_set && ssh->kex != ખાલી &&
	    ssh->kex->name != ખાલી && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	મુક્ત(local_user);
	મુક્ત(host);
}

/* print all known host keys for a given host, but skip keys of given type */
સ્થિર પૂર્ણાંક
show_other_ચાવીઓ(સંરચના hostkeys *hostkeys, સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક type[] = {
		ચાવી_RSA,
		ચાવી_ECDSA,
		ચાવી_ED25519,
		ચાવી_MLDSA44_ED25519,
		-1
	};
	પૂર્ણાંક i, ret = 0;
	અક્ષર *fp, *ra;
	અચલ સંરચના hostkey_entry *found;

	માટે (i = 0; type[i] != -1; i++) {
		જો (type[i] == ચાવી->type)
			ચાલુ;
		જો (!lookup_ચાવી_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			ચાલુ;
		fp = sshkey_fingerprint(found->ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->ચાવી,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		જો (fp == ખાલી || ra == ખાલી)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->ચાવી),
		    found->host, found->file, found->લીટી,
		    sshkey_type(found->ચાવી), fp);
		જો (options.visual_host_ચાવી)
			logit("%s", ra);
		મુક્ત(ra);
		મુક્ત(fp);
		ret = 1;
	}
	પાછા ret;
}

સ્થિર શૂન્ય
warn_changed_ચાવી(સંરચના sshkey *host_ચાવી)
{
	અક્ષર *fp;

	fp = sshkey_fingerprint(host_ચાવી, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	જો (fp == ખાલી)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_ચાવી), fp);
	error("Please contact your system administrator.");

	મુક્ત(fp);
}

/*
 * Execute a local command
 */
પૂર્ણાંક
ssh_local_cmd(અચલ અક્ષર *args)
{
	અક્ષર *shell;
	pid_t pid;
	પૂર્ણાંક status;
	શૂન્ય (*osighand)(પૂર્ણાંક);

	જો (!options.permit_local_command ||
	    args == ખાલી || !*args)
		પાછા (1);

	જો ((shell = getenv("SHELL")) == ખાલી || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	જો (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (અક્ષર *)ખાલી);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} નહીંતર જો (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	જ્યારે (waitpid(pid, &status, 0) == -1)
		જો (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	જો (!WIFEXITED(status))
		પાછા (1);

	પાછા (WEXITSTATUS(status));
}

શૂન્ય
maybe_add_ચાવી_to_agent(અચલ અક્ષર *authfile, સંરચના sshkey *ખાનગી,
    અચલ અક્ષર *comment, અચલ અક્ષર *passphrase)
{
	પૂર્ણાંક auth_sock = -1, r;
	અચલ અક્ષર *skprovider = ખાલી;

	જો (options.add_ચાવીઓ_to_agent == 0)
		પાછા;

	જો ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		પાછા;
	}

	જો (options.add_ચાવીઓ_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		પાછા;
	}
	જો (sshkey_is_sk(ખાનગી))
		skprovider = options.sk_provider;
	જો ((r = ssh_add_identity_constrained(auth_sock, ખાનગી,
	    comment == ખાલી ? authfile : comment,
	    options.add_ચાવીઓ_to_agent_lifespan,
	    (options.add_ચાવીઓ_to_agent == 3), skprovider, ખાલી, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	નહીંતર
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
