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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <net/if.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <ifaddrs.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshconnect.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "dns.h"
#அந்தர்பாவ "monitor_fdpass.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "kex.h"

கட்டமைப்பு sshkey *previous_host_சாவி = வெற்று;

நிலையான முழு matching_host_சாவி_dns = 0;

நிலையான pid_t proxy_command_pid = 0;

/* import */
வெளி முழு debug_flag;
வெளி Options options;
வெளி எழுத்து *__progname;

நிலையான முழு show_other_சாவிகள்(கட்டமைப்பு hostkeys *, கட்டமைப்பு sshkey *);
நிலையான வெறுமை warn_changed_சாவி(கட்டமைப்பு sshkey *);

வெறுமை
ssh_conn_info_free(கட்டமைப்பு ssh_conn_info *cinfo)
{
	எனில் (cinfo == வெற்று)
		திரும்பு;
	விடுவி(cinfo->conn_hash_hex);
	விடுவி(cinfo->shorthost);
	விடுவி(cinfo->uidstr);
	விடுவி(cinfo->keyalias);
	விடுவி(cinfo->thishost);
	விடுவி(cinfo->host_arg);
	விடுவி(cinfo->portstr);
	விடுவி(cinfo->remhost);
	விடுவி(cinfo->remuser);
	விடுவி(cinfo->homedir);
	விடுவி(cinfo->locuser);
	விடுவி(cinfo->jmphost);
	freezero(cinfo, அளவு(*cinfo));
}

கட்டமைப்பு ssh_conn_info *
ssh_conn_info_dup(மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	கட்டமைப்பு ssh_conn_info *ret;

	எனில் (cinfo == வெற்று)
		திரும்பு வெற்று;
	ret = xcalloc(1, அளவு(*ret));
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
	திரும்பு ret;
}

/* Expand a proxy command */
நிலையான எழுத்து *
expand_proxy_command(மாறிலி எழுத்து *proxy_command, மாறிலி எழுத்து *user,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *host_arg, முழு port)
{
	எழுத்து *tmp, *ret, strport[NI_MAXSERV];
	மாறிலி எழுத்து *keyalias = options.host_சாவி_alias ?
	    options.host_சாவி_alias : host_arg;

	snprintf(strport, அளவு strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (எழுத்து *)வெற்று);
	விடுவி(tmp);
	திரும்பு ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
நிலையான முழு
ssh_proxy_fdpass_connect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *host_arg, u_short port, மாறிலி எழுத்து *proxy_command)
{
	எழுத்து *command_string;
	முழு sp[2], sock;
	pid_t pid;
	எழுத்து *shell;

	எனில் ((shell = getenv("SHELL")) == வெற்று)
		shell = _PATH_BSHELL;

	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	எனில் ((pid = fork()) == 0) {
		எழுத்து *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		எனில் (sp[0] != 0) {
			எனில் (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		எனில் (sp[0] != 1) {
			எனில் (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		எனில் (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		எனில் (!debug_flag && options.control_path != வெற்று &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = வெற்று;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	எனில் (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	விடுவி(command_string);

	எனில் ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	போது (waitpid(pid, வெற்று, 0) == -1)
		எனில் (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	எனில் (ssh_packet_set_connection(ssh, sock, sock) == வெற்று)
		திரும்பு -1; /* ssh_packet_set_connection logs error */

	திரும்பு 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
நிலையான முழு
ssh_proxy_connect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host, மாறிலி எழுத்து *host_arg,
    u_short port, மாறிலி எழுத்து *proxy_command)
{
	எழுத்து *command_string;
	முழு pin[2], pout[2];
	pid_t pid;
	எழுத்து *shell;

	எனில் ((shell = getenv("SHELL")) == வெற்று || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	எனில் (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	எனில் ((pid = fork()) == 0) {
		எழுத்து *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		எனில் (pin[0] != 0) {
			எனில் (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		எனில் (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		எனில் (!debug_flag && options.control_path != வெற்று &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = வெற்று;

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
	எனில் (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	இல்லையெனில்
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	விடுவி(command_string);

	/* Set the connection file descriptors. */
	எனில் (ssh_packet_set_connection(ssh, pout[0], pin[1]) == வெற்று)
		திரும்பு -1; /* ssh_packet_set_connection logs error */

	திரும்பு 0;
}

வெறுமை
ssh_kill_proxy_command(வெறுமை)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	எனில் (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
நிலையான முழு
check_ifaddrs(மாறிலி எழுத்து *ifname, முழு af, மாறிலி கட்டமைப்பு ifaddrs *ifaddrs,
    கட்டமைப்பு sockaddr_storage *resultp, socklen_t *rlenp)
{
	கட்டமைப்பு sockaddr_in6 *sa6;
	கட்டமைப்பு sockaddr_in *sa;
	கட்டமைப்பு in6_addr *v6addr;
	மாறிலி கட்டமைப்பு ifaddrs *ifa;
	முழு allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	க்கு (allow_local = 0; allow_local < 2; allow_local++) {
		க்கு (ifa = ifaddrs; ifa != வெற்று; ifa = ifa->ifa_next) {
			எனில் (ifa->ifa_addr == வெற்று || ifa->ifa_name == வெற்று ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				தொடர்;
			தேர்வு (ifa->ifa_addr->sa_family) {
			நிலை AF_INET:
				sa = (கட்டமைப்பு sockaddr_in *)ifa->ifa_addr;
				எனில் (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					தொடர்;
				எனில் (*rlenp < அளவு(கட்டமைப்பு sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					திரும்பு -1;
				}
				*rlenp = அளவு(கட்டமைப்பு sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				திரும்பு 0;
			நிலை AF_INET6:
				sa6 = (கட்டமைப்பு sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				எனில் (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					தொடர்;
				எனில் (*rlenp < அளவு(கட்டமைப்பு sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					திரும்பு -1;
				}
				*rlenp = அளவு(கட்டமைப்பு sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				திரும்பு 0;
			}
		}
	}
	திரும்பு -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
நிலையான முழு
ssh_create_socket(கட்டமைப்பு addrinfo *ai)
{
	முழு sock, r;
	கட்டமைப்பு sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	கட்டமைப்பு addrinfo hints, *res = வெற்று;
#ifdef HAVE_IFADDRS_H
	கட்டமைப்பு ifaddrs *ifaddrs = வெற்று;
#endif
	எழுத்து ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	எனில் (sock == -1) {
		error("socket: %s", strerror(errno));
		திரும்பு -1;
	}
	(வெறுமை)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	எனில் (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	எனில் (options.bind_address == வெற்று && options.bind_interface == வெற்று)
		திரும்பு sock;

	எனில் (options.bind_address != வெற்று) {
		memset(&hints, 0, அளவு(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		எனில் ((r = getaddrinfo(options.bind_address, வெற்று,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			செல் fail;
		}
		எனில் (res == வெற்று) {
			error("getaddrinfo: no addrs");
			செல் fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} இல்லையெனில் எனில் (options.bind_interface != வெற்று) {
#ifdef HAVE_IFADDRS_H
		எனில் ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			செல் fail;
		}
		bindaddrlen = அளவு(bindaddr);
		எனில் (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			செல் fail;
		}
#இல்லையெனில்
		error("BindInterface not supported on this platform.");
#endif
	}
	எனில் ((r = getnameinfo((கட்டமைப்பு sockaddr *)&bindaddr, bindaddrlen,
	    ntop, அளவு(ntop), வெற்று, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		செல் fail;
	}
	எனில் (bind(sock, (கட்டமைப்பு sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		செல் fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	செல் out;
fail:
	close(sock);
	sock = -1;
 out:
	எனில் (res != வெற்று)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	எனில் (ifaddrs != வெற்று)
		freeifaddrs(ifaddrs);
#endif
	திரும்பு sock;
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
நிலையான முழு
ssh_connect_direct(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host, கட்டமைப்பு addrinfo *aitop,
    கட்டமைப்பு sockaddr_storage *hostaddr, u_short port, முழு connection_attempts,
    முழு *timeout_ms, முழு want_keepalive)
{
	முழு saved_timeout_ms = *timeout_ms;
	முழு oerrno, sock = -1, attempt;
	எழுத்து ntop[NI_MAXHOST], strport[NI_MAXSERV];
	கட்டமைப்பு addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, அளவு(ntop));
	memset(strport, 0, அளவு(strport));

	க்கு (attempt = 0; attempt < connection_attempts; attempt++) {
		எனில் (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		க்கு (ai = aitop; ai; ai = ai->ai_next) {
			எனில் (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				தொடர்;
			}
			எனில் (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, அளவு(ntop), strport, அளவு(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				தொடர்;
			}
			எனில் (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				தொடர்;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			எனில் (sock < 0) {
				/* Any error is already output */
				errno = 0;
				தொடர்;
			}

			*timeout_ms = saved_timeout_ms;
			எனில் (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				நிறுத்து;
			} இல்லையெனில் {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		எனில் (sock != -1)
			நிறுத்து;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	எனில் (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		திரும்பு -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	எனில் (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	எனில் (ssh_packet_set_connection(ssh, sock, sock) == வெற்று)
		திரும்பு -1; /* ssh_packet_set_connection logs error */

	திரும்பு 0;
}

முழு
ssh_connect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host, மாறிலி எழுத்து *host_arg,
    கட்டமைப்பு addrinfo *addrs, கட்டமைப்பு sockaddr_storage *hostaddr, u_short port,
    முழு connection_attempts, முழு *timeout_ms, முழு want_keepalive)
{
	முழு in, out;

	எனில் (options.proxy_command == வெற்று) {
		திரும்பு ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} இல்லையெனில் எனில் (strcmp(options.proxy_command, "-") == 0) {
		எனில் ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			எனில் (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			திரும்பு -1; /* ssh_packet_set_connection logs error */
		}
		எனில் ((ssh_packet_set_connection(ssh, in, out)) == வெற்று)
			திரும்பு -1; /* ssh_packet_set_connection logs error */
		திரும்பு 0;
	} இல்லையெனில் எனில் (options.proxy_use_fdpass) {
		திரும்பு ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	திரும்பு ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
நிலையான முழு
confirm(மாறிலி எழுத்து *prompt, மாறிலி எழுத்து *fingerprint)
{
	மாறிலி எழுத்து *செய்தி, *again = "Please type 'yes' or 'no': ";
	மாறிலி எழுத்து *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	எழுத்து *p, *cp;
	முழு ret = -1;

	எனில் (options.batch_mode)
		திரும்பு 0;
	க்கு (செய்தி = prompt;;செய்தி = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(செய்தி, RP_ECHO);
		எனில் (p == வெற்று)
			திரும்பு 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		எனில் (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		இல்லையெனில் எனில் (strcasecmp(p, "yes") == 0 || (fingerprint != வெற்று &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		விடுவி(cp);
		எனில் (ret != -1)
			திரும்பு ret;
	}
}

நிலையான முழு
sockaddr_is_local(கட்டமைப்பு sockaddr *hostaddr)
{
	தேர்வு (hostaddr->sa_family) {
	நிலை AF_INET:
		திரும்பு (ntohl(((கட்டமைப்பு sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	நிலை AF_INET6:
		திரும்பு IN6_IS_ADDR_LOOPBACK(
		    &(((கட்டமைப்பு sockaddr_in6 *)hostaddr)->sin6_addr));
	இயல்பு:
		திரும்பு 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
வெறுமை
get_hostfile_hostname_ipaddr(எழுத்து *hostname, கட்டமைப்பு sockaddr *hostaddr,
    u_short port, எழுத்து **hostfile_hostname, எழுத்து **hostfile_ipaddr)
{
	எழுத்து ntop[NI_MAXHOST];
	socklen_t addrlen;

	தேர்வு (hostaddr == வெற்று ? -1 : hostaddr->sa_family) {
	நிலை -1:
		addrlen = 0;
		நிறுத்து;
	நிலை AF_INET:
		addrlen = அளவு(கட்டமைப்பு sockaddr_in);
		நிறுத்து;
	நிலை AF_INET6:
		addrlen = அளவு(கட்டமைப்பு sockaddr_in6);
		நிறுத்து;
	இயல்பு:
		addrlen = அளவு(கட்டமைப்பு sockaddr);
		நிறுத்து;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	எனில் (hostfile_ipaddr != வெற்று) {
		எனில் (options.proxy_command == வெற்று) {
			எனில் (getnameinfo(hostaddr, addrlen,
			    ntop, அளவு(ntop), வெற்று, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} இல்லையெனில் {
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
	எனில் (hostfile_hostname != வெற்று) {
		எனில் (options.host_சாவி_alias != வெற்று) {
			*hostfile_hostname = xstrdup(options.host_சாவி_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} இல்லையெனில் {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
நிலையான முழு
path_in_hostfiles(மாறிலி எழுத்து *path, எழுத்து **hostfiles, u_int இலக்கம்_hostfiles)
{
	u_int i;

	க்கு (i = 0; i < இலக்கம்_hostfiles; i++) {
		எனில் (strcmp(path, hostfiles[i]) == 0)
			திரும்பு 1;
	}
	திரும்பு 0;
}

கட்டமைப்பு find_by_சாவி_ctx {
	மாறிலி எழுத்து *host, *ip;
	மாறிலி கட்டமைப்பு sshkey *சாவி;
	எழுத்து **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
நிலையான எழுத்து *
try_tilde_unexpand(மாறிலி எழுத்து *path)
{
	எழுத்து *home, *ret = வெற்று;
	size_t l;

	எனில் (*path != '/')
		திரும்பு xstrdup(path);
	எனில் ((home = getenv("HOME")) == வெற்று || (l = strlen(home)) == 0)
		திரும்பு xstrdup(path);
	எனில் (strncmp(path, home, l) != 0)
		திரும்பு xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	எனில் (home[l - 1] != '/' && path[l] != '/')
		திரும்பு xstrdup(path);
	எனில் (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	திரும்பு ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
முழு
hostkey_accepted_by_hostkeyalgs(மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	மாறிலி எழுத்து *ktype = sshkey_ssh_name(சாவி);
	மாறிலி எழுத்து *hostkeyalgs = options.hostkeyalgorithms;

	எனில் (சாவி->type == சாவி_UNSPEC)
		திரும்பு 0;
	எனில் (சாவி->type == சாவி_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		திரும்பு 1;
	எனில் (சாவி->type == சாவி_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		திரும்பு 1;
	திரும்பு match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

நிலையான முழு
hostkeys_find_by_சாவி_cb(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு find_by_சாவி_ctx *ctx = (கட்டமைப்பு find_by_சாவி_ctx *)_ctx;
	எழுத்து *path;

	/* we are looking for keys with names that *do not* match */
	எனில் ((l->match & HKF_MATCH_HOST) != 0)
		திரும்பு 0;
	/* not interested in marker lines */
	எனில் (l->marker != MRK_NONE)
		திரும்பு 0;
	/* we are only interested in exact key matches */
	எனில் (l->சாவி == வெற்று || !sshkey_equal(ctx->சாவி, l->சாவி))
		திரும்பு 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, அளவு(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	விடுவி(path);
	திரும்பு 0;
}

நிலையான முழு
hostkeys_find_by_சாவி_hostfile(மாறிலி எழுத்து *file, மாறிலி எழுத்து *which,
    கட்டமைப்பு find_by_சாவி_ctx *ctx)
{
	முழு r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	எனில் ((r = hostkeys_foreach(file, hostkeys_find_by_சாவி_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_சாவி, 0)) != 0) {
		எனில் (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			திரும்பு 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		திரும்பு r;
	}
	திரும்பு 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
நிலையான வெறுமை
hostkeys_find_by_சாவி(மாறிலி எழுத்து *host, மாறிலி எழுத்து *ip, மாறிலி கட்டமைப்பு sshkey *சாவி,
    எழுத்து **user_hostfiles, u_int இலக்கம்_user_hostfiles,
    எழுத்து **system_hostfiles, u_int இலக்கம்_system_hostfiles,
    எழுத்து ***names, u_int *nnames)
{
	கட்டமைப்பு find_by_சாவி_ctx ctx = {வெற்று, வெற்று, வெற்று, வெற்று, 0};
	u_int i;

	*names = வெற்று;
	*nnames = 0;

	எனில் (சாவி == வெற்று || sshkey_is_cert(சாவி))
		திரும்பு;

	ctx.host = host;
	ctx.ip = ip;
	ctx.சாவி = சாவி;

	க்கு (i = 0; i < இலக்கம்_user_hostfiles; i++) {
		எனில் (hostkeys_find_by_சாவி_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			செல் fail;
	}
	க்கு (i = 0; i < இலக்கம்_system_hostfiles; i++) {
		எனில் (hostkeys_find_by_சாவி_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			செல் fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = வெற்று;
	ctx.nnames = 0;
	திரும்பு;
 fail:
	க்கு (i = 0; i < ctx.nnames; i++)
		விடுவி(ctx.names[i]);
	விடுவி(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
நிலையான எழுத்து *
other_hostkeys_message(மாறிலி எழுத்து *host, மாறிலி எழுத்து *ip,
    மாறிலி கட்டமைப்பு sshkey *சாவி,
    எழுத்து **user_hostfiles, u_int இலக்கம்_user_hostfiles,
    எழுத்து **system_hostfiles, u_int இலக்கம்_system_hostfiles)
{
	எழுத்து *ret = வெற்று, **othernames = வெற்று;
	u_int i, n, இலக்கம்_othernames = 0;

	hostkeys_find_by_சாவி(host, ip, சாவி,
	    user_hostfiles, இலக்கம்_user_hostfiles,
	    system_hostfiles, இலக்கம்_system_hostfiles,
	    &othernames, &இலக்கம்_othernames);
	எனில் (இலக்கம்_othernames == 0)
		திரும்பு xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = இலக்கம்_othernames;
	எனில் (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	க்கு (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	எனில் (n < இலக்கம்_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    இலக்கம்_othernames - n);
	}
	க்கு (i = 0; i < இலக்கம்_othernames; i++)
		விடுவி(othernames[i]);
	விடுவி(othernames);
	திரும்பு ret;
}

வெறுமை
load_hostkeys_command(கட்டமைப்பு hostkeys *hostkeys, மாறிலி எழுத்து *command_template,
    மாறிலி எழுத்து *invocation, மாறிலி கட்டமைப்பு ssh_conn_info *cinfo,
    மாறிலி கட்டமைப்பு sshkey *host_சாவி, மாறிலி எழுத்து *hostfile_hostname)
{
	முழு r, i, ac = 0;
	எழுத்து *சாவி_fp = வெற்று, *keytext = வெற்று, *tmp;
	எழுத்து *command = வெற்று, *tag = வெற்று, **av = வெற்று;
	FILE *f = வெற்று;
	pid_t pid;
	வெறுமை (*osigchld)(முழு);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	எனில் (host_சாவி != வெற்று) {
		எனில் ((சாவி_fp = sshkey_fingerprint(host_சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint failed");
		எனில் ((r = sshkey_to_base64(host_சாவி, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	எனில் (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		செல் out;
	}
	எனில் (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		செல் out;
	}
	க்கு (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_சாவி == வெற்று ? "NONE" : sshkey_ssh_name(host_சாவி),
		    "f", சாவி_fp == வெற்று ? "NONE" : சாவி_fp,
		    "K", keytext == வெற்று ? "NONE" : keytext,
		    (எழுத்து *)வெற்று);
		எனில் (tmp == வெற்று)
			fatal_f("percent_expand failed");
		விடுவி(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	எனில் ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, வெற்று, வெற்று, வெற்று)) == 0)
		செல் out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	எனில் (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	எனில் (f != வெற்று)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	க்கு (i = 0; i < ac; i++)
		விடுவி(av[i]);
	விடுவி(av);
	விடுவி(tag);
	விடுவி(command);
	விடுவி(சாவி_fp);
	விடுவி(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
நிலையான முழு
check_host_சாவி(எழுத்து *hostname, மாறிலி கட்டமைப்பு ssh_conn_info *cinfo,
    கட்டமைப்பு sockaddr *hostaddr, u_short port,
    கட்டமைப்பு sshkey *host_சாவி, முழு readonly, முழு clobber_port,
    எழுத்து **user_hostfiles, u_int இலக்கம்_user_hostfiles,
    எழுத்து **system_hostfiles, u_int இலக்கம்_system_hostfiles,
    மாறிலி எழுத்து *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	கட்டமைப்பு sshkey *raw_சாவி = வெற்று;
	எழுத்து *ip = வெற்று, *host = வெற்று;
	எழுத்து hostline[1000], *hostp, *fp, *ra;
	எழுத்து செய்தி[1024];
	மாறிலி எழுத்து *type, *fail_reason = வெற்று;
	மாறிலி கட்டமைப்பு hostkey_entry *host_found = வெற்று, *ip_found = வெற்று;
	முழு len, cancelled_forwarding = 0, confirmed;
	முழு local = sockaddr_is_local(hostaddr);
	முழு r, want_cert = sshkey_is_cert(host_சாவி), host_ip_differ = 0;
	முழு hostkey_trusted = 0; /* Known or explicitly accepted by user */
	கட்டமைப்பு hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	எனில் (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_சாவி_alias == வெற்று) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		திரும்பு 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	எனில் (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	எனில் (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != வெற்று))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	க்கு (i = 0; i < இலக்கம்_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	க்கு (i = 0; i < இலக்கம்_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	எனில் (hostfile_command != வெற்று && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_சாவி, host);
	}

	ip_hostkeys = வெற்று;
	எனில் (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		க்கு (i = 0; i < இலக்கம்_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		க்கு (i = 0; i < இலக்கம்_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		எனில் (hostfile_command != வெற்று && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_சாவி, ip);
		}
	}

 retry:
	எனில் (!hostkey_accepted_by_hostkeyalgs(host_சாவி)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_சாவி));
		செல் fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_சாவி);
	type = sshkey_type(host_சாவி);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_சாவி_in_hostkeys(host_hostkeys, host_சாவி,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	எனில் (!readonly && (இலக்கம்_user_hostfiles == 0 ||
	    (host_found != வெற்று && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	எனில் (!want_cert && ip_hostkeys != வெற்று) {
		ip_status = check_சாவி_in_hostkeys(ip_hostkeys, host_சாவி,
		    &ip_found);
		எனில் (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != வெற்று &&
		    !sshkey_equal(ip_found->சாவி, host_found->சாவி))))
			host_ip_differ = 1;
	} இல்லையெனில்
		ip_status = host_status;

	தேர்வு (host_status) {
	நிலை HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->வரி);
		எனில் (want_cert) {
			எனில் (sshkey_cert_check_host(host_சாவி,
			    options.host_சாவி_alias == வெற்று ?
			    hostname : options.host_சாவி_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				செல் fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			எனில் (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		எனில் (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, இலக்கம்_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != வெற்று &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, இலக்கம்_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		எனில் (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		எனில் (options.check_host_ip && ip_status == HOST_NEW) {
			எனில் (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			இல்லையெனில் எனில் (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_சாவி, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			இல்லையெனில்
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} இல்லையெனில் எனில் (options.visual_host_சாவி) {
			fp = sshkey_fingerprint(host_சாவி,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_சாவி,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			எனில் (fp == வெற்று || ra == வெற்று)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			விடுவி(ra);
			விடுவி(fp);
		}
		hostkey_trusted = 1;
		நிறுத்து;
	நிலை HOST_NEW:
		எனில் (options.host_சாவி_alias == வெற்று && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			எனில் (check_host_சாவி(hostname, cinfo, hostaddr, 0,
			    host_சாவி, ROQUIET, 1,
			    user_hostfiles, இலக்கம்_user_hostfiles,
			    system_hostfiles, இலக்கம்_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				நிறுத்து;
			}
		}
		எனில் (readonly || want_cert)
			செல் fail;
		/* The host is new. */
		எனில் (options.strict_host_சாவி_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			செல் fail;
		} இல்லையெனில் எனில் (options.strict_host_சாவி_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			எழுத்து *msg1 = வெற்று, *msg2 = வெற்று;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			எனில் (show_other_சாவிகள்(host_hostkeys, host_சாவி)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} இல்லையெனில்
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_சாவி,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_சாவி,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			எனில் (fp == வெற்று || ra == வெற்று)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			எனில் (options.visual_host_சாவி)
				xextendf(&msg1, "\n", "%s", ra);
			எனில் (options.verify_host_சாவி_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_சாவி_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			எனில் ((msg2 = other_hostkeys_message(host, ip, host_சாவி,
			    user_hostfiles, இலக்கம்_user_hostfiles,
			    system_hostfiles, இலக்கம்_system_hostfiles)) != வெற்று)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			விடுவி(ra);
			விடுவி(fp);
			விடுவி(msg1);
			விடுவி(msg2);
			எனில் (!confirmed)
				செல் fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		எனில் (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, அளவு(hostline), "%s,%s", host, ip);
			hostp = hostline;
			எனில் (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_சாவி, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_சாவி, options.hash_known_hosts);
			} இல்லையெனில் {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_சாவி,
				    options.hash_known_hosts);
			}
		} இல்லையெனில் {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_சாவி, options.hash_known_hosts);
			hostp = host;
		}

		எனில் (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		இல்லையெனில்
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		நிறுத்து;
	நிலை HOST_REVOKED:
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
		எனில் (options.strict_host_சாவி_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			செல் fail;
		}
		செல் continue_unsafe;

	நிலை HOST_CHANGED:
		எனில் (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->வரி);
			செல் fail;
		}
		எனில் (readonly == ROQUIET)
			செல் fail;
		எனில் (options.check_host_ip && host_ip_differ) {
			எழுத்து *சாவி_செய்தி;
			எனில் (ip_status == HOST_NEW)
				சாவி_செய்தி = "is unknown";
			இல்லையெனில் எனில் (ip_status == HOST_OK)
				சாவி_செய்தி = "is unchanged";
			இல்லையெனில்
				சாவி_செய்தி = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", சாவி_செய்தி);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			எனில் (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->வரி);
		}
		/* The host key has changed. */
		warn_changed_சாவி(host_சாவி);
		எனில் (இலக்கம்_user_hostfiles > 0 || இலக்கம்_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", இலக்கம்_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->சாவி),
		    host_found->file, host_found->வரி);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		எனில் (options.strict_host_சாவி_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			செல் fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		எனில் (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		எனில் (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		எனில் (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		எனில் (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		எனில் (options.இலக்கம்_local_forwards > 0 ||
		    options.இலக்கம்_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.இலக்கம்_local_forwards =
			    options.இலக்கம்_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		எனில் (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		எனில் (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		எனில் (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		நிறுத்து;
	நிலை HOST_FOUND:
		fatal("internal error");
		நிறுத்து;
	}

	எனில் (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(செய்தி, அளவு(செய்தி),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->வரி);
		எனில் (host_status == HOST_OK) {
			len = strlen(செய்தி);
			snprintf(செய்தி + len, அளவு(செய்தி) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->வரி);
		}
		எனில் (options.strict_host_சாவி_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(செய்தி, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", அளவு(செய்தி));
			எனில் (!confirm(செய்தி, வெற்று))
				செல் fail;
		} இல்லையெனில் எனில் (options.strict_host_சாவி_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", செய்தி);
			error("Exiting, you have requested strict checking.");
			செல் fail;
		} இல்லையெனில் {
			logit("%s", செய்தி);
		}
	}

	எனில் (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_சாவி);
	விடுவி(ip);
	விடுவி(host);
	எனில் (host_hostkeys != வெற்று)
		free_hostkeys(host_hostkeys);
	எனில் (ip_hostkeys != வெற்று)
		free_hostkeys(ip_hostkeys);
	திரும்பு 0;

fail:
	எனில் (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		எனில் ((r = sshkey_from_private(host_சாவி, &raw_சாவி)) != 0)
			fatal_fr(r, "decode key");
		எனில் ((r = sshkey_drop_cert(raw_சாவி)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_சாவி = raw_சாவி;
		செல் retry;
	}
	sshkey_free(raw_சாவி);
	விடுவி(ip);
	விடுவி(host);
	எனில் (host_hostkeys != வெற்று)
		free_hostkeys(host_hostkeys);
	எனில் (ip_hostkeys != வெற்று)
		free_hostkeys(ip_hostkeys);
	திரும்பு -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
முழு
verify_host_சாவி(எழுத்து *host, கட்டமைப்பு sockaddr *hostaddr, கட்டமைப்பு sshkey *host_சாவி,
    மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	u_int i;
	முழு r = -1, flags = 0;
	எழுத்து valid[64], *fp = வெற்று, *cafp = வெற்று;
	கட்டமைப்பு sshkey *plain = வெற்று;

	எனில் ((fp = sshkey_fingerprint(host_சாவி,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று) {
		error_fr(r, "fingerprint host key");
		r = -1;
		செல் out;
	}

	எனில் (sshkey_is_cert(host_சாவி)) {
		எனில் ((cafp = sshkey_fingerprint(host_சாவி->cert->signature_சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			செல் out;
		}
		sshkey_format_cert_validity(host_சாவி->cert,
		    valid, அளவு(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_சாவி), fp,
		    (unsigned long long)host_சாவி->cert->serial,
		    host_சாவி->cert->சாவி_id,
		    sshkey_ssh_name(host_சாவி->cert->signature_சாவி), cafp,
		    valid);
		க்கு (i = 0; i < host_சாவி->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_சாவி->cert->principals[i]);
		}
	} இல்லையெனில் {
		debug("Server host key: %s %s", sshkey_ssh_name(host_சாவி), fp);
	}

	எனில் (sshkey_equal(previous_host_சாவி, host_சாவி)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_சாவி), fp);
		r = 0;
		செல் out;
	}

	/* Check in RevokedHostKeys files if specified */
	க்கு (i = 0; i < options.இலக்கம்_revoked_host_சாவிகள்; i++) {
		r = sshkey_check_revoked(host_சாவி,
		    options.revoked_host_சாவிகள்[i]);
		தேர்வு (r) {
		நிலை 0:
			நிறுத்து; /* not revoked */
		நிலை SSH_ERR_சாவி_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_சாவி), fp,
			    options.revoked_host_சாவிகள்[i]);
			r = -1;
			செல் out;
		இயல்பு:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_சாவி),
			    fp, options.revoked_host_சாவிகள்[i]);
			r = -1;
			செல் out;
		}
	}

	எனில் (options.verify_host_சாவி_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		எனில் ((r = sshkey_from_private(host_சாவி, &plain)) != 0)
			செல் out;
		எனில் (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		எனில் (verify_host_சாவி_dns(host, hostaddr, plain, &flags) == 0) {
			எனில் (flags & DNS_VERIFY_FOUND) {
				எனில் (options.verify_host_சாவி_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					செல் out;
				}
				எனில் (flags & DNS_VERIFY_MATCH) {
					matching_host_சாவி_dns = 1;
				} இல்லையெனில் {
					warn_changed_சாவி(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_சாவி(host, cinfo, hostaddr, options.port, host_சாவி,
	    RDRW, 0, options.user_hostfiles, options.இலக்கம்_user_hostfiles,
	    options.system_hostfiles, options.இலக்கம்_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	விடுவி(fp);
	விடுவி(cafp);
	எனில் (r == 0 && host_சாவி != வெற்று) {
		sshkey_free(previous_host_சாவி);
		r = sshkey_from_private(host_சாவி, &previous_host_சாவி);
	}

	திரும்பு r;
}

நிலையான வெறுமை
warn_nonpq_kex(வெறுமை)
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
வெறுமை
ssh_login(கட்டமைப்பு ssh *ssh, Sensitive *sensitive, மாறிலி எழுத்து *orighost,
    கட்டமைப்பு sockaddr_storage *hostaddr, u_short port, கட்டமைப்பு passwd *pw,
    முழு timeout_ms, மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	எழுத்து *host;
	எழுத்து *server_user, *local_user;
	முழு r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	எனில் ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	எனில் ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	எனில் (!options.kex_algorithms_set && ssh->kex != வெற்று &&
	    ssh->kex->name != வெற்று && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	விடுவி(local_user);
	விடுவி(host);
}

/* print all known host keys for a given host, but skip keys of given type */
நிலையான முழு
show_other_சாவிகள்(கட்டமைப்பு hostkeys *hostkeys, கட்டமைப்பு sshkey *சாவி)
{
	முழு type[] = {
		சாவி_RSA,
		சாவி_ECDSA,
		சாவி_ED25519,
		சாவி_MLDSA44_ED25519,
		-1
	};
	முழு i, ret = 0;
	எழுத்து *fp, *ra;
	மாறிலி கட்டமைப்பு hostkey_entry *found;

	க்கு (i = 0; type[i] != -1; i++) {
		எனில் (type[i] == சாவி->type)
			தொடர்;
		எனில் (!lookup_சாவி_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			தொடர்;
		fp = sshkey_fingerprint(found->சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->சாவி,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		எனில் (fp == வெற்று || ra == வெற்று)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->சாவி),
		    found->host, found->file, found->வரி,
		    sshkey_type(found->சாவி), fp);
		எனில் (options.visual_host_சாவி)
			logit("%s", ra);
		விடுவி(ra);
		விடுவி(fp);
		ret = 1;
	}
	திரும்பு ret;
}

நிலையான வெறுமை
warn_changed_சாவி(கட்டமைப்பு sshkey *host_சாவி)
{
	எழுத்து *fp;

	fp = sshkey_fingerprint(host_சாவி, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	எனில் (fp == வெற்று)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_சாவி), fp);
	error("Please contact your system administrator.");

	விடுவி(fp);
}

/*
 * Execute a local command
 */
முழு
ssh_local_cmd(மாறிலி எழுத்து *args)
{
	எழுத்து *shell;
	pid_t pid;
	முழு status;
	வெறுமை (*osighand)(முழு);

	எனில் (!options.permit_local_command ||
	    args == வெற்று || !*args)
		திரும்பு (1);

	எனில் ((shell = getenv("SHELL")) == வெற்று || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	எனில் (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (எழுத்து *)வெற்று);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} இல்லையெனில் எனில் (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	போது (waitpid(pid, &status, 0) == -1)
		எனில் (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	எனில் (!WIFEXITED(status))
		திரும்பு (1);

	திரும்பு (WEXITSTATUS(status));
}

வெறுமை
maybe_add_சாவி_to_agent(மாறிலி எழுத்து *authfile, கட்டமைப்பு sshkey *தனிப்பட்ட,
    மாறிலி எழுத்து *comment, மாறிலி எழுத்து *passphrase)
{
	முழு auth_sock = -1, r;
	மாறிலி எழுத்து *skprovider = வெற்று;

	எனில் (options.add_சாவிகள்_to_agent == 0)
		திரும்பு;

	எனில் ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		திரும்பு;
	}

	எனில் (options.add_சாவிகள்_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		திரும்பு;
	}
	எனில் (sshkey_is_sk(தனிப்பட்ட))
		skprovider = options.sk_provider;
	எனில் ((r = ssh_add_identity_constrained(auth_sock, தனிப்பட்ட,
	    comment == வெற்று ? authfile : comment,
	    options.add_சாவிகள்_to_agent_lifespan,
	    (options.add_சாவிகள்_to_agent == 3), skprovider, வெற்று, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	இல்லையெனில்
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
