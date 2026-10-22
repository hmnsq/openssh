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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>
#شامل <sys/socket.h>

#شامل <net/if.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <ifaddrs.h>

#شامل "xmalloc.h"
#شامل "hostfile.h"
#شامل "ssh.h"
#شامل "compat.h"
#شامل "packet.h"
#شامل "sshkey.h"
#شامل "sshconnect.h"
#شامل "log.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "dns.h"
#شامل "monitor_fdpass.h"
#شامل "authfile.h"
#شامل "ssherr.h"
#شامل "authfd.h"
#شامل "kex.h"

ساختار sshkey *previous_host_کلید = پوچ;

ایستا صحیح matching_host_کلید_dns = 0;

ایستا pid_t proxy_command_pid = 0;

/* import */
بیرونی صحیح debug_flag;
بیرونی Options options;
بیرونی نویسه *__progname;

ایستا صحیح show_other_کلیدها(ساختار hostkeys *, ساختار sshkey *);
ایستا تهی warn_changed_کلید(ساختار sshkey *);

تهی
ssh_conn_info_free(ساختار ssh_conn_info *cinfo)
{
	اگر (cinfo == پوچ)
		بازگشت;
	آزاد(cinfo->conn_hash_hex);
	آزاد(cinfo->shorthost);
	آزاد(cinfo->uidstr);
	آزاد(cinfo->keyalias);
	آزاد(cinfo->thishost);
	آزاد(cinfo->host_arg);
	آزاد(cinfo->portstr);
	آزاد(cinfo->remhost);
	آزاد(cinfo->remuser);
	آزاد(cinfo->homedir);
	آزاد(cinfo->locuser);
	آزاد(cinfo->jmphost);
	freezero(cinfo, اندازه(*cinfo));
}

ساختار ssh_conn_info *
ssh_conn_info_dup(ثابت ساختار ssh_conn_info *cinfo)
{
	ساختار ssh_conn_info *ret;

	اگر (cinfo == پوچ)
		بازگشت پوچ;
	ret = xcalloc(1, اندازه(*ret));
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
	بازگشت ret;
}

/* Expand a proxy command */
ایستا نویسه *
expand_proxy_command(ثابت نویسه *proxy_command, ثابت نویسه *user,
    ثابت نویسه *host, ثابت نویسه *host_arg, صحیح port)
{
	نویسه *tmp, *ret, strport[NI_MAXSERV];
	ثابت نویسه *keyalias = options.host_کلید_alias ?
	    options.host_کلید_alias : host_arg;

	snprintf(strport, اندازه strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (نویسه *)پوچ);
	آزاد(tmp);
	بازگشت ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ایستا صحیح
ssh_proxy_fdpass_connect(ساختار ssh *ssh, ثابت نویسه *host,
    ثابت نویسه *host_arg, u_short port, ثابت نویسه *proxy_command)
{
	نویسه *command_string;
	صحیح sp[2], sock;
	pid_t pid;
	نویسه *shell;

	اگر ((shell = getenv("SHELL")) == پوچ)
		shell = _PATH_BSHELL;

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	اگر ((pid = fork()) == 0) {
		نویسه *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		اگر (sp[0] != 0) {
			اگر (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		اگر (sp[0] != 1) {
			اگر (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		اگر (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		اگر (!debug_flag && options.control_path != پوچ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = پوچ;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	آزاد(command_string);

	اگر ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	وقتی (waitpid(pid, پوچ, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	اگر (ssh_packet_set_connection(ssh, sock, sock) == پوچ)
		بازگشت -1; /* ssh_packet_set_connection logs error */

	بازگشت 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ایستا صحیح
ssh_proxy_connect(ساختار ssh *ssh, ثابت نویسه *host, ثابت نویسه *host_arg,
    u_short port, ثابت نویسه *proxy_command)
{
	نویسه *command_string;
	صحیح pin[2], pout[2];
	pid_t pid;
	نویسه *shell;

	اگر ((shell = getenv("SHELL")) == پوچ || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	اگر (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	اگر ((pid = fork()) == 0) {
		نویسه *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		اگر (pin[0] != 0) {
			اگر (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		اگر (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		اگر (!debug_flag && options.control_path != پوچ &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = پوچ;

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
	اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	وگرنه
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	آزاد(command_string);

	/* Set the connection file descriptors. */
	اگر (ssh_packet_set_connection(ssh, pout[0], pin[1]) == پوچ)
		بازگشت -1; /* ssh_packet_set_connection logs error */

	بازگشت 0;
}

تهی
ssh_kill_proxy_command(تهی)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	اگر (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ایستا صحیح
check_ifaddrs(ثابت نویسه *ifname, صحیح af, ثابت ساختار ifaddrs *ifaddrs,
    ساختار sockaddr_storage *resultp, socklen_t *rlenp)
{
	ساختار sockaddr_in6 *sa6;
	ساختار sockaddr_in *sa;
	ساختار in6_addr *v6addr;
	ثابت ساختار ifaddrs *ifa;
	صحیح allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	برای (allow_local = 0; allow_local < 2; allow_local++) {
		برای (ifa = ifaddrs; ifa != پوچ; ifa = ifa->ifa_next) {
			اگر (ifa->ifa_addr == پوچ || ifa->ifa_name == پوچ ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				ادامه;
			انتخاب (ifa->ifa_addr->sa_family) {
			حالت AF_INET:
				sa = (ساختار sockaddr_in *)ifa->ifa_addr;
				اگر (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					ادامه;
				اگر (*rlenp < اندازه(ساختار sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					بازگشت -1;
				}
				*rlenp = اندازه(ساختار sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				بازگشت 0;
			حالت AF_INET6:
				sa6 = (ساختار sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				اگر (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					ادامه;
				اگر (*rlenp < اندازه(ساختار sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					بازگشت -1;
				}
				*rlenp = اندازه(ساختار sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				بازگشت 0;
			}
		}
	}
	بازگشت -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
ایستا صحیح
ssh_create_socket(ساختار addrinfo *ai)
{
	صحیح sock, r;
	ساختار sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ساختار addrinfo hints, *res = پوچ;
#ifdef HAVE_IFADDRS_H
	ساختار ifaddrs *ifaddrs = پوچ;
#endif
	نویسه ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	اگر (sock == -1) {
		error("socket: %s", strerror(errno));
		بازگشت -1;
	}
	(تهی)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	اگر (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	اگر (options.bind_address == پوچ && options.bind_interface == پوچ)
		بازگشت sock;

	اگر (options.bind_address != پوچ) {
		memset(&hints, 0, اندازه(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		اگر ((r = getaddrinfo(options.bind_address, پوچ,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			برو fail;
		}
		اگر (res == پوچ) {
			error("getaddrinfo: no addrs");
			برو fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} وگرنه اگر (options.bind_interface != پوچ) {
#ifdef HAVE_IFADDRS_H
		اگر ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			برو fail;
		}
		bindaddrlen = اندازه(bindaddr);
		اگر (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			برو fail;
		}
#وگرنه
		error("BindInterface not supported on this platform.");
#endif
	}
	اگر ((r = getnameinfo((ساختار sockaddr *)&bindaddr, bindaddrlen,
	    ntop, اندازه(ntop), پوچ, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		برو fail;
	}
	اگر (bind(sock, (ساختار sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		برو fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	برو out;
fail:
	close(sock);
	sock = -1;
 out:
	اگر (res != پوچ)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	اگر (ifaddrs != پوچ)
		freeifaddrs(ifaddrs);
#endif
	بازگشت sock;
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
ایستا صحیح
ssh_connect_direct(ساختار ssh *ssh, ثابت نویسه *host, ساختار addrinfo *aitop,
    ساختار sockaddr_storage *hostaddr, u_short port, صحیح connection_attempts,
    صحیح *timeout_ms, صحیح want_keepalive)
{
	صحیح saved_timeout_ms = *timeout_ms;
	صحیح oerrno, sock = -1, attempt;
	نویسه ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ساختار addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, اندازه(ntop));
	memset(strport, 0, اندازه(strport));

	برای (attempt = 0; attempt < connection_attempts; attempt++) {
		اگر (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		برای (ai = aitop; ai; ai = ai->ai_next) {
			اگر (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				ادامه;
			}
			اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, اندازه(ntop), strport, اندازه(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				ادامه;
			}
			اگر (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				ادامه;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			اگر (sock < 0) {
				/* Any error is already output */
				errno = 0;
				ادامه;
			}

			*timeout_ms = saved_timeout_ms;
			اگر (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				بشکن;
			} وگرنه {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		اگر (sock != -1)
			بشکن;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	اگر (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		بازگشت -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	اگر (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	اگر (ssh_packet_set_connection(ssh, sock, sock) == پوچ)
		بازگشت -1; /* ssh_packet_set_connection logs error */

	بازگشت 0;
}

صحیح
ssh_connect(ساختار ssh *ssh, ثابت نویسه *host, ثابت نویسه *host_arg,
    ساختار addrinfo *addrs, ساختار sockaddr_storage *hostaddr, u_short port,
    صحیح connection_attempts, صحیح *timeout_ms, صحیح want_keepalive)
{
	صحیح in, out;

	اگر (options.proxy_command == پوچ) {
		بازگشت ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} وگرنه اگر (strcmp(options.proxy_command, "-") == 0) {
		اگر ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			اگر (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			بازگشت -1; /* ssh_packet_set_connection logs error */
		}
		اگر ((ssh_packet_set_connection(ssh, in, out)) == پوچ)
			بازگشت -1; /* ssh_packet_set_connection logs error */
		بازگشت 0;
	} وگرنه اگر (options.proxy_use_fdpass) {
		بازگشت ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	بازگشت ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
ایستا صحیح
confirm(ثابت نویسه *prompt, ثابت نویسه *fingerprint)
{
	ثابت نویسه *پیام, *again = "Please type 'yes' or 'no': ";
	ثابت نویسه *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	نویسه *p, *cp;
	صحیح ret = -1;

	اگر (options.batch_mode)
		بازگشت 0;
	برای (پیام = prompt;;پیام = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(پیام, RP_ECHO);
		اگر (p == پوچ)
			بازگشت 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		اگر (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		وگرنه اگر (strcasecmp(p, "yes") == 0 || (fingerprint != پوچ &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		آزاد(cp);
		اگر (ret != -1)
			بازگشت ret;
	}
}

ایستا صحیح
sockaddr_is_local(ساختار sockaddr *hostaddr)
{
	انتخاب (hostaddr->sa_family) {
	حالت AF_INET:
		بازگشت (ntohl(((ساختار sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	حالت AF_INET6:
		بازگشت IN6_IS_ADDR_LOOPBACK(
		    &(((ساختار sockaddr_in6 *)hostaddr)->sin6_addr));
	پیشفرض:
		بازگشت 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
تهی
get_hostfile_hostname_ipaddr(نویسه *hostname, ساختار sockaddr *hostaddr,
    u_short port, نویسه **hostfile_hostname, نویسه **hostfile_ipaddr)
{
	نویسه ntop[NI_MAXHOST];
	socklen_t addrlen;

	انتخاب (hostaddr == پوچ ? -1 : hostaddr->sa_family) {
	حالت -1:
		addrlen = 0;
		بشکن;
	حالت AF_INET:
		addrlen = اندازه(ساختار sockaddr_in);
		بشکن;
	حالت AF_INET6:
		addrlen = اندازه(ساختار sockaddr_in6);
		بشکن;
	پیشفرض:
		addrlen = اندازه(ساختار sockaddr);
		بشکن;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	اگر (hostfile_ipaddr != پوچ) {
		اگر (options.proxy_command == پوچ) {
			اگر (getnameinfo(hostaddr, addrlen,
			    ntop, اندازه(ntop), پوچ, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} وگرنه {
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
	اگر (hostfile_hostname != پوچ) {
		اگر (options.host_کلید_alias != پوچ) {
			*hostfile_hostname = xstrdup(options.host_کلید_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} وگرنه {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ایستا صحیح
path_in_hostfiles(ثابت نویسه *path, نویسه **hostfiles, u_int رقم_hostfiles)
{
	u_int i;

	برای (i = 0; i < رقم_hostfiles; i++) {
		اگر (strcmp(path, hostfiles[i]) == 0)
			بازگشت 1;
	}
	بازگشت 0;
}

ساختار find_by_کلید_ctx {
	ثابت نویسه *host, *ip;
	ثابت ساختار sshkey *کلید;
	نویسه **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ایستا نویسه *
try_tilde_unexpand(ثابت نویسه *path)
{
	نویسه *home, *ret = پوچ;
	size_t l;

	اگر (*path != '/')
		بازگشت xstrdup(path);
	اگر ((home = getenv("HOME")) == پوچ || (l = strlen(home)) == 0)
		بازگشت xstrdup(path);
	اگر (strncmp(path, home, l) != 0)
		بازگشت xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	اگر (home[l - 1] != '/' && path[l] != '/')
		بازگشت xstrdup(path);
	اگر (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	بازگشت ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
صحیح
hostkey_accepted_by_hostkeyalgs(ثابت ساختار sshkey *کلید)
{
	ثابت نویسه *ktype = sshkey_ssh_name(کلید);
	ثابت نویسه *hostkeyalgs = options.hostkeyalgorithms;

	اگر (کلید->type == کلید_UNSPEC)
		بازگشت 0;
	اگر (کلید->type == کلید_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		بازگشت 1;
	اگر (کلید->type == کلید_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		بازگشت 1;
	بازگشت match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

ایستا صحیح
hostkeys_find_by_کلید_cb(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار find_by_کلید_ctx *ctx = (ساختار find_by_کلید_ctx *)_ctx;
	نویسه *path;

	/* we are looking for keys with names that *do not* match */
	اگر ((l->match & HKF_MATCH_HOST) != 0)
		بازگشت 0;
	/* not interested in marker lines */
	اگر (l->marker != MRK_NONE)
		بازگشت 0;
	/* we are only interested in exact key matches */
	اگر (l->کلید == پوچ || !sshkey_equal(ctx->کلید, l->کلید))
		بازگشت 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, اندازه(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	آزاد(path);
	بازگشت 0;
}

ایستا صحیح
hostkeys_find_by_کلید_hostfile(ثابت نویسه *file, ثابت نویسه *which,
    ساختار find_by_کلید_ctx *ctx)
{
	صحیح r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	اگر ((r = hostkeys_foreach(file, hostkeys_find_by_کلید_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_کلید, 0)) != 0) {
		اگر (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			بازگشت 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		بازگشت r;
	}
	بازگشت 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ایستا تهی
hostkeys_find_by_کلید(ثابت نویسه *host, ثابت نویسه *ip, ثابت ساختار sshkey *کلید,
    نویسه **user_hostfiles, u_int رقم_user_hostfiles,
    نویسه **system_hostfiles, u_int رقم_system_hostfiles,
    نویسه ***names, u_int *nnames)
{
	ساختار find_by_کلید_ctx ctx = {پوچ, پوچ, پوچ, پوچ, 0};
	u_int i;

	*names = پوچ;
	*nnames = 0;

	اگر (کلید == پوچ || sshkey_is_cert(کلید))
		بازگشت;

	ctx.host = host;
	ctx.ip = ip;
	ctx.کلید = کلید;

	برای (i = 0; i < رقم_user_hostfiles; i++) {
		اگر (hostkeys_find_by_کلید_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			برو fail;
	}
	برای (i = 0; i < رقم_system_hostfiles; i++) {
		اگر (hostkeys_find_by_کلید_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			برو fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = پوچ;
	ctx.nnames = 0;
	بازگشت;
 fail:
	برای (i = 0; i < ctx.nnames; i++)
		آزاد(ctx.names[i]);
	آزاد(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
ایستا نویسه *
other_hostkeys_message(ثابت نویسه *host, ثابت نویسه *ip,
    ثابت ساختار sshkey *کلید,
    نویسه **user_hostfiles, u_int رقم_user_hostfiles,
    نویسه **system_hostfiles, u_int رقم_system_hostfiles)
{
	نویسه *ret = پوچ, **othernames = پوچ;
	u_int i, n, رقم_othernames = 0;

	hostkeys_find_by_کلید(host, ip, کلید,
	    user_hostfiles, رقم_user_hostfiles,
	    system_hostfiles, رقم_system_hostfiles,
	    &othernames, &رقم_othernames);
	اگر (رقم_othernames == 0)
		بازگشت xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = رقم_othernames;
	اگر (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	برای (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	اگر (n < رقم_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    رقم_othernames - n);
	}
	برای (i = 0; i < رقم_othernames; i++)
		آزاد(othernames[i]);
	آزاد(othernames);
	بازگشت ret;
}

تهی
load_hostkeys_command(ساختار hostkeys *hostkeys, ثابت نویسه *command_template,
    ثابت نویسه *invocation, ثابت ساختار ssh_conn_info *cinfo,
    ثابت ساختار sshkey *host_کلید, ثابت نویسه *hostfile_hostname)
{
	صحیح r, i, ac = 0;
	نویسه *کلید_fp = پوچ, *keytext = پوچ, *tmp;
	نویسه *command = پوچ, *tag = پوچ, **av = پوچ;
	FILE *f = پوچ;
	pid_t pid;
	تهی (*osigchld)(صحیح);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	اگر (host_کلید != پوچ) {
		اگر ((کلید_fp = sshkey_fingerprint(host_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
			fatal_f("sshkey_fingerprint failed");
		اگر ((r = sshkey_to_base64(host_کلید, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	اگر (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		برو out;
	}
	اگر (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		برو out;
	}
	برای (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_کلید == پوچ ? "NONE" : sshkey_ssh_name(host_کلید),
		    "f", کلید_fp == پوچ ? "NONE" : کلید_fp,
		    "K", keytext == پوچ ? "NONE" : keytext,
		    (نویسه *)پوچ);
		اگر (tmp == پوچ)
			fatal_f("percent_expand failed");
		آزاد(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	اگر ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, پوچ, پوچ, پوچ)) == 0)
		برو out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	اگر (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	اگر (f != پوچ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	برای (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
	آزاد(tag);
	آزاد(command);
	آزاد(کلید_fp);
	آزاد(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
ایستا صحیح
check_host_کلید(نویسه *hostname, ثابت ساختار ssh_conn_info *cinfo,
    ساختار sockaddr *hostaddr, u_short port,
    ساختار sshkey *host_کلید, صحیح readonly, صحیح clobber_port,
    نویسه **user_hostfiles, u_int رقم_user_hostfiles,
    نویسه **system_hostfiles, u_int رقم_system_hostfiles,
    ثابت نویسه *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	ساختار sshkey *raw_کلید = پوچ;
	نویسه *ip = پوچ, *host = پوچ;
	نویسه hostline[1000], *hostp, *fp, *ra;
	نویسه پیام[1024];
	ثابت نویسه *type, *fail_reason = پوچ;
	ثابت ساختار hostkey_entry *host_found = پوچ, *ip_found = پوچ;
	صحیح len, cancelled_forwarding = 0, confirmed;
	صحیح local = sockaddr_is_local(hostaddr);
	صحیح r, want_cert = sshkey_is_cert(host_کلید), host_ip_differ = 0;
	صحیح hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ساختار hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	اگر (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_کلید_alias == پوچ) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		بازگشت 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	اگر (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	اگر (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != پوچ))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	برای (i = 0; i < رقم_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	برای (i = 0; i < رقم_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	اگر (hostfile_command != پوچ && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_کلید, host);
	}

	ip_hostkeys = پوچ;
	اگر (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		برای (i = 0; i < رقم_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		برای (i = 0; i < رقم_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		اگر (hostfile_command != پوچ && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_کلید, ip);
		}
	}

 retry:
	اگر (!hostkey_accepted_by_hostkeyalgs(host_کلید)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_کلید));
		برو fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_کلید);
	type = sshkey_type(host_کلید);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_کلید_in_hostkeys(host_hostkeys, host_کلید,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	اگر (!readonly && (رقم_user_hostfiles == 0 ||
	    (host_found != پوچ && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	اگر (!want_cert && ip_hostkeys != پوچ) {
		ip_status = check_کلید_in_hostkeys(ip_hostkeys, host_کلید,
		    &ip_found);
		اگر (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != پوچ &&
		    !sshkey_equal(ip_found->کلید, host_found->کلید))))
			host_ip_differ = 1;
	} وگرنه
		ip_status = host_status;

	انتخاب (host_status) {
	حالت HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->سطر);
		اگر (want_cert) {
			اگر (sshkey_cert_check_host(host_کلید,
			    options.host_کلید_alias == پوچ ?
			    hostname : options.host_کلید_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				برو fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			اگر (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		اگر (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, رقم_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != پوچ &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, رقم_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		اگر (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		اگر (options.check_host_ip && ip_status == HOST_NEW) {
			اگر (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			وگرنه اگر (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_کلید, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			وگرنه
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} وگرنه اگر (options.visual_host_کلید) {
			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			اگر (fp == پوچ || ra == پوچ)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			آزاد(ra);
			آزاد(fp);
		}
		hostkey_trusted = 1;
		بشکن;
	حالت HOST_NEW:
		اگر (options.host_کلید_alias == پوچ && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			اگر (check_host_کلید(hostname, cinfo, hostaddr, 0,
			    host_کلید, ROQUIET, 1,
			    user_hostfiles, رقم_user_hostfiles,
			    system_hostfiles, رقم_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				بشکن;
			}
		}
		اگر (readonly || want_cert)
			برو fail;
		/* The host is new. */
		اگر (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			برو fail;
		} وگرنه اگر (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			نویسه *msg1 = پوچ, *msg2 = پوچ;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			اگر (show_other_کلیدها(host_hostkeys, host_کلید)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} وگرنه
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			اگر (fp == پوچ || ra == پوچ)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			اگر (options.visual_host_کلید)
				xextendf(&msg1, "\n", "%s", ra);
			اگر (options.verify_host_کلید_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_کلید_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			اگر ((msg2 = other_hostkeys_message(host, ip, host_کلید,
			    user_hostfiles, رقم_user_hostfiles,
			    system_hostfiles, رقم_system_hostfiles)) != پوچ)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			آزاد(ra);
			آزاد(fp);
			آزاد(msg1);
			آزاد(msg2);
			اگر (!confirmed)
				برو fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		اگر (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, اندازه(hostline), "%s,%s", host, ip);
			hostp = hostline;
			اگر (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_کلید, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_کلید, options.hash_known_hosts);
			} وگرنه {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_کلید,
				    options.hash_known_hosts);
			}
		} وگرنه {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_کلید, options.hash_known_hosts);
			hostp = host;
		}

		اگر (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		وگرنه
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		بشکن;
	حالت HOST_REVOKED:
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
		اگر (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			برو fail;
		}
		برو continue_unsafe;

	حالت HOST_CHANGED:
		اگر (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->سطر);
			برو fail;
		}
		اگر (readonly == ROQUIET)
			برو fail;
		اگر (options.check_host_ip && host_ip_differ) {
			نویسه *کلید_پیام;
			اگر (ip_status == HOST_NEW)
				کلید_پیام = "is unknown";
			وگرنه اگر (ip_status == HOST_OK)
				کلید_پیام = "is unchanged";
			وگرنه
				کلید_پیام = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", کلید_پیام);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			اگر (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->سطر);
		}
		/* The host key has changed. */
		warn_changed_کلید(host_کلید);
		اگر (رقم_user_hostfiles > 0 || رقم_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", رقم_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->کلید),
		    host_found->file, host_found->سطر);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		اگر (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			برو fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		اگر (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		اگر (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		اگر (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		اگر (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		اگر (options.رقم_local_forwards > 0 ||
		    options.رقم_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.رقم_local_forwards =
			    options.رقم_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		اگر (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		اگر (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		اگر (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		بشکن;
	حالت HOST_FOUND:
		fatal("internal error");
		بشکن;
	}

	اگر (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(پیام, اندازه(پیام),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->سطر);
		اگر (host_status == HOST_OK) {
			len = strlen(پیام);
			snprintf(پیام + len, اندازه(پیام) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->سطر);
		}
		اگر (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(پیام, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", اندازه(پیام));
			اگر (!confirm(پیام, پوچ))
				برو fail;
		} وگرنه اگر (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", پیام);
			error("Exiting, you have requested strict checking.");
			برو fail;
		} وگرنه {
			logit("%s", پیام);
		}
	}

	اگر (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_کلید);
	آزاد(ip);
	آزاد(host);
	اگر (host_hostkeys != پوچ)
		free_hostkeys(host_hostkeys);
	اگر (ip_hostkeys != پوچ)
		free_hostkeys(ip_hostkeys);
	بازگشت 0;

fail:
	اگر (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		اگر ((r = sshkey_from_private(host_کلید, &raw_کلید)) != 0)
			fatal_fr(r, "decode key");
		اگر ((r = sshkey_drop_cert(raw_کلید)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_کلید = raw_کلید;
		برو retry;
	}
	sshkey_free(raw_کلید);
	آزاد(ip);
	آزاد(host);
	اگر (host_hostkeys != پوچ)
		free_hostkeys(host_hostkeys);
	اگر (ip_hostkeys != پوچ)
		free_hostkeys(ip_hostkeys);
	بازگشت -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
صحیح
verify_host_کلید(نویسه *host, ساختار sockaddr *hostaddr, ساختار sshkey *host_کلید,
    ثابت ساختار ssh_conn_info *cinfo)
{
	u_int i;
	صحیح r = -1, flags = 0;
	نویسه valid[64], *fp = پوچ, *cafp = پوچ;
	ساختار sshkey *plain = پوچ;

	اگر ((fp = sshkey_fingerprint(host_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ) {
		error_fr(r, "fingerprint host key");
		r = -1;
		برو out;
	}

	اگر (sshkey_is_cert(host_کلید)) {
		اگر ((cafp = sshkey_fingerprint(host_کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			برو out;
		}
		sshkey_format_cert_validity(host_کلید->cert,
		    valid, اندازه(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_کلید), fp,
		    (unsigned long long)host_کلید->cert->serial,
		    host_کلید->cert->کلید_id,
		    sshkey_ssh_name(host_کلید->cert->signature_کلید), cafp,
		    valid);
		برای (i = 0; i < host_کلید->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_کلید->cert->principals[i]);
		}
	} وگرنه {
		debug("Server host key: %s %s", sshkey_ssh_name(host_کلید), fp);
	}

	اگر (sshkey_equal(previous_host_کلید, host_کلید)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_کلید), fp);
		r = 0;
		برو out;
	}

	/* Check in RevokedHostKeys files if specified */
	برای (i = 0; i < options.رقم_revoked_host_کلیدها; i++) {
		r = sshkey_check_revoked(host_کلید,
		    options.revoked_host_کلیدها[i]);
		انتخاب (r) {
		حالت 0:
			بشکن; /* not revoked */
		حالت SSH_ERR_کلید_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_کلید), fp,
			    options.revoked_host_کلیدها[i]);
			r = -1;
			برو out;
		پیشفرض:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_کلید),
			    fp, options.revoked_host_کلیدها[i]);
			r = -1;
			برو out;
		}
	}

	اگر (options.verify_host_کلید_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		اگر ((r = sshkey_from_private(host_کلید, &plain)) != 0)
			برو out;
		اگر (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		اگر (verify_host_کلید_dns(host, hostaddr, plain, &flags) == 0) {
			اگر (flags & DNS_VERIFY_FOUND) {
				اگر (options.verify_host_کلید_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					برو out;
				}
				اگر (flags & DNS_VERIFY_MATCH) {
					matching_host_کلید_dns = 1;
				} وگرنه {
					warn_changed_کلید(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_کلید(host, cinfo, hostaddr, options.port, host_کلید,
	    RDRW, 0, options.user_hostfiles, options.رقم_user_hostfiles,
	    options.system_hostfiles, options.رقم_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	آزاد(fp);
	آزاد(cafp);
	اگر (r == 0 && host_کلید != پوچ) {
		sshkey_free(previous_host_کلید);
		r = sshkey_from_private(host_کلید, &previous_host_کلید);
	}

	بازگشت r;
}

ایستا تهی
warn_nonpq_kex(تهی)
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
تهی
ssh_login(ساختار ssh *ssh, Sensitive *sensitive, ثابت نویسه *orighost,
    ساختار sockaddr_storage *hostaddr, u_short port, ساختار passwd *pw,
    صحیح timeout_ms, ثابت ساختار ssh_conn_info *cinfo)
{
	نویسه *host;
	نویسه *server_user, *local_user;
	صحیح r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	اگر ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	اگر ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	اگر (!options.kex_algorithms_set && ssh->kex != پوچ &&
	    ssh->kex->name != پوچ && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	آزاد(local_user);
	آزاد(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ایستا صحیح
show_other_کلیدها(ساختار hostkeys *hostkeys, ساختار sshkey *کلید)
{
	صحیح type[] = {
		کلید_RSA,
		کلید_ECDSA,
		کلید_ED25519,
		کلید_MLDSA44_ED25519,
		-1
	};
	صحیح i, ret = 0;
	نویسه *fp, *ra;
	ثابت ساختار hostkey_entry *found;

	برای (i = 0; type[i] != -1; i++) {
		اگر (type[i] == کلید->type)
			ادامه;
		اگر (!lookup_کلید_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			ادامه;
		fp = sshkey_fingerprint(found->کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->کلید,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		اگر (fp == پوچ || ra == پوچ)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->کلید),
		    found->host, found->file, found->سطر,
		    sshkey_type(found->کلید), fp);
		اگر (options.visual_host_کلید)
			logit("%s", ra);
		آزاد(ra);
		آزاد(fp);
		ret = 1;
	}
	بازگشت ret;
}

ایستا تهی
warn_changed_کلید(ساختار sshkey *host_کلید)
{
	نویسه *fp;

	fp = sshkey_fingerprint(host_کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	اگر (fp == پوچ)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_کلید), fp);
	error("Please contact your system administrator.");

	آزاد(fp);
}

/*
 * Execute a local command
 */
صحیح
ssh_local_cmd(ثابت نویسه *args)
{
	نویسه *shell;
	pid_t pid;
	صحیح status;
	تهی (*osighand)(صحیح);

	اگر (!options.permit_local_command ||
	    args == پوچ || !*args)
		بازگشت (1);

	اگر ((shell = getenv("SHELL")) == پوچ || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	اگر (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (نویسه *)پوچ);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} وگرنه اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	وقتی (waitpid(pid, &status, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	اگر (!WIFEXITED(status))
		بازگشت (1);

	بازگشت (WEXITSTATUS(status));
}

تهی
maybe_add_کلید_to_agent(ثابت نویسه *authfile, ساختار sshkey *خصوصی,
    ثابت نویسه *comment, ثابت نویسه *passphrase)
{
	صحیح auth_sock = -1, r;
	ثابت نویسه *skprovider = پوچ;

	اگر (options.add_کلیدها_to_agent == 0)
		بازگشت;

	اگر ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		بازگشت;
	}

	اگر (options.add_کلیدها_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		بازگشت;
	}
	اگر (sshkey_is_sk(خصوصی))
		skprovider = options.sk_provider;
	اگر ((r = ssh_add_identity_constrained(auth_sock, خصوصی,
	    comment == پوچ ? authfile : comment,
	    options.add_کلیدها_to_agent_lifespan,
	    (options.add_کلیدها_to_agent == 3), skprovider, پوچ, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	وگرنه
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
