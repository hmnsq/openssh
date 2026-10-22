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

ساخت sshkey *پچھلا_host_کلید = تہی;

ساکن صحیح matching_host_کلید_dns = 0;

ساکن pid_t proxy_command_pid = 0;

/* import */
خارجی صحیح debug_flag;
خارجی Options options;
خارجی حرف *__progname;

ساکن صحیح show_other_کلیدیں(ساخت hostkeys *, ساخت sshkey *);
ساکن خالی warn_بدلا_کلید(ساخت sshkey *);

خالی
ssh_conn_info_free(ساخت ssh_conn_info *cinfo)
{
	اگر (cinfo == تہی)
		واپس;
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
	freezero(cinfo, حجم(*cinfo));
}

ساخت ssh_conn_info *
ssh_conn_info_dup(ثابت ساخت ssh_conn_info *cinfo)
{
	ساخت ssh_conn_info *ret;

	اگر (cinfo == تہی)
		واپس تہی;
	ret = xcalloc(1, حجم(*ret));
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
	واپس ret;
}

/* Expand a proxy command */
ساکن حرف *
expand_proxy_command(ثابت حرف *proxy_command, ثابت حرف *user,
    ثابت حرف *host, ثابت حرف *host_arg, صحیح پورٹ)
{
	حرف *tmp, *ret, strport[NI_MAXSERV];
	ثابت حرف *keyalias = options.host_کلید_alias ?
	    options.host_کلید_alias : host_arg;

	snprintf(strport, حجم strport, "%d", پورٹ);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (حرف *)تہی);
	آزاد(tmp);
	واپس ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ساکن صحیح
ssh_proxy_fdpass_connect(ساخت ssh *ssh, ثابت حرف *host,
    ثابت حرف *host_arg, u_short پورٹ, ثابت حرف *proxy_command)
{
	حرف *command_string;
	صحیح sp[2], sock;
	pid_t pid;
	حرف *shell;

	اگر ((shell = getenv("SHELL")) == تہی)
		shell = _PATH_BSHELL;

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, پورٹ);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	اگر ((pid = fork()) == 0) {
		حرف *argv[10];

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
		اگر (!debug_flag && options.control_راستہ != تہی &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = تہی;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		باہر_نکلو(1);
	}
	/* Parent. */
	اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	آزاد(command_string);

	اگر ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	جب (waitpid(pid, تہی, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	اگر (ssh_packet_سیٹ_connection(ssh, sock, sock) == تہی)
		واپس -1; /* ssh_packet_set_connection logs error */

	واپس 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ساکن صحیح
ssh_proxy_connect(ساخت ssh *ssh, ثابت حرف *host, ثابت حرف *host_arg,
    u_short پورٹ, ثابت حرف *proxy_command)
{
	حرف *command_string;
	صحیح pin[2], pout[2];
	pid_t pid;
	حرف *shell;

	اگر ((shell = getenv("SHELL")) == تہی || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	اگر (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, پورٹ);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	اگر ((pid = fork()) == 0) {
		حرف *argv[10];

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
		اگر (!debug_flag && options.control_راستہ != تہی &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = تہی;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		باہر_نکلو(1);
	}
	/* Parent. */
	اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ورنہ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	آزاد(command_string);

	/* Set the connection file descriptors. */
	اگر (ssh_packet_سیٹ_connection(ssh, pout[0], pin[1]) == تہی)
		واپس -1; /* ssh_packet_set_connection logs error */

	واپس 0;
}

خالی
ssh_kill_proxy_command(خالی)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	اگر (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#اگر_تعریف_شدہ HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ساکن صحیح
check_ifaddrs(ثابت حرف *ifname, صحیح af, ثابت ساخت ifaddrs *ifaddrs,
    ساخت sockaddr_storage *resultp, socklen_t *rlenp)
{
	ساخت sockaddr_in6 *sa6;
	ساخت sockaddr_in *sa;
	ساخت in6_addr *v6addr;
	ثابت ساخت ifaddrs *ifa;
	صحیح allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	برائے (allow_local = 0; allow_local < 2; allow_local++) {
		برائے (ifa = ifaddrs; ifa != تہی; ifa = ifa->ifa_اگلا) {
			اگر (ifa->ifa_addr == تہی || ifa->ifa_name == تہی ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				جاری;
			انتخاب (ifa->ifa_addr->sa_family) {
			حالت AF_INET:
				sa = (ساخت sockaddr_in *)ifa->ifa_addr;
				اگر (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					جاری;
				اگر (*rlenp < حجم(ساخت sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					واپس -1;
				}
				*rlenp = حجم(ساخت sockaddr_in);
				حافظہ_نقل(resultp, sa, *rlenp);
				واپس 0;
			حالت AF_INET6:
				sa6 = (ساخت sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				اگر (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					جاری;
				اگر (*rlenp < حجم(ساخت sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					واپس -1;
				}
				*rlenp = حجم(ساخت sockaddr_in6);
				حافظہ_نقل(resultp, sa6, *rlenp);
				واپس 0;
			}
		}
	}
	واپس -1;
}
#اگر_ختم

/*
 * Creates a socket for use as the ssh connection.
 */
ساکن صحیح
ssh_create_socket(ساخت addrinfo *ai)
{
	صحیح sock, r;
	ساخت sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	ساخت addrinfo hints, *res = تہی;
#اگر_تعریف_شدہ HAVE_IFADDRS_H
	ساخت ifaddrs *ifaddrs = تہی;
#اگر_ختم
	حرف ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	اگر (sock == -1) {
		error("socket: %s", strerror(errno));
		واپس -1;
	}
	(خالی)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	اگر (options.ip_qos_interactive != زیادہ_سے_زیادہ_عدد)
		سیٹ_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	اگر (options.bind_پتہ == تہی && options.bind_interface == تہی)
		واپس sock;

	اگر (options.bind_پتہ != تہی) {
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		اگر ((r = getaddrinfo(options.bind_پتہ, تہی,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_پتہ,
			    ssh_gai_strerror(r));
			جاؤ fail;
		}
		اگر (res == تہی) {
			error("getaddrinfo: no addrs");
			جاؤ fail;
		}
		حافظہ_نقل(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ورنہ اگر (options.bind_interface != تہی) {
#اگر_تعریف_شدہ HAVE_IFADDRS_H
		اگر ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			جاؤ fail;
		}
		bindaddrlen = حجم(bindaddr);
		اگر (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			جاؤ fail;
		}
#ورنہ
		error("BindInterface not supported on this platform.");
#اگر_ختم
	}
	اگر ((r = getnameinfo((ساخت sockaddr *)&bindaddr, bindaddrlen,
	    ntop, حجم(ntop), تہی, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		جاؤ fail;
	}
	اگر (bind(sock, (ساخت sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		جاؤ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	جاؤ برآمد;
fail:
	close(sock);
	sock = -1;
 برآمد:
	اگر (res != تہی)
		freeaddrinfo(res);
#اگر_تعریف_شدہ HAVE_IFADDRS_H
	اگر (ifaddrs != تہی)
		freeifaddrs(ifaddrs);
#اگر_ختم
	واپس sock;
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
ساکن صحیح
ssh_connect_براہ_راست(ساخت ssh *ssh, ثابت حرف *host, ساخت addrinfo *aitop,
    ساخت sockaddr_storage *hostaddr, u_short پورٹ, صحیح connection_attempts,
    صحیح *timeout_ms, صحیح want_keepalive)
{
	صحیح saved_timeout_ms = *timeout_ms;
	صحیح oerrno, sock = -1, attempt;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];
	ساخت addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, حجم(ntop));
	memset(strport, 0, حجم(strport));

	برائے (attempt = 0; attempt < connection_attempts; attempt++) {
		اگر (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		برائے (ai = aitop; ai; ai = ai->ai_next) {
			اگر (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				جاری;
			}
			اگر (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, حجم(ntop), strport, حجم(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				جاری;
			}
			اگر (options.پتہ_family != AF_UNSPEC &&
			    ai->ai_family != options.پتہ_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				جاری;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			اگر (sock < 0) {
				/* Any error is already output */
				errno = 0;
				جاری;
			}

			*timeout_ms = saved_timeout_ms;
			اگر (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				حافظہ_نقل(hostaddr, ai->ai_addr, ai->ai_addrlen);
				توڑو;
			} ورنہ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		اگر (sock != -1)
			توڑو;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	اگر (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		واپس -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	اگر (want_keepalive)
		سیٹ_keepalive(sock); /* logs errors */

	/* Set the connection. */
	اگر (ssh_packet_سیٹ_connection(ssh, sock, sock) == تہی)
		واپس -1; /* ssh_packet_set_connection logs error */

	واپس 0;
}

صحیح
ssh_connect(ساخت ssh *ssh, ثابت حرف *host, ثابت حرف *host_arg,
    ساخت addrinfo *addrs, ساخت sockaddr_storage *hostaddr, u_short پورٹ,
    صحیح connection_attempts, صحیح *timeout_ms, صحیح want_keepalive)
{
	صحیح اندر, برآمد;

	اگر (options.proxy_command == تہی) {
		واپس ssh_connect_براہ_راست(ssh, host, addrs, hostaddr, پورٹ,
		    connection_attempts, timeout_ms, want_keepalive);
	} ورنہ اگر (strcmp(options.proxy_command, "-") == 0) {
		اگر ((اندر = dup(STDIN_FILENO)) == -1 ||
		    (برآمد = dup(STDOUT_FILENO)) == -1) {
			اگر (اندر >= 0)
				close(اندر);
			error_f("dup() in/out failed");
			واپس -1; /* ssh_packet_set_connection logs error */
		}
		اگر ((ssh_packet_سیٹ_connection(ssh, اندر, برآمد)) == تہی)
			واپس -1; /* ssh_packet_set_connection logs error */
		واپس 0;
	} ورنہ اگر (options.proxy_use_fdpass) {
		واپس ssh_proxy_fdpass_connect(ssh, host, host_arg, پورٹ,
		    options.proxy_command);
	}
	واپس ssh_proxy_connect(ssh, host, host_arg, پورٹ,
	    options.proxy_command);
}

/* defaults to 'no' */
ساکن صحیح
confirm(ثابت حرف *prompt, ثابت حرف *fingerprint)
{
	ثابت حرف *پیغام, *again = "Please type 'yes' or 'no': ";
	ثابت حرف *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	حرف *p, *cp;
	صحیح ret = -1;

	اگر (options.batch_منوال)
		واپس 0;
	برائے (پیغام = prompt;;پیغام = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(پیغام, RP_ECHO);
		اگر (p == تہی)
			واپس 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		اگر (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ورنہ اگر (strcasecmp(p, "yes") == 0 || (fingerprint != تہی &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		آزاد(cp);
		اگر (ret != -1)
			واپس ret;
	}
}

ساکن صحیح
sockaddr_is_local(ساخت sockaddr *hostaddr)
{
	انتخاب (hostaddr->sa_family) {
	حالت AF_INET:
		واپس (ntohl(((ساخت sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	حالت AF_INET6:
		واپس IN6_IS_ADDR_LOOPBACK(
		    &(((ساخت sockaddr_in6 *)hostaddr)->sin6_addr));
	طےشدہ:
		واپس 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
خالی
get_hostfile_hostname_ipaddr(حرف *hostname, ساخت sockaddr *hostaddr,
    u_short پورٹ, حرف **hostfile_hostname, حرف **hostfile_ipaddr)
{
	حرف ntop[NI_MAXHOST];
	socklen_t addrlen;

	انتخاب (hostaddr == تہی ? -1 : hostaddr->sa_family) {
	حالت -1:
		addrlen = 0;
		توڑو;
	حالت AF_INET:
		addrlen = حجم(ساخت sockaddr_in);
		توڑو;
	حالت AF_INET6:
		addrlen = حجم(ساخت sockaddr_in6);
		توڑو;
	طےشدہ:
		addrlen = حجم(ساخت sockaddr);
		توڑو;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	اگر (hostfile_ipaddr != تہی) {
		اگر (options.proxy_command == تہی) {
			اگر (getnameinfo(hostaddr, addrlen,
			    ntop, حجم(ntop), تہی, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_پورٹ(ntop, پورٹ);
		} ورنہ {
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
	اگر (hostfile_hostname != تہی) {
		اگر (options.host_کلید_alias != تہی) {
			*hostfile_hostname = xstrdup(options.host_کلید_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ورنہ {
			*hostfile_hostname = put_host_پورٹ(hostname, پورٹ);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ساکن صحیح
راستہ_اندر_hostfiles(ثابت حرف *راستہ, حرف **hostfiles, u_int عدد_hostfiles)
{
	u_int i;

	برائے (i = 0; i < عدد_hostfiles; i++) {
		اگر (strcmp(راستہ, hostfiles[i]) == 0)
			واپس 1;
	}
	واپس 0;
}

ساخت ڈھونڈو_by_کلید_ctx {
	ثابت حرف *host, *ip;
	ثابت ساخت sshkey *کلید;
	حرف **نام;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ساکن حرف *
try_tilde_unexpand(ثابت حرف *راستہ)
{
	حرف *home, *ret = تہی;
	سائز_t l;

	اگر (*راستہ != '/')
		واپس xstrdup(راستہ);
	اگر ((home = getenv("HOME")) == تہی || (l = لڑی_لمبائی(home)) == 0)
		واپس xstrdup(راستہ);
	اگر (لڑی_موازنہ(راستہ, home, l) != 0)
		واپس xstrdup(راستہ);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	اگر (home[l - 1] != '/' && راستہ[l] != '/')
		واپس xstrdup(راستہ);
	اگر (راستہ[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", راستہ + l);
	واپس ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
صحیح
hostkey_accepted_by_hostkeyalgs(ثابت ساخت sshkey *کلید)
{
	ثابت حرف *ktype = sshkey_ssh_name(کلید);
	ثابت حرف *hostkeyalgs = options.hostkeyalgorithms;

	اگر (کلید->type == کلید_UNSPEC)
		واپس 0;
	اگر (کلید->type == کلید_RSA &&
	    (مطابقت_نمونہ_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    مطابقت_نمونہ_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		واپس 1;
	اگر (کلید->type == کلید_RSA_CERT &&
	    (مطابقت_نمونہ_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    مطابقت_نمونہ_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		واپس 1;
	واپس مطابقت_نمونہ_list(ktype, hostkeyalgs, 0) == 1;
}

ساکن صحیح
hostkeys_ڈھونڈو_by_کلید_cb(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت ڈھونڈو_by_کلید_ctx *ctx = (ساخت ڈھونڈو_by_کلید_ctx *)_ctx;
	حرف *راستہ;

	/* we are looking for keys with names that *do not* match */
	اگر ((l->مطابقت & HKF_مطابقت_HOST) != 0)
		واپس 0;
	/* not interested in marker lines */
	اگر (l->marker != MRK_NONE)
		واپس 0;
	/* we are only interested in exact key matches */
	اگر (l->کلید == تہی || !sshkey_equal(ctx->کلید, l->کلید))
		واپس 0;
	راستہ = try_tilde_unexpand(l->راستہ);
	debug_f("found matching key in %s:%lu", راستہ, l->linenum);
	ctx->نام = xrecallocarray(ctx->نام,
	    ctx->nnames, ctx->nnames + 1, حجم(*ctx->نام));
	xasprintf(&ctx->نام[ctx->nnames], "%s:%lu: %s", راستہ, l->linenum,
	    لڑی_موازنہ(l->hosts, HASH_MAGIC, لڑی_لمبائی(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	آزاد(راستہ);
	واپس 0;
}

ساکن صحیح
hostkeys_ڈھونڈو_by_کلید_hostfile(ثابت حرف *file, ثابت حرف *which,
    ساخت ڈھونڈو_by_کلید_ctx *ctx)
{
	صحیح r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	اگر ((r = hostkeys_foreach(file, hostkeys_ڈھونڈو_by_کلید_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_کلید, 0)) != 0) {
		اگر (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			واپس 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		واپس r;
	}
	واپس 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ساکن خالی
hostkeys_ڈھونڈو_by_کلید(ثابت حرف *host, ثابت حرف *ip, ثابت ساخت sshkey *کلید,
    حرف **user_hostfiles, u_int عدد_user_hostfiles,
    حرف **system_hostfiles, u_int عدد_system_hostfiles,
    حرف ***نام, u_int *nnames)
{
	ساخت ڈھونڈو_by_کلید_ctx ctx = {تہی, تہی, تہی, تہی, 0};
	u_int i;

	*نام = تہی;
	*nnames = 0;

	اگر (کلید == تہی || sshkey_is_cert(کلید))
		واپس;

	ctx.host = host;
	ctx.ip = ip;
	ctx.کلید = کلید;

	برائے (i = 0; i < عدد_user_hostfiles; i++) {
		اگر (hostkeys_ڈھونڈو_by_کلید_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			جاؤ fail;
	}
	برائے (i = 0; i < عدد_system_hostfiles; i++) {
		اگر (hostkeys_ڈھونڈو_by_کلید_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			جاؤ fail;
	}
	/* success */
	*نام = ctx.نام;
	*nnames = ctx.nnames;
	ctx.نام = تہی;
	ctx.nnames = 0;
	واپس;
 fail:
	برائے (i = 0; i < ctx.nnames; i++)
		آزاد(ctx.نام[i]);
	آزاد(ctx.نام);
}

#تعریف_کرو MAX_OTHER_نام	8 /* Maximum number of names to list */
ساکن حرف *
other_hostkeys_پیغام(ثابت حرف *host, ثابت حرف *ip,
    ثابت ساخت sshkey *کلید,
    حرف **user_hostfiles, u_int عدد_user_hostfiles,
    حرف **system_hostfiles, u_int عدد_system_hostfiles)
{
	حرف *ret = تہی, **othernames = تہی;
	u_int i, n, عدد_othernames = 0;

	hostkeys_ڈھونڈو_by_کلید(host, ip, کلید,
	    user_hostfiles, عدد_user_hostfiles,
	    system_hostfiles, عدد_system_hostfiles,
	    &othernames, &عدد_othernames);
	اگر (عدد_othernames == 0)
		واپس xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = عدد_othernames;
	اگر (n > MAX_OTHER_نام)
		n = MAX_OTHER_نام;
	برائے (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	اگر (n < عدد_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    عدد_othernames - n);
	}
	برائے (i = 0; i < عدد_othernames; i++)
		آزاد(othernames[i]);
	آزاد(othernames);
	واپس ret;
}

خالی
بھرو_hostkeys_command(ساخت hostkeys *hostkeys, ثابت حرف *command_template,
    ثابت حرف *invocation, ثابت ساخت ssh_conn_info *cinfo,
    ثابت ساخت sshkey *host_کلید, ثابت حرف *hostfile_hostname)
{
	صحیح r, i, ac = 0;
	حرف *کلید_fp = تہی, *keytext = تہی, *tmp;
	حرف *command = تہی, *لیبل = تہی, **av = تہی;
	FILE *f = تہی;
	pid_t pid;
	خالی (*osigchld)(صحیح);

	xasprintf(&لیبل, "KnownHostsCommand-%s", invocation);

	اگر (host_کلید != تہی) {
		اگر ((کلید_fp = sshkey_fingerprint(host_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint failed");
		اگر ((r = sshkey_مقصد_base64(host_کلید, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	اگر (argv_بانٹو(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", لیبل,
		    command_template);
		جاؤ برآمد;
	}
	اگر (ac == 0) {
		error("%s \"%s\" yielded no arguments", لیبل,
		    command_template);
		جاؤ برآمد;
	}
	برائے (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_دلائل(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_کلید == تہی ? "NONE" : sshkey_ssh_name(host_کلید),
		    "f", کلید_fp == تہی ? "NONE" : کلید_fp,
		    "K", keytext == تہی ? "NONE" : keytext,
		    (حرف *)تہی);
		اگر (tmp == تہی)
			fatal_f("percent_expand failed");
		آزاد(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	اگر ((pid = subprocess(لیبل, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_راستہ|
	    SSH_SUBPROCESS_PRESERVE_ENV, تہی, تہی, تہی)) == 0)
		جاؤ برآمد;

	بھرو_hostkeys_file(hostkeys, hostfile_hostname, لیبل, f, 1);

	اگر (exited_cleanly(pid, لیبل, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 برآمد:
	اگر (f != تہی)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	برائے (i = 0; i < ac; i++)
		آزاد(av[i]);
	آزاد(av);
	آزاد(لیبل);
	آزاد(command);
	آزاد(کلید_fp);
	آزاد(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#تعریف_کرو RDRW	0
#تعریف_کرو RDONLY	1
#تعریف_کرو ROQUIET	2
ساکن صحیح
check_host_کلید(حرف *hostname, ثابت ساخت ssh_conn_info *cinfo,
    ساخت sockaddr *hostaddr, u_short پورٹ,
    ساخت sshkey *host_کلید, صحیح readonly, صحیح clobber_پورٹ,
    حرف **user_hostfiles, u_int عدد_user_hostfiles,
    حرف **system_hostfiles, u_int عدد_system_hostfiles,
    ثابت حرف *hostfile_command)
{
	Host_حالت host_حالت = -1, ip_حالت = -1;
	ساخت sshkey *raw_کلید = تہی;
	حرف *ip = تہی, *host = تہی;
	حرف hostline[1000], *hostp, *fp, *ra;
	حرف پیغام[1024];
	ثابت حرف *type, *fail_reason = تہی;
	ثابت ساخت hostkey_اندراج *host_ملا = تہی, *ip_ملا = تہی;
	صحیح len, cancelled_forwarding = 0, confirmed;
	صحیح local = sockaddr_is_local(hostaddr);
	صحیح r, want_cert = sshkey_is_cert(host_کلید), host_ip_فرق = 0;
	صحیح hostkey_trusted = 0; /* Known or explicitly accepted by user */
	ساخت hostkeys *host_hostkeys, *ip_hostkeys;
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
	    options.host_کلید_alias == تہی) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		واپس 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	اگر (strcspn(hostname, "@?*#[]|'\'\"\\") != لڑی_لمبائی(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_پورٹ ? 0 : پورٹ, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	اگر (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != تہی))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	برائے (i = 0; i < عدد_user_hostfiles; i++)
		بھرو_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	برائے (i = 0; i < عدد_system_hostfiles; i++)
		بھرو_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	اگر (hostfile_command != تہی && !clobber_پورٹ) {
		بھرو_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_کلید, host);
	}

	ip_hostkeys = تہی;
	اگر (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		برائے (i = 0; i < عدد_user_hostfiles; i++)
			بھرو_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		برائے (i = 0; i < عدد_system_hostfiles; i++)
			بھرو_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		اگر (hostfile_command != تہی && !clobber_پورٹ) {
			بھرو_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_کلید, ip);
		}
	}

 retry:
	اگر (!hostkey_accepted_by_hostkeyalgs(host_کلید)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_کلید));
		جاؤ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_کلید);
	type = sshkey_type(host_کلید);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_حالت = check_کلید_اندر_hostkeys(host_hostkeys, host_کلید,
	    &host_ملا);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	اگر (!readonly && (عدد_user_hostfiles == 0 ||
	    (host_ملا != تہی && host_ملا->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	اگر (!want_cert && ip_hostkeys != تہی) {
		ip_حالت = check_کلید_اندر_hostkeys(ip_hostkeys, host_کلید,
		    &ip_ملا);
		اگر (host_حالت == HOST_بدلا &&
		    (ip_حالت != HOST_بدلا ||
		    (ip_ملا != تہی &&
		    !sshkey_equal(ip_ملا->کلید, host_ملا->کلید))))
			host_ip_فرق = 1;
	} ورنہ
		ip_حالت = host_حالت;

	انتخاب (host_حالت) {
	حالت HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_ملا->file, host_ملا->سطر);
		اگر (want_cert) {
			اگر (sshkey_cert_check_host(host_کلید,
			    options.host_کلید_alias == تہی ?
			    hostname : options.host_کلید_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				جاؤ fail;
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
		    (راستہ_اندر_hostfiles(host_ملا->file,
		    system_hostfiles, عدد_system_hostfiles) ||
		    (ip_حالت == HOST_OK && ip_ملا != تہی &&
		    راستہ_اندر_hostfiles(ip_ملا->file,
		    system_hostfiles, عدد_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		اگر (options.update_hostkeys != 0 && host_ملا->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		اگر (options.check_host_ip && ip_حالت == HOST_NEW) {
			اگر (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ورنہ اگر (!جوڑو_host_مقصد_hostfile(user_hostfiles[0], ip,
			    host_کلید, options.hash_معلوم_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ورنہ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ورنہ اگر (options.visual_host_کلید) {
			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			اگر (fp == تہی || ra == تہی)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			آزاد(ra);
			آزاد(fp);
		}
		hostkey_trusted = 1;
		توڑو;
	حالت HOST_NEW:
		اگر (options.host_کلید_alias == تہی && پورٹ != 0 &&
		    پورٹ != SSH_DEFAULT_پورٹ && !clobber_پورٹ) {
			debug("checking without port identifier");
			اگر (check_host_کلید(hostname, cinfo, hostaddr, 0,
			    host_کلید, ROQUIET, 1,
			    user_hostfiles, عدد_user_hostfiles,
			    system_hostfiles, عدد_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				توڑو;
			}
		}
		اگر (readonly || want_cert)
			جاؤ fail;
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
			جاؤ fail;
		} ورنہ اگر (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			حرف *msg1 = تہی, *msg2 = تہی;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			اگر (show_other_کلیدیں(host_hostkeys, host_کلید)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ورنہ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			اگر (fp == تہی || ra == تہی)
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
			اگر ((msg2 = other_hostkeys_پیغام(host, ip, host_کلید,
			    user_hostfiles, عدد_user_hostfiles,
			    system_hostfiles, عدد_system_hostfiles)) != تہی)
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
				جاؤ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		اگر (options.check_host_ip && ip_حالت == HOST_NEW) {
			snprintf(hostline, حجم(hostline), "%s,%s", host, ip);
			hostp = hostline;
			اگر (options.hash_معلوم_hosts) {
				/* Add hash of host and IP separately */
				r = جوڑو_host_مقصد_hostfile(user_hostfiles[0],
				    host, host_کلید, options.hash_معلوم_hosts) &&
				    جوڑو_host_مقصد_hostfile(user_hostfiles[0], ip,
				    host_کلید, options.hash_معلوم_hosts);
			} ورنہ {
				/* Add unhashed "host,ip" */
				r = جوڑو_host_مقصد_hostfile(user_hostfiles[0],
				    hostline, host_کلید,
				    options.hash_معلوم_hosts);
			}
		} ورنہ {
			r = جوڑو_host_مقصد_hostfile(user_hostfiles[0], host,
			    host_کلید, options.hash_معلوم_hosts);
			hostp = host;
		}

		اگر (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ورنہ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		توڑو;
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
			جاؤ fail;
		}
		جاؤ continue_unsafe;

	حالت HOST_بدلا:
		اگر (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_ملا->file, host_ملا->سطر);
			جاؤ fail;
		}
		اگر (readonly == ROQUIET)
			جاؤ fail;
		اگر (options.check_host_ip && host_ip_فرق) {
			حرف *کلید_پیغام;
			اگر (ip_حالت == HOST_NEW)
				کلید_پیغام = "is unknown";
			ورنہ اگر (ip_حالت == HOST_OK)
				کلید_پیغام = "is unchanged";
			ورنہ
				کلید_پیغام = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", کلید_پیغام);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			اگر (ip_حالت != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_ملا->file, ip_ملا->سطر);
		}
		/* The host key has changed. */
		warn_بدلا_کلید(host_کلید);
		اگر (عدد_user_hostfiles > 0 || عدد_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", عدد_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_ملا->کلید),
		    host_ملا->file, host_ملا->سطر);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		اگر (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			جاؤ fail;
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
		اگر (options.عدد_local_forwards > 0 ||
		    options.عدد_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.عدد_local_forwards =
			    options.عدد_remote_forwards = 0;
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
		توڑو;
	حالت HOST_ملا:
		fatal("internal error");
		توڑو;
	}

	اگر (options.check_host_ip && host_حالت != HOST_بدلا &&
	    ip_حالت == HOST_بدلا) {
		snprintf(پیغام, حجم(پیغام),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_ملا->file, ip_ملا->سطر);
		اگر (host_حالت == HOST_OK) {
			len = لڑی_لمبائی(پیغام);
			snprintf(پیغام + len, حجم(پیغام) - len,
			    "\nMatching host key in %s:%lu",
			    host_ملا->file, host_ملا->سطر);
		}
		اگر (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(پیغام, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", حجم(پیغام));
			اگر (!confirm(پیغام, تہی))
				جاؤ fail;
		} ورنہ اگر (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", پیغام);
			error("Exiting, you have requested strict checking.");
			جاؤ fail;
		} ورنہ {
			logit("%s", پیغام);
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
	اگر (host_hostkeys != تہی)
		free_hostkeys(host_hostkeys);
	اگر (ip_hostkeys != تہی)
		free_hostkeys(ip_hostkeys);
	واپس 0;

fail:
	اگر (want_cert && host_حالت != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		اگر ((r = sshkey_from_نجی(host_کلید, &raw_کلید)) != 0)
			fatal_fr(r, "decode key");
		اگر ((r = sshkey_drop_cert(raw_کلید)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_کلید = raw_کلید;
		جاؤ retry;
	}
	sshkey_free(raw_کلید);
	آزاد(ip);
	آزاد(host);
	اگر (host_hostkeys != تہی)
		free_hostkeys(host_hostkeys);
	اگر (ip_hostkeys != تہی)
		free_hostkeys(ip_hostkeys);
	واپس -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
صحیح
verify_host_کلید(حرف *host, ساخت sockaddr *hostaddr, ساخت sshkey *host_کلید,
    ثابت ساخت ssh_conn_info *cinfo)
{
	u_int i;
	صحیح r = -1, flags = 0;
	حرف valid[64], *fp = تہی, *cafp = تہی;
	ساخت sshkey *plain = تہی;

	اگر ((fp = sshkey_fingerprint(host_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی) {
		error_fr(r, "fingerprint host key");
		r = -1;
		جاؤ برآمد;
	}

	اگر (sshkey_is_cert(host_کلید)) {
		اگر ((cafp = sshkey_fingerprint(host_کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			جاؤ برآمد;
		}
		sshkey_format_cert_validity(host_کلید->cert,
		    valid, حجم(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_کلید), fp,
		    (غیرعلامتی طویل طویل)host_کلید->cert->serial,
		    host_کلید->cert->کلید_id,
		    sshkey_ssh_name(host_کلید->cert->signature_کلید), cafp,
		    valid);
		برائے (i = 0; i < host_کلید->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_کلید->cert->principals[i]);
		}
	} ورنہ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_کلید), fp);
	}

	اگر (sshkey_equal(پچھلا_host_کلید, host_کلید)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_کلید), fp);
		r = 0;
		جاؤ برآمد;
	}

	/* Check in RevokedHostKeys files if specified */
	برائے (i = 0; i < options.عدد_revoked_host_کلیدیں; i++) {
		r = sshkey_check_revoked(host_کلید,
		    options.revoked_host_کلیدیں[i]);
		انتخاب (r) {
		حالت 0:
			توڑو; /* not revoked */
		حالت SSH_ERR_کلید_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_کلید), fp,
			    options.revoked_host_کلیدیں[i]);
			r = -1;
			جاؤ برآمد;
		طےشدہ:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_کلید),
			    fp, options.revoked_host_کلیدیں[i]);
			r = -1;
			جاؤ برآمد;
		}
	}

	اگر (options.verify_host_کلید_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		اگر ((r = sshkey_from_نجی(host_کلید, &plain)) != 0)
			جاؤ برآمد;
		اگر (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		اگر (verify_host_کلید_dns(host, hostaddr, plain, &flags) == 0) {
			اگر (flags & DNS_VERIFY_ملا) {
				اگر (options.verify_host_کلید_dns == 1 &&
				    flags & DNS_VERIFY_مطابقت &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					جاؤ برآمد;
				}
				اگر (flags & DNS_VERIFY_مطابقت) {
					matching_host_کلید_dns = 1;
				} ورنہ {
					warn_بدلا_کلید(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_کلید(host, cinfo, hostaddr, options.پورٹ, host_کلید,
	    RDRW, 0, options.user_hostfiles, options.عدد_user_hostfiles,
	    options.system_hostfiles, options.عدد_system_hostfiles,
	    options.معلوم_hosts_command);

برآمد:
	sshkey_free(plain);
	آزاد(fp);
	آزاد(cafp);
	اگر (r == 0 && host_کلید != تہی) {
		sshkey_free(پچھلا_host_کلید);
		r = sshkey_from_نجی(host_کلید, &پچھلا_host_کلید);
	}

	واپس r;
}

ساکن خالی
warn_nonpq_kex(خالی)
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
خالی
ssh_login(ساخت ssh *ssh, Sensitive *sensitive, ثابت حرف *orighost,
    ساخت sockaddr_storage *hostaddr, u_short پورٹ, ساخت passwd *pw,
    صحیح timeout_ms, ثابت ساخت ssh_conn_info *cinfo)
{
	حرف *host;
	حرف *server_user, *local_user;
	صحیح r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	اگر ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.نسخہ_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	اگر ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_سیٹ_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, پورٹ, server_user);
	ssh_kex2(ssh, host, hostaddr, پورٹ, cinfo);
	kex_سیٹ_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_سیٹ);
	اگر (!options.kex_algorithms_سیٹ && ssh->kex != تہی &&
	    ssh->kex->name != تہی && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	آزاد(local_user);
	آزاد(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ساکن صحیح
show_other_کلیدیں(ساخت hostkeys *hostkeys, ساخت sshkey *کلید)
{
	صحیح type[] = {
		کلید_RSA,
		کلید_ECDSA,
		کلید_ED25519,
		کلید_MLDSA44_ED25519,
		-1
	};
	صحیح i, ret = 0;
	حرف *fp, *ra;
	ثابت ساخت hostkey_اندراج *ملا;

	برائے (i = 0; type[i] != -1; i++) {
		اگر (type[i] == کلید->type)
			جاری;
		اگر (!lookup_کلید_اندر_hostkeys_by_type(hostkeys, type[i],
		    -1, &ملا))
			جاری;
		fp = sshkey_fingerprint(ملا->کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ملا->کلید,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		اگر (fp == تہی || ra == تہی)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(ملا->کلید),
		    ملا->host, ملا->file, ملا->سطر,
		    sshkey_type(ملا->کلید), fp);
		اگر (options.visual_host_کلید)
			logit("%s", ra);
		آزاد(ra);
		آزاد(fp);
		ret = 1;
	}
	واپس ret;
}

ساکن خالی
warn_بدلا_کلید(ساخت sshkey *host_کلید)
{
	حرف *fp;

	fp = sshkey_fingerprint(host_کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	اگر (fp == تہی)
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
ssh_local_cmd(ثابت حرف *دلائل)
{
	حرف *shell;
	pid_t pid;
	صحیح حالت_2;
	خالی (*osighand)(صحیح);

	اگر (!options.permit_local_command ||
	    دلائل == تہی || !*دلائل)
		واپس (1);

	اگر ((shell = getenv("SHELL")) == تہی || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	اگر (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, دلائل);
		execl(shell, shell, "-c", دلائل, (حرف *)تہی);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, دلائل, strerror(errno));
		_exit(1);
	} ورنہ اگر (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	جب (waitpid(pid, &حالت_2, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	اگر (!WIFEXITED(حالت_2))
		واپس (1);

	واپس (WEXITSTATUS(حالت_2));
}

خالی
maybe_جوڑو_کلید_مقصد_agent(ثابت حرف *authfile, ساخت sshkey *نجی,
    ثابت حرف *comment, ثابت حرف *passphrase)
{
	صحیح auth_sock = -1, r;
	ثابت حرف *skprovider = تہی;

	اگر (options.جوڑو_کلیدیں_مقصد_agent == 0)
		واپس;

	اگر ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		واپس;
	}

	اگر (options.جوڑو_کلیدیں_مقصد_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		واپس;
	}
	اگر (sshkey_is_sk(نجی))
		skprovider = options.sk_provider;
	اگر ((r = ssh_جوڑو_شناختی_عنصر_constrained(auth_sock, نجی,
	    comment == تہی ? authfile : comment,
	    options.جوڑو_کلیدیں_مقصد_agent_lifespan,
	    (options.جوڑو_کلیدیں_مقصد_agent == 3), skprovider, تہی, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ورنہ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
