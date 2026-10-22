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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>
#ضمن <sys/socket.h>

#ضمن <net/if.h>
#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <ifaddrs.h>

#ضمن "xmalloc.h"
#ضمن "hostfile.h"
#ضمن "ssh.h"
#ضمن "compat.h"
#ضمن "packet.h"
#ضمن "sshkey.h"
#ضمن "sshconnect.h"
#ضمن "log.h"
#ضمن "match.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "dns.h"
#ضمن "monitor_fdpass.h"
#ضمن "authfile.h"
#ضمن "ssherr.h"
#ضمن "authfd.h"
#ضمن "kex.h"

بنية sshkey *قبلی_host_کلید = عدم;

ساكن صحيح matching_host_کلید_dns = 0;

ساكن pid_t proxy_command_pid = 0;

/* import */
خارجي صحيح debug_flag;
خارجي Options options;
خارجي حرف *__progname;

ساكن صحيح show_other_کلیدها(بنية hostkeys *, بنية sshkey *);
ساكن فراغ warn_تغییریافته_کلید(بنية sshkey *);

فراغ
ssh_conn_info_free(بنية ssh_conn_info *cinfo)
{
	إذا (cinfo == عدم)
		أرجع;
	حرر(cinfo->conn_hash_hex);
	حرر(cinfo->shorthost);
	حرر(cinfo->uidstr);
	حرر(cinfo->keyalias);
	حرر(cinfo->thishost);
	حرر(cinfo->host_arg);
	حرر(cinfo->portstr);
	حرر(cinfo->remhost);
	حرر(cinfo->remuser);
	حرر(cinfo->homedir);
	حرر(cinfo->locuser);
	حرر(cinfo->jmphost);
	freezero(cinfo, حجم(*cinfo));
}

بنية ssh_conn_info *
ssh_conn_info_dup(ثابت بنية ssh_conn_info *cinfo)
{
	بنية ssh_conn_info *ret;

	إذا (cinfo == عدم)
		أرجع عدم;
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
	أرجع ret;
}

/* Expand a proxy command */
ساكن حرف *
expand_proxy_command(ثابت حرف *proxy_command, ثابت حرف *user,
    ثابت حرف *host, ثابت حرف *host_arg, صحيح پورت)
{
	حرف *tmp, *ret, strport[NI_MAXSERV];
	ثابت حرف *keyalias = options.host_کلید_alias ?
	    options.host_کلید_alias : host_arg;

	snprintf(strport, حجم strport, "%d", پورت);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (حرف *)عدم);
	حرر(tmp);
	أرجع ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
ساكن صحيح
ssh_proxy_fdpass_connect(بنية ssh *ssh, ثابت حرف *host,
    ثابت حرف *host_arg, u_short پورت, ثابت حرف *proxy_command)
{
	حرف *command_string;
	صحيح sp[2], sock;
	pid_t pid;
	حرف *shell;

	إذا ((shell = getenv("SHELL")) == عدم)
		shell = _PATH_BSHELL;

	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, پورت);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	إذا ((pid = fork()) == 0) {
		حرف *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		إذا (sp[0] != 0) {
			إذا (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		إذا (sp[0] != 1) {
			إذا (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		إذا (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		إذا (!debug_flag && options.control_مسیر != عدم &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = عدم;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		خروج(1);
	}
	/* Parent. */
	إذا (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	حرر(command_string);

	إذا ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	طالما (waitpid(pid, عدم, 0) == -1)
		إذا (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	إذا (ssh_packet_مجموعه_connection(ssh, sock, sock) == عدم)
		أرجع -1; /* ssh_packet_set_connection logs error */

	أرجع 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
ساكن صحيح
ssh_proxy_connect(بنية ssh *ssh, ثابت حرف *host, ثابت حرف *host_arg,
    u_short پورت, ثابت حرف *proxy_command)
{
	حرف *command_string;
	صحيح pin[2], pout[2];
	pid_t pid;
	حرف *shell;

	إذا ((shell = getenv("SHELL")) == عدم || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	إذا (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, پورت);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	إذا ((pid = fork()) == 0) {
		حرف *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		إذا (pin[0] != 0) {
			إذا (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		إذا (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		إذا (!debug_flag && options.control_مسیر != عدم &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = عدم;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		perror(argv[0]);
		خروج(1);
	}
	/* Parent. */
	إذا (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	وإلا
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	حرر(command_string);

	/* Set the connection file descriptors. */
	إذا (ssh_packet_مجموعه_connection(ssh, pout[0], pin[1]) == عدم)
		أرجع -1; /* ssh_packet_set_connection logs error */

	أرجع 0;
}

فراغ
ssh_kill_proxy_command(فراغ)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	إذا (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#اگر_تعریف_شده HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
ساكن صحيح
check_ifaddrs(ثابت حرف *ifname, صحيح af, ثابت بنية ifaddrs *ifaddrs,
    بنية sockaddr_storage *resultp, socklen_t *rlenp)
{
	بنية sockaddr_in6 *sa6;
	بنية sockaddr_in *sa;
	بنية in6_addr *v6addr;
	ثابت بنية ifaddrs *ifa;
	صحيح allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	لكل (allow_local = 0; allow_local < 2; allow_local++) {
		لكل (ifa = ifaddrs; ifa != عدم; ifa = ifa->ifa_بعدی) {
			إذا (ifa->ifa_addr == عدم || ifa->ifa_name == عدم ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				استمر;
			بدل (ifa->ifa_addr->sa_family) {
			حالة AF_INET:
				sa = (بنية sockaddr_in *)ifa->ifa_addr;
				إذا (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					استمر;
				إذا (*rlenp < حجم(بنية sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					أرجع -1;
				}
				*rlenp = حجم(بنية sockaddr_in);
				کپی_حافظه(resultp, sa, *rlenp);
				أرجع 0;
			حالة AF_INET6:
				sa6 = (بنية sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				إذا (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					استمر;
				إذا (*rlenp < حجم(بنية sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					أرجع -1;
				}
				*rlenp = حجم(بنية sockaddr_in6);
				کپی_حافظه(resultp, sa6, *rlenp);
				أرجع 0;
			}
		}
	}
	أرجع -1;
}
#پایان_اگر

/*
 * Creates a socket for use as the ssh connection.
 */
ساكن صحيح
ssh_create_socket(بنية addrinfo *ai)
{
	صحيح sock, r;
	بنية sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	بنية addrinfo hints, *res = عدم;
#اگر_تعریف_شده HAVE_IFADDRS_H
	بنية ifaddrs *ifaddrs = عدم;
#پایان_اگر
	حرف ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	إذا (sock == -1) {
		error("socket: %s", strerror(errno));
		أرجع -1;
	}
	(فراغ)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	إذا (options.ip_qos_interactive != بیشترین_صحیح)
		مجموعه_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	إذا (options.bind_آدرس == عدم && options.bind_interface == عدم)
		أرجع sock;

	إذا (options.bind_آدرس != عدم) {
		memset(&hints, 0, حجم(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		إذا ((r = getaddrinfo(options.bind_آدرس, عدم,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_آدرس,
			    ssh_gai_strerror(r));
			اذهب fail;
		}
		إذا (res == عدم) {
			error("getaddrinfo: no addrs");
			اذهب fail;
		}
		کپی_حافظه(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} وإلا إذا (options.bind_interface != عدم) {
#اگر_تعریف_شده HAVE_IFADDRS_H
		إذا ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			اذهب fail;
		}
		bindaddrlen = حجم(bindaddr);
		إذا (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			اذهب fail;
		}
#وإلا
		error("BindInterface not supported on this platform.");
#پایان_اگر
	}
	إذا ((r = getnameinfo((بنية sockaddr *)&bindaddr, bindaddrlen,
	    ntop, حجم(ntop), عدم, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		اذهب fail;
	}
	إذا (bind(sock, (بنية sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		اذهب fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	اذهب بیرون;
fail:
	close(sock);
	sock = -1;
 بیرون:
	إذا (res != عدم)
		freeaddrinfo(res);
#اگر_تعریف_شده HAVE_IFADDRS_H
	إذا (ifaddrs != عدم)
		freeifaddrs(ifaddrs);
#پایان_اگر
	أرجع sock;
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
ساكن صحيح
ssh_connect_مستقیم(بنية ssh *ssh, ثابت حرف *host, بنية addrinfo *aitop,
    بنية sockaddr_storage *hostaddr, u_short پورت, صحيح connection_attempts,
    صحيح *timeout_ms, صحيح want_keepalive)
{
	صحيح saved_timeout_ms = *timeout_ms;
	صحيح oerrno, sock = -1, attempt;
	حرف ntop[NI_MAXHOST], strport[NI_MAXSERV];
	بنية addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, حجم(ntop));
	memset(strport, 0, حجم(strport));

	لكل (attempt = 0; attempt < connection_attempts; attempt++) {
		إذا (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		لكل (ai = aitop; ai; ai = ai->ai_next) {
			إذا (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				استمر;
			}
			إذا (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, حجم(ntop), strport, حجم(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				استمر;
			}
			إذا (options.آدرس_family != AF_UNSPEC &&
			    ai->ai_family != options.آدرس_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				استمر;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			إذا (sock < 0) {
				/* Any error is already output */
				errno = 0;
				استمر;
			}

			*timeout_ms = saved_timeout_ms;
			إذا (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				کپی_حافظه(hostaddr, ai->ai_addr, ai->ai_addrlen);
				اكسر;
			} وإلا {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		إذا (sock != -1)
			اكسر;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	إذا (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		أرجع -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	إذا (want_keepalive)
		مجموعه_keepalive(sock); /* logs errors */

	/* Set the connection. */
	إذا (ssh_packet_مجموعه_connection(ssh, sock, sock) == عدم)
		أرجع -1; /* ssh_packet_set_connection logs error */

	أرجع 0;
}

صحيح
ssh_connect(بنية ssh *ssh, ثابت حرف *host, ثابت حرف *host_arg,
    بنية addrinfo *addrs, بنية sockaddr_storage *hostaddr, u_short پورت,
    صحيح connection_attempts, صحيح *timeout_ms, صحيح want_keepalive)
{
	صحيح درون, بیرون;

	إذا (options.proxy_command == عدم) {
		أرجع ssh_connect_مستقیم(ssh, host, addrs, hostaddr, پورت,
		    connection_attempts, timeout_ms, want_keepalive);
	} وإلا إذا (strcmp(options.proxy_command, "-") == 0) {
		إذا ((درون = dup(STDIN_FILENO)) == -1 ||
		    (بیرون = dup(STDOUT_FILENO)) == -1) {
			إذا (درون >= 0)
				close(درون);
			error_f("dup() in/out failed");
			أرجع -1; /* ssh_packet_set_connection logs error */
		}
		إذا ((ssh_packet_مجموعه_connection(ssh, درون, بیرون)) == عدم)
			أرجع -1; /* ssh_packet_set_connection logs error */
		أرجع 0;
	} وإلا إذا (options.proxy_use_fdpass) {
		أرجع ssh_proxy_fdpass_connect(ssh, host, host_arg, پورت,
		    options.proxy_command);
	}
	أرجع ssh_proxy_connect(ssh, host, host_arg, پورت,
	    options.proxy_command);
}

/* defaults to 'no' */
ساكن صحيح
confirm(ثابت حرف *prompt, ثابت حرف *fingerprint)
{
	ثابت حرف *پیام, *again = "Please type 'yes' or 'no': ";
	ثابت حرف *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	حرف *p, *cp;
	صحيح ret = -1;

	إذا (options.batch_نما)
		أرجع 0;
	لكل (پیام = prompt;;پیام = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(پیام, RP_ECHO);
		إذا (p == عدم)
			أرجع 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		إذا (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		وإلا إذا (strcasecmp(p, "yes") == 0 || (fingerprint != عدم &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		حرر(cp);
		إذا (ret != -1)
			أرجع ret;
	}
}

ساكن صحيح
sockaddr_is_local(بنية sockaddr *hostaddr)
{
	بدل (hostaddr->sa_family) {
	حالة AF_INET:
		أرجع (ntohl(((بنية sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	حالة AF_INET6:
		أرجع IN6_IS_ADDR_LOOPBACK(
		    &(((بنية sockaddr_in6 *)hostaddr)->sin6_addr));
	افتراضي:
		أرجع 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
فراغ
get_hostfile_hostname_ipaddr(حرف *hostname, بنية sockaddr *hostaddr,
    u_short پورت, حرف **hostfile_hostname, حرف **hostfile_ipaddr)
{
	حرف ntop[NI_MAXHOST];
	socklen_t addrlen;

	بدل (hostaddr == عدم ? -1 : hostaddr->sa_family) {
	حالة -1:
		addrlen = 0;
		اكسر;
	حالة AF_INET:
		addrlen = حجم(بنية sockaddr_in);
		اكسر;
	حالة AF_INET6:
		addrlen = حجم(بنية sockaddr_in6);
		اكسر;
	افتراضي:
		addrlen = حجم(بنية sockaddr);
		اكسر;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	إذا (hostfile_ipaddr != عدم) {
		إذا (options.proxy_command == عدم) {
			إذا (getnameinfo(hostaddr, addrlen,
			    ntop, حجم(ntop), عدم, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_پورت(ntop, پورت);
		} وإلا {
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
	إذا (hostfile_hostname != عدم) {
		إذا (options.host_کلید_alias != عدم) {
			*hostfile_hostname = xstrdup(options.host_کلید_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} وإلا {
			*hostfile_hostname = put_host_پورت(hostname, پورت);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
ساكن صحيح
مسیر_درون_hostfiles(ثابت حرف *مسیر, حرف **hostfiles, u_int رقم_hostfiles)
{
	u_int i;

	لكل (i = 0; i < رقم_hostfiles; i++) {
		إذا (strcmp(مسیر, hostfiles[i]) == 0)
			أرجع 1;
	}
	أرجع 0;
}

بنية پیدا_کن_by_کلید_ctx {
	ثابت حرف *host, *ip;
	ثابت بنية sshkey *کلید;
	حرف **نامها;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
ساكن حرف *
try_tilde_unexpand(ثابت حرف *مسیر)
{
	حرف *home, *ret = عدم;
	اندازه_t l;

	إذا (*مسیر != '/')
		أرجع xstrdup(مسیر);
	إذا ((home = getenv("HOME")) == عدم || (l = طول_رشته(home)) == 0)
		أرجع xstrdup(مسیر);
	إذا (مقایسه_رشته(مسیر, home, l) != 0)
		أرجع xstrdup(مسیر);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	إذا (home[l - 1] != '/' && مسیر[l] != '/')
		أرجع xstrdup(مسیر);
	إذا (مسیر[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", مسیر + l);
	أرجع ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
صحيح
hostkey_accepted_by_hostkeyalgs(ثابت بنية sshkey *کلید)
{
	ثابت حرف *ktype = sshkey_ssh_name(کلید);
	ثابت حرف *hostkeyalgs = options.hostkeyalgorithms;

	إذا (کلید->type == کلید_UNSPEC)
		أرجع 0;
	إذا (کلید->type == کلید_RSA &&
	    (تطابق_الگو_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    تطابق_الگو_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		أرجع 1;
	إذا (کلید->type == کلید_RSA_CERT &&
	    (تطابق_الگو_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    تطابق_الگو_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		أرجع 1;
	أرجع تطابق_الگو_list(ktype, hostkeyalgs, 0) == 1;
}

ساكن صحيح
hostkeys_پیدا_کن_by_کلید_cb(بنية hostkey_foreach_سطر *l, فراغ *_ctx)
{
	بنية پیدا_کن_by_کلید_ctx *ctx = (بنية پیدا_کن_by_کلید_ctx *)_ctx;
	حرف *مسیر;

	/* we are looking for keys with names that *do not* match */
	إذا ((l->تطابق & HKF_تطابق_HOST) != 0)
		أرجع 0;
	/* not interested in marker lines */
	إذا (l->marker != MRK_NONE)
		أرجع 0;
	/* we are only interested in exact key matches */
	إذا (l->کلید == عدم || !sshkey_equal(ctx->کلید, l->کلید))
		أرجع 0;
	مسیر = try_tilde_unexpand(l->مسیر);
	debug_f("found matching key in %s:%lu", مسیر, l->linenum);
	ctx->نامها = xrecallocarray(ctx->نامها,
	    ctx->nnames, ctx->nnames + 1, حجم(*ctx->نامها));
	xasprintf(&ctx->نامها[ctx->nnames], "%s:%lu: %s", مسیر, l->linenum,
	    مقایسه_رشته(l->hosts, HASH_MAGIC, طول_رشته(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	حرر(مسیر);
	أرجع 0;
}

ساكن صحيح
hostkeys_پیدا_کن_by_کلید_hostfile(ثابت حرف *file, ثابت حرف *which,
    بنية پیدا_کن_by_کلید_ctx *ctx)
{
	صحيح r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	إذا ((r = hostkeys_foreach(file, hostkeys_پیدا_کن_by_کلید_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_کلید, 0)) != 0) {
		إذا (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			أرجع 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		أرجع r;
	}
	أرجع 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
ساكن فراغ
hostkeys_پیدا_کن_by_کلید(ثابت حرف *host, ثابت حرف *ip, ثابت بنية sshkey *کلید,
    حرف **user_hostfiles, u_int رقم_user_hostfiles,
    حرف **system_hostfiles, u_int رقم_system_hostfiles,
    حرف ***نامها, u_int *nnames)
{
	بنية پیدا_کن_by_کلید_ctx ctx = {عدم, عدم, عدم, عدم, 0};
	u_int i;

	*نامها = عدم;
	*nnames = 0;

	إذا (کلید == عدم || sshkey_is_cert(کلید))
		أرجع;

	ctx.host = host;
	ctx.ip = ip;
	ctx.کلید = کلید;

	لكل (i = 0; i < رقم_user_hostfiles; i++) {
		إذا (hostkeys_پیدا_کن_by_کلید_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			اذهب fail;
	}
	لكل (i = 0; i < رقم_system_hostfiles; i++) {
		إذا (hostkeys_پیدا_کن_by_کلید_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			اذهب fail;
	}
	/* success */
	*نامها = ctx.نامها;
	*nnames = ctx.nnames;
	ctx.نامها = عدم;
	ctx.nnames = 0;
	أرجع;
 fail:
	لكل (i = 0; i < ctx.nnames; i++)
		حرر(ctx.نامها[i]);
	حرر(ctx.نامها);
}

#تعریف_کن MAX_OTHER_نامها	8 /* Maximum number of names to list */
ساكن حرف *
other_hostkeys_پیام(ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *کلید,
    حرف **user_hostfiles, u_int رقم_user_hostfiles,
    حرف **system_hostfiles, u_int رقم_system_hostfiles)
{
	حرف *ret = عدم, **othernames = عدم;
	u_int i, n, رقم_othernames = 0;

	hostkeys_پیدا_کن_by_کلید(host, ip, کلید,
	    user_hostfiles, رقم_user_hostfiles,
	    system_hostfiles, رقم_system_hostfiles,
	    &othernames, &رقم_othernames);
	إذا (رقم_othernames == 0)
		أرجع xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = رقم_othernames;
	إذا (n > MAX_OTHER_نامها)
		n = MAX_OTHER_نامها;
	لكل (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	إذا (n < رقم_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    رقم_othernames - n);
	}
	لكل (i = 0; i < رقم_othernames; i++)
		حرر(othernames[i]);
	حرر(othernames);
	أرجع ret;
}

فراغ
بارگیری_hostkeys_command(بنية hostkeys *hostkeys, ثابت حرف *command_template,
    ثابت حرف *invocation, ثابت بنية ssh_conn_info *cinfo,
    ثابت بنية sshkey *host_کلید, ثابت حرف *hostfile_hostname)
{
	صحيح r, i, ac = 0;
	حرف *کلید_fp = عدم, *keytext = عدم, *tmp;
	حرف *command = عدم, *برچسب = عدم, **av = عدم;
	FILE *f = عدم;
	pid_t pid;
	فراغ (*osigchld)(صحيح);

	xasprintf(&برچسب, "KnownHostsCommand-%s", invocation);

	إذا (host_کلید != عدم) {
		إذا ((کلید_fp = sshkey_fingerprint(host_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		إذا ((r = sshkey_مقصد_base64(host_کلید, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	إذا (argv_تقسیم(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", برچسب,
		    command_template);
		اذهب بیرون;
	}
	إذا (ac == 0) {
		error("%s \"%s\" yielded no arguments", برچسب,
		    command_template);
		اذهب بیرون;
	}
	لكل (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_آرگومانها(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_کلید == عدم ? "NONE" : sshkey_ssh_name(host_کلید),
		    "f", کلید_fp == عدم ? "NONE" : کلید_fp,
		    "K", keytext == عدم ? "NONE" : keytext,
		    (حرف *)عدم);
		إذا (tmp == عدم)
			fatal_f("percent_expand failed");
		حرر(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	إذا ((pid = subprocess(برچسب, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_مسیر|
	    SSH_SUBPROCESS_PRESERVE_ENV, عدم, عدم, عدم)) == 0)
		اذهب بیرون;

	بارگیری_hostkeys_file(hostkeys, hostfile_hostname, برچسب, f, 1);

	إذا (exited_cleanly(pid, برچسب, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 بیرون:
	إذا (f != عدم)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	لكل (i = 0; i < ac; i++)
		حرر(av[i]);
	حرر(av);
	حرر(برچسب);
	حرر(command);
	حرر(کلید_fp);
	حرر(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#تعریف_کن RDRW	0
#تعریف_کن RDONLY	1
#تعریف_کن ROQUIET	2
ساكن صحيح
check_host_کلید(حرف *hostname, ثابت بنية ssh_conn_info *cinfo,
    بنية sockaddr *hostaddr, u_short پورت,
    بنية sshkey *host_کلید, صحيح readonly, صحيح clobber_پورت,
    حرف **user_hostfiles, u_int رقم_user_hostfiles,
    حرف **system_hostfiles, u_int رقم_system_hostfiles,
    ثابت حرف *hostfile_command)
{
	Host_وضعیت host_وضعیت = -1, ip_وضعیت = -1;
	بنية sshkey *raw_کلید = عدم;
	حرف *ip = عدم, *host = عدم;
	حرف hostline[1000], *hostp, *fp, *ra;
	حرف پیام[1024];
	ثابت حرف *type, *fail_reason = عدم;
	ثابت بنية hostkey_مدخل *host_یافت = عدم, *ip_یافت = عدم;
	صحيح len, cancelled_forwarding = 0, confirmed;
	صحيح local = sockaddr_is_local(hostaddr);
	صحيح r, want_cert = sshkey_is_cert(host_کلید), host_ip_تفاوت = 0;
	صحيح hostkey_trusted = 0; /* Known or explicitly accepted by user */
	بنية hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	إذا (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_کلید_alias == عدم) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		أرجع 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	إذا (strcspn(hostname, "@?*#[]|'\'\"\\") != طول_رشته(hostname)) {
		debug_f("invalid hostname \"%s\"; will not record: %s",
		    hostname, fail_reason);
		readonly = RDONLY;
	}

	/*
	 * Prepare the hostname and address strings used for hostkey lookup.
	 * In some cases, these will have a port number appended.
	 */
	get_hostfile_hostname_ipaddr(hostname, hostaddr,
	    clobber_پورت ? 0 : پورت, &host, &ip);

	/*
	 * Turn off check_host_ip if the connection is to localhost, via proxy
	 * command or if we don't have a hostname to compare with
	 */
	إذا (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != عدم))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	لكل (i = 0; i < رقم_user_hostfiles; i++)
		بارگیری_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	لكل (i = 0; i < رقم_system_hostfiles; i++)
		بارگیری_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	إذا (hostfile_command != عدم && !clobber_پورت) {
		بارگیری_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_کلید, host);
	}

	ip_hostkeys = عدم;
	إذا (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		لكل (i = 0; i < رقم_user_hostfiles; i++)
			بارگیری_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		لكل (i = 0; i < رقم_system_hostfiles; i++)
			بارگیری_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		إذا (hostfile_command != عدم && !clobber_پورت) {
			بارگیری_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_کلید, ip);
		}
	}

 retry:
	إذا (!hostkey_accepted_by_hostkeyalgs(host_کلید)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_کلید));
		اذهب fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_کلید);
	type = sshkey_type(host_کلید);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_وضعیت = check_کلید_درون_hostkeys(host_hostkeys, host_کلید,
	    &host_یافت);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	إذا (!readonly && (رقم_user_hostfiles == 0 ||
	    (host_یافت != عدم && host_یافت->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	إذا (!want_cert && ip_hostkeys != عدم) {
		ip_وضعیت = check_کلید_درون_hostkeys(ip_hostkeys, host_کلید,
		    &ip_یافت);
		إذا (host_وضعیت == HOST_تغییریافته &&
		    (ip_وضعیت != HOST_تغییریافته ||
		    (ip_یافت != عدم &&
		    !sshkey_equal(ip_یافت->کلید, host_یافت->کلید))))
			host_ip_تفاوت = 1;
	} وإلا
		ip_وضعیت = host_وضعیت;

	بدل (host_وضعیت) {
	حالة HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_یافت->file, host_یافت->سطر);
		إذا (want_cert) {
			إذا (sshkey_cert_check_host(host_کلید,
			    options.host_کلید_alias == عدم ?
			    hostname : options.host_کلید_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				اذهب fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			إذا (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		إذا (options.update_hostkeys != 0 &&
		    (مسیر_درون_hostfiles(host_یافت->file,
		    system_hostfiles, رقم_system_hostfiles) ||
		    (ip_وضعیت == HOST_OK && ip_یافت != عدم &&
		    مسیر_درون_hostfiles(ip_یافت->file,
		    system_hostfiles, رقم_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		إذا (options.update_hostkeys != 0 && host_یافت->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		إذا (options.check_host_ip && ip_وضعیت == HOST_NEW) {
			إذا (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			وإلا إذا (!جمع_کن_host_مقصد_hostfile(user_hostfiles[0], ip,
			    host_کلید, options.hash_معلوم_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			وإلا
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} وإلا إذا (options.visual_host_کلید) {
			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			إذا (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			حرر(ra);
			حرر(fp);
		}
		hostkey_trusted = 1;
		اكسر;
	حالة HOST_NEW:
		إذا (options.host_کلید_alias == عدم && پورت != 0 &&
		    پورت != SSH_DEFAULT_پورت && !clobber_پورت) {
			debug("checking without port identifier");
			إذا (check_host_کلید(hostname, cinfo, hostaddr, 0,
			    host_کلید, ROQUIET, 1,
			    user_hostfiles, رقم_user_hostfiles,
			    system_hostfiles, رقم_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				اكسر;
			}
		}
		إذا (readonly || want_cert)
			اذهب fail;
		/* The host is new. */
		إذا (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			اذهب fail;
		} وإلا إذا (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			حرف *msg1 = عدم, *msg2 = عدم;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			إذا (show_other_کلیدها(host_hostkeys, host_کلید)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} وإلا
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_کلید,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			إذا (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			إذا (options.visual_host_کلید)
				xextendf(&msg1, "\n", "%s", ra);
			إذا (options.verify_host_کلید_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_کلید_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			إذا ((msg2 = other_hostkeys_پیام(host, ip, host_کلید,
			    user_hostfiles, رقم_user_hostfiles,
			    system_hostfiles, رقم_system_hostfiles)) != عدم)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			حرر(ra);
			حرر(fp);
			حرر(msg1);
			حرر(msg2);
			إذا (!confirmed)
				اذهب fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		إذا (options.check_host_ip && ip_وضعیت == HOST_NEW) {
			snprintf(hostline, حجم(hostline), "%s,%s", host, ip);
			hostp = hostline;
			إذا (options.hash_معلوم_hosts) {
				/* Add hash of host and IP separately */
				r = جمع_کن_host_مقصد_hostfile(user_hostfiles[0],
				    host, host_کلید, options.hash_معلوم_hosts) &&
				    جمع_کن_host_مقصد_hostfile(user_hostfiles[0], ip,
				    host_کلید, options.hash_معلوم_hosts);
			} وإلا {
				/* Add unhashed "host,ip" */
				r = جمع_کن_host_مقصد_hostfile(user_hostfiles[0],
				    hostline, host_کلید,
				    options.hash_معلوم_hosts);
			}
		} وإلا {
			r = جمع_کن_host_مقصد_hostfile(user_hostfiles[0], host,
			    host_کلید, options.hash_معلوم_hosts);
			hostp = host;
		}

		إذا (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		وإلا
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		اكسر;
	حالة HOST_REVOKED:
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
		إذا (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			اذهب fail;
		}
		اذهب continue_unsafe;

	حالة HOST_تغییریافته:
		إذا (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_یافت->file, host_یافت->سطر);
			اذهب fail;
		}
		إذا (readonly == ROQUIET)
			اذهب fail;
		إذا (options.check_host_ip && host_ip_تفاوت) {
			حرف *کلید_پیام;
			إذا (ip_وضعیت == HOST_NEW)
				کلید_پیام = "is unknown";
			وإلا إذا (ip_وضعیت == HOST_OK)
				کلید_پیام = "is unchanged";
			وإلا
				کلید_پیام = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", کلید_پیام);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			إذا (ip_وضعیت != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_یافت->file, ip_یافت->سطر);
		}
		/* The host key has changed. */
		warn_تغییریافته_کلید(host_کلید);
		إذا (رقم_user_hostfiles > 0 || رقم_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", رقم_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_یافت->کلید),
		    host_یافت->file, host_یافت->سطر);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		إذا (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			اذهب fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		إذا (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		إذا (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		إذا (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		إذا (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		إذا (options.رقم_local_forwards > 0 ||
		    options.رقم_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.رقم_local_forwards =
			    options.رقم_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		إذا (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		إذا (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		إذا (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		اكسر;
	حالة HOST_یافت:
		fatal("internal error");
		اكسر;
	}

	إذا (options.check_host_ip && host_وضعیت != HOST_تغییریافته &&
	    ip_وضعیت == HOST_تغییریافته) {
		snprintf(پیام, حجم(پیام),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_یافت->file, ip_یافت->سطر);
		إذا (host_وضعیت == HOST_OK) {
			len = طول_رشته(پیام);
			snprintf(پیام + len, حجم(پیام) - len,
			    "\nMatching host key in %s:%lu",
			    host_یافت->file, host_یافت->سطر);
		}
		إذا (options.strict_host_کلید_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(پیام, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", حجم(پیام));
			إذا (!confirm(پیام, عدم))
				اذهب fail;
		} وإلا إذا (options.strict_host_کلید_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", پیام);
			error("Exiting, you have requested strict checking.");
			اذهب fail;
		} وإلا {
			logit("%s", پیام);
		}
	}

	إذا (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_کلید);
	حرر(ip);
	حرر(host);
	إذا (host_hostkeys != عدم)
		free_hostkeys(host_hostkeys);
	إذا (ip_hostkeys != عدم)
		free_hostkeys(ip_hostkeys);
	أرجع 0;

fail:
	إذا (want_cert && host_وضعیت != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		إذا ((r = sshkey_from_خصوصی(host_کلید, &raw_کلید)) != 0)
			fatal_fr(r, "decode key");
		إذا ((r = sshkey_drop_cert(raw_کلید)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_کلید = raw_کلید;
		اذهب retry;
	}
	sshkey_free(raw_کلید);
	حرر(ip);
	حرر(host);
	إذا (host_hostkeys != عدم)
		free_hostkeys(host_hostkeys);
	إذا (ip_hostkeys != عدم)
		free_hostkeys(ip_hostkeys);
	أرجع -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
صحيح
verify_host_کلید(حرف *host, بنية sockaddr *hostaddr, بنية sshkey *host_کلید,
    ثابت بنية ssh_conn_info *cinfo)
{
	u_int i;
	صحيح r = -1, flags = 0;
	حرف valid[64], *fp = عدم, *cafp = عدم;
	بنية sshkey *plain = عدم;

	إذا ((fp = sshkey_fingerprint(host_کلید,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
		error_fr(r, "fingerprint host key");
		r = -1;
		اذهب بیرون;
	}

	إذا (sshkey_is_cert(host_کلید)) {
		إذا ((cafp = sshkey_fingerprint(host_کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			اذهب بیرون;
		}
		sshkey_format_cert_validity(host_کلید->cert,
		    valid, حجم(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_کلید), fp,
		    (بیعلامت دراز دراز)host_کلید->cert->serial,
		    host_کلید->cert->کلید_id,
		    sshkey_ssh_name(host_کلید->cert->signature_کلید), cafp,
		    valid);
		لكل (i = 0; i < host_کلید->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_کلید->cert->principals[i]);
		}
	} وإلا {
		debug("Server host key: %s %s", sshkey_ssh_name(host_کلید), fp);
	}

	إذا (sshkey_equal(قبلی_host_کلید, host_کلید)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_کلید), fp);
		r = 0;
		اذهب بیرون;
	}

	/* Check in RevokedHostKeys files if specified */
	لكل (i = 0; i < options.رقم_revoked_host_کلیدها; i++) {
		r = sshkey_check_revoked(host_کلید,
		    options.revoked_host_کلیدها[i]);
		بدل (r) {
		حالة 0:
			اكسر; /* not revoked */
		حالة SSH_ERR_کلید_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_کلید), fp,
			    options.revoked_host_کلیدها[i]);
			r = -1;
			اذهب بیرون;
		افتراضي:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_کلید),
			    fp, options.revoked_host_کلیدها[i]);
			r = -1;
			اذهب بیرون;
		}
	}

	إذا (options.verify_host_کلید_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		إذا ((r = sshkey_from_خصوصی(host_کلید, &plain)) != 0)
			اذهب بیرون;
		إذا (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		إذا (verify_host_کلید_dns(host, hostaddr, plain, &flags) == 0) {
			إذا (flags & DNS_VERIFY_یافت) {
				إذا (options.verify_host_کلید_dns == 1 &&
				    flags & DNS_VERIFY_تطابق &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					اذهب بیرون;
				}
				إذا (flags & DNS_VERIFY_تطابق) {
					matching_host_کلید_dns = 1;
				} وإلا {
					warn_تغییریافته_کلید(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_کلید(host, cinfo, hostaddr, options.پورت, host_کلید,
	    RDRW, 0, options.user_hostfiles, options.رقم_user_hostfiles,
	    options.system_hostfiles, options.رقم_system_hostfiles,
	    options.معلوم_hosts_command);

بیرون:
	sshkey_free(plain);
	حرر(fp);
	حرر(cafp);
	إذا (r == 0 && host_کلید != عدم) {
		sshkey_free(قبلی_host_کلید);
		r = sshkey_from_خصوصی(host_کلید, &قبلی_host_کلید);
	}

	أرجع r;
}

ساكن فراغ
warn_nonpq_kex(فراغ)
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
فراغ
ssh_login(بنية ssh *ssh, Sensitive *sensitive, ثابت حرف *orighost,
    بنية sockaddr_storage *hostaddr, u_short پورت, بنية passwd *pw,
    صحيح timeout_ms, ثابت بنية ssh_conn_info *cinfo)
{
	حرف *host;
	حرف *server_user, *local_user;
	صحيح r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	إذا ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.نسخه_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	إذا ((ssh->compat & SSH_BUG_NOREKEY)) {
		logit("Warning: this server does not support rekeying.");
		logit("This session will eventually fail");
	}

	/* Put the connection into non-blocking mode. */
	ssh_packet_مجموعه_nonblocking(ssh);

	/* key exchange */
	/* authenticate user */
	debug("Authenticating to %s:%d as '%s'", host, پورت, server_user);
	ssh_kex2(ssh, host, hostaddr, پورت, cinfo);
	kex_مجموعه_warn_weak_crypto(ssh, options.warn_weak_crypto &&
	    !options.kex_algorithms_مجموعه);
	إذا (!options.kex_algorithms_مجموعه && ssh->kex != عدم &&
	    ssh->kex->name != عدم && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	حرر(local_user);
	حرر(host);
}

/* print all known host keys for a given host, but skip keys of given type */
ساكن صحيح
show_other_کلیدها(بنية hostkeys *hostkeys, بنية sshkey *کلید)
{
	صحيح type[] = {
		کلید_RSA,
		کلید_ECDSA,
		کلید_ED25519,
		کلید_MLDSA44_ED25519,
		-1
	};
	صحيح i, ret = 0;
	حرف *fp, *ra;
	ثابت بنية hostkey_مدخل *یافت;

	لكل (i = 0; type[i] != -1; i++) {
		إذا (type[i] == کلید->type)
			استمر;
		إذا (!lookup_کلید_درون_hostkeys_by_type(hostkeys, type[i],
		    -1, &یافت))
			استمر;
		fp = sshkey_fingerprint(یافت->کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(یافت->کلید,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		إذا (fp == عدم || ra == عدم)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(یافت->کلید),
		    یافت->host, یافت->file, یافت->سطر,
		    sshkey_type(یافت->کلید), fp);
		إذا (options.visual_host_کلید)
			logit("%s", ra);
		حرر(ra);
		حرر(fp);
		ret = 1;
	}
	أرجع ret;
}

ساكن فراغ
warn_تغییریافته_کلید(بنية sshkey *host_کلید)
{
	حرف *fp;

	fp = sshkey_fingerprint(host_کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	إذا (fp == عدم)
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

	حرر(fp);
}

/*
 * Execute a local command
 */
صحيح
ssh_local_cmd(ثابت حرف *آرگومانها)
{
	حرف *shell;
	pid_t pid;
	صحيح وضعیت;
	فراغ (*osighand)(صحيح);

	إذا (!options.permit_local_command ||
	    آرگومانها == عدم || !*آرگومانها)
		أرجع (1);

	إذا ((shell = getenv("SHELL")) == عدم || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	إذا (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, آرگومانها);
		execl(shell, shell, "-c", آرگومانها, (حرف *)عدم);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, آرگومانها, strerror(errno));
		_exit(1);
	} وإلا إذا (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	طالما (waitpid(pid, &وضعیت, 0) == -1)
		إذا (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	إذا (!WIFEXITED(وضعیت))
		أرجع (1);

	أرجع (WEXITSTATUS(وضعیت));
}

فراغ
maybe_جمع_کن_کلید_مقصد_agent(ثابت حرف *authfile, بنية sshkey *خاص,
    ثابت حرف *comment, ثابت حرف *passphrase)
{
	صحيح auth_sock = -1, r;
	ثابت حرف *skprovider = عدم;

	إذا (options.جمع_کن_کلیدها_مقصد_agent == 0)
		أرجع;

	إذا ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		أرجع;
	}

	إذا (options.جمع_کن_کلیدها_مقصد_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		أرجع;
	}
	إذا (sshkey_is_sk(خاص))
		skprovider = options.sk_provider;
	إذا ((r = ssh_جمع_کن_عنصر_خنثی_constrained(auth_sock, خاص,
	    comment == عدم ? authfile : comment,
	    options.جمع_کن_کلیدها_مقصد_agent_lifespan,
	    (options.جمع_کن_کلیدها_مقصد_agent == 3), skprovider, عدم, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	وإلا
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
