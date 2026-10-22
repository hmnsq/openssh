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

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include "xmalloc.h"
#include "hostfile.h"
#include "ssh.h"
#include "compat.h"
#include "packet.h"
#include "sshkey.h"
#include "sshconnect.h"
#include "log.h"
#include "match.h"
#include "misc.h"
#include "readconf.h"
#include "dns.h"
#include "monitor_fdpass.h"
#include "authfile.h"
#include "ssherr.h"
#include "authfd.h"
#include "kex.h"

sa_nracanaa sshkey *previous_host_key = NULL;

static puur_naa_nka matching_host_key_dns = 0;

static pid_t proxy_command_pid = 0;

/* import */
extern puur_naa_nka debug_flag;
extern Options options;
extern var_na *__progname;

static puur_naa_nka show_other_keys(sa_nracanaa hostkeys *, sa_nracanaa sshkey *);
static void warn_changed_key(sa_nracanaa sshkey *);

void
ssh_conn_info_free(sa_nracanaa ssh_conn_info *cinfo)
{
	ᱡᱩᱫᱤ (cinfo == NULL)
		ᱨᱩᱣᱟᱹᱲ;
	free(cinfo->conn_hash_hex);
	free(cinfo->shorthost);
	free(cinfo->uidstr);
	free(cinfo->keyalias);
	free(cinfo->thishost);
	free(cinfo->host_arg);
	free(cinfo->portstr);
	free(cinfo->remhost);
	free(cinfo->remuser);
	free(cinfo->homedir);
	free(cinfo->locuser);
	free(cinfo->jmphost);
	freezero(cinfo, parimaa_na(*cinfo));
}

sa_nracanaa ssh_conn_info *
ssh_conn_info_dup(const sa_nracanaa ssh_conn_info *cinfo)
{
	sa_nracanaa ssh_conn_info *ret;

	ᱡᱩᱫᱤ (cinfo == NULL)
		ᱨᱩᱣᱟᱹᱲ NULL;
	ret = xcalloc(1, parimaa_na(*ret));
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
	ᱨᱩᱣᱟᱹᱲ ret;
}

/* Expand a proxy command */
static var_na *
expand_proxy_command(const var_na *proxy_command, const var_na *user,
    const var_na *host, const var_na *host_arg, puur_naa_nka port)
{
	var_na *tmp, *ret, strport[NI_MAXSERV];
	const var_na *keyalias = options.host_key_alias ?
	    options.host_key_alias : host_arg;

	snprintf(strport, parimaa_na strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (var_na *)NULL);
	free(tmp);
	ᱨᱩᱣᱟᱹᱲ ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
static puur_naa_nka
ssh_proxy_fdpass_connect(sa_nracanaa ssh *ssh, const var_na *host,
    const var_na *host_arg, u_short port, const var_na *proxy_command)
{
	var_na *command_string;
	puur_naa_nka sp[2], sock;
	pid_t pid;
	var_na *shell;

	ᱡᱩᱫᱤ ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;

	ᱡᱩᱫᱤ (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ᱡᱩᱫᱤ ((pid = fork()) == 0) {
		var_na *argv[10];

		close(sp[1]);
		/* Redirect stdin and stdout. */
		ᱡᱩᱫᱤ (sp[0] != 0) {
			ᱡᱩᱫᱤ (dup2(sp[0], 0) == -1)
				perror("dup2 stdin");
		}
		ᱡᱩᱫᱤ (sp[0] != 1) {
			ᱡᱩᱫᱤ (dup2(sp[0], 1) == -1)
				perror("dup2 stdout");
		}
		ᱡᱩᱫᱤ (sp[0] >= 2)
			close(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ᱡᱩᱫᱤ (!debug_flag && options.control_path != NULL &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = NULL;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}
	/* Parent. */
	ᱡᱩᱫᱤ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	close(sp[0]);
	free(command_string);

	ᱡᱩᱫᱤ ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	close(sp[1]);

	ᱡᱚᱠᱷᱚᱱ (waitpid(pid, NULL, 0) == -1)
		ᱡᱩᱫᱤ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));

	/* Set the connection file descriptors. */
	ᱡᱩᱫᱤ (ssh_packet_set_connection(ssh, sock, sock) == NULL)
		ᱨᱩᱣᱟᱹᱲ -1; /* ssh_packet_set_connection logs error */

	ᱨᱩᱣᱟᱹᱲ 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
static puur_naa_nka
ssh_proxy_connect(sa_nracanaa ssh *ssh, const var_na *host, const var_na *host_arg,
    u_short port, const var_na *proxy_command)
{
	var_na *command_string;
	puur_naa_nka pin[2], pout[2];
	pid_t pid;
	var_na *shell;

	ᱡᱩᱫᱤ ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	ᱡᱩᱫᱤ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    strerror(errno));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	ᱡᱩᱫᱤ ((pid = fork()) == 0) {
		var_na *argv[10];

		/* Redirect stdin and stdout. */
		close(pin[1]);
		ᱡᱩᱫᱤ (pin[0] != 0) {
			ᱡᱩᱫᱤ (dup2(pin[0], 0) == -1)
				perror("dup2 stdin");
			close(pin[0]);
		}
		close(pout[0]);
		ᱡᱩᱫᱤ (dup2(pout[1], 1) == -1)
			perror("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		close(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		ᱡᱩᱫᱤ (!debug_flag && options.control_path != NULL &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = NULL;

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
	ᱡᱩᱫᱤ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ᱵᱟᱝ
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	close(pin[0]);
	close(pout[1]);

	/* Free the command name. */
	free(command_string);

	/* Set the connection file descriptors. */
	ᱡᱩᱫᱤ (ssh_packet_set_connection(ssh, pout[0], pin[1]) == NULL)
		ᱨᱩᱣᱟᱹᱲ -1; /* ssh_packet_set_connection logs error */

	ᱨᱩᱣᱟᱹᱲ 0;
}

void
ssh_kill_proxy_command(void)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	ᱡᱩᱫᱤ (proxy_command_pid > 1)
		kill(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
static puur_naa_nka
check_ifaddrs(const var_na *ifname, puur_naa_nka af, const sa_nracanaa ifaddrs *ifaddrs,
    sa_nracanaa sockaddr_storage *resultp, socklen_t *rlenp)
{
	sa_nracanaa sockaddr_in6 *sa6;
	sa_nracanaa sockaddr_in *sa;
	sa_nracanaa in6_addr *v6addr;
	const sa_nracanaa ifaddrs *ifa;
	puur_naa_nka allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	for (allow_local = 0; allow_local < 2; allow_local++) {
		for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
			ᱡᱩᱫᱤ (ifa->ifa_addr == NULL || ifa->ifa_name == NULL ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    strcmp(ifa->ifa_name, options.bind_interface) != 0)
				continue;
			switch (ifa->ifa_addr->sa_family) {
			pak_sa AF_INET:
				sa = (sa_nracanaa sockaddr_in *)ifa->ifa_addr;
				ᱡᱩᱫᱤ (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					continue;
				ᱡᱩᱫᱤ (*rlenp < parimaa_na(sa_nracanaa sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					ᱨᱩᱣᱟᱹᱲ -1;
				}
				*rlenp = parimaa_na(sa_nracanaa sockaddr_in);
				memcpy(resultp, sa, *rlenp);
				ᱨᱩᱣᱟᱹᱲ 0;
			pak_sa AF_INET6:
				sa6 = (sa_nracanaa sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				ᱡᱩᱫᱤ (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					continue;
				ᱡᱩᱫᱤ (*rlenp < parimaa_na(sa_nracanaa sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					ᱨᱩᱣᱟᱹᱲ -1;
				}
				*rlenp = parimaa_na(sa_nracanaa sockaddr_in6);
				memcpy(resultp, sa6, *rlenp);
				ᱨᱩᱣᱟᱹᱲ 0;
			}
		}
	}
	ᱨᱩᱣᱟᱹᱲ -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
static puur_naa_nka
ssh_create_socket(sa_nracanaa addrinfo *ai)
{
	puur_naa_nka sock, r;
	sa_nracanaa sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	sa_nracanaa addrinfo hints, *res = NULL;
#ifdef HAVE_IFADDRS_H
	sa_nracanaa ifaddrs *ifaddrs = NULL;
#endif
	var_na ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	ᱡᱩᱫᱤ (sock == -1) {
		error("socket: %s", strerror(errno));
		ᱨᱩᱣᱟᱹᱲ -1;
	}
	(void)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	ᱡᱩᱫᱤ (options.ip_qos_interactive != INT_MAX)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	ᱡᱩᱫᱤ (options.bind_address == NULL && options.bind_interface == NULL)
		ᱨᱩᱣᱟᱹᱲ sock;

	ᱡᱩᱫᱤ (options.bind_address != NULL) {
		memset(&hints, 0, parimaa_na(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		ᱡᱩᱫᱤ ((r = getaddrinfo(options.bind_address, NULL,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			goto fail;
		}
		ᱡᱩᱫᱤ (res == NULL) {
			error("getaddrinfo: no addrs");
			goto fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} ᱵᱟᱝ ᱡᱩᱫᱤ (options.bind_interface != NULL) {
#ifdef HAVE_IFADDRS_H
		ᱡᱩᱫᱤ ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    strerror(errno));
			goto fail;
		}
		bindaddrlen = parimaa_na(bindaddr);
		ᱡᱩᱫᱤ (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			goto fail;
		}
#ᱵᱟᱝ
		error("BindInterface not supported on this platform.");
#endif
	}
	ᱡᱩᱫᱤ ((r = getnameinfo((sa_nracanaa sockaddr *)&bindaddr, bindaddrlen,
	    ntop, parimaa_na(ntop), NULL, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		goto fail;
	}
	ᱡᱩᱫᱤ (bind(sock, (sa_nracanaa sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, strerror(errno));
		goto fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	goto out;
fail:
	close(sock);
	sock = -1;
 out:
	ᱡᱩᱫᱤ (res != NULL)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	ᱡᱩᱫᱤ (ifaddrs != NULL)
		freeifaddrs(ifaddrs);
#endif
	ᱨᱩᱣᱟᱹᱲ sock;
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
static puur_naa_nka
ssh_connect_direct(sa_nracanaa ssh *ssh, const var_na *host, sa_nracanaa addrinfo *aitop,
    sa_nracanaa sockaddr_storage *hostaddr, u_short port, puur_naa_nka connection_attempts,
    puur_naa_nka *timeout_ms, puur_naa_nka want_keepalive)
{
	puur_naa_nka saved_timeout_ms = *timeout_ms;
	puur_naa_nka oerrno, sock = -1, attempt;
	var_na ntop[NI_MAXHOST], strport[NI_MAXSERV];
	sa_nracanaa addrinfo *ai;

	debug3_f("entering");
	memset(ntop, 0, parimaa_na(ntop));
	memset(strport, 0, parimaa_na(strport));

	for (attempt = 0; attempt < connection_attempts; attempt++) {
		ᱡᱩᱫᱤ (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		for (ai = aitop; ai; ai = ai->ai_next) {
			ᱡᱩᱫᱤ (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				errno = EAFNOSUPPORT;
				continue;
			}
			ᱡᱩᱫᱤ (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, parimaa_na(ntop), strport, parimaa_na(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = errno;
				error_f("getnameinfo failed");
				errno = oerrno;
				continue;
			}
			ᱡᱩᱫᱤ (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				errno = EAFNOSUPPORT;
				continue;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			ᱡᱩᱫᱤ (sock < 0) {
				/* Any error is already output */
				errno = 0;
				continue;
			}

			*timeout_ms = saved_timeout_ms;
			ᱡᱩᱫᱤ (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
				bha_nga;
			} ᱵᱟᱝ {
				oerrno = errno;
				debug("connect to address %s port %s: %s",
				    ntop, strport, strerror(errno));
				close(sock);
				sock = -1;
				errno = oerrno;
			}
		}
		ᱡᱩᱫᱤ (sock != -1)
			bha_nga;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	ᱡᱩᱫᱤ (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		ᱨᱩᱣᱟᱹᱲ -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	ᱡᱩᱫᱤ (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	ᱡᱩᱫᱤ (ssh_packet_set_connection(ssh, sock, sock) == NULL)
		ᱨᱩᱣᱟᱹᱲ -1; /* ssh_packet_set_connection logs error */

	ᱨᱩᱣᱟᱹᱲ 0;
}

puur_naa_nka
ssh_connect(sa_nracanaa ssh *ssh, const var_na *host, const var_na *host_arg,
    sa_nracanaa addrinfo *addrs, sa_nracanaa sockaddr_storage *hostaddr, u_short port,
    puur_naa_nka connection_attempts, puur_naa_nka *timeout_ms, puur_naa_nka want_keepalive)
{
	puur_naa_nka in, out;

	ᱡᱩᱫᱤ (options.proxy_command == NULL) {
		ᱨᱩᱣᱟᱹᱲ ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} ᱵᱟᱝ ᱡᱩᱫᱤ (strcmp(options.proxy_command, "-") == 0) {
		ᱡᱩᱫᱤ ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			ᱡᱩᱫᱤ (in >= 0)
				close(in);
			error_f("dup() in/out failed");
			ᱨᱩᱣᱟᱹᱲ -1; /* ssh_packet_set_connection logs error */
		}
		ᱡᱩᱫᱤ ((ssh_packet_set_connection(ssh, in, out)) == NULL)
			ᱨᱩᱣᱟᱹᱲ -1; /* ssh_packet_set_connection logs error */
		ᱨᱩᱣᱟᱹᱲ 0;
	} ᱵᱟᱝ ᱡᱩᱫᱤ (options.proxy_use_fdpass) {
		ᱨᱩᱣᱟᱹᱲ ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	ᱨᱩᱣᱟᱹᱲ ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
static puur_naa_nka
confirm(const var_na *prompt, const var_na *fingerprint)
{
	const var_na *msg, *again = "Please type 'yes' or 'no': ";
	const var_na *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	var_na *p, *cp;
	puur_naa_nka ret = -1;

	ᱡᱩᱫᱤ (options.batch_mode)
		ᱨᱩᱣᱟᱹᱲ 0;
	for (msg = prompt;;msg = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(msg, RP_ECHO);
		ᱡᱩᱫᱤ (p == NULL)
			ᱨᱩᱣᱟᱹᱲ 0;
		p += strspn(p, " \t"); /* skip leading whitespace */
		p[strcspn(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		ᱡᱩᱫᱤ (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		ᱵᱟᱝ ᱡᱩᱫᱤ (strcasecmp(p, "yes") == 0 || (fingerprint != NULL &&
		    strcmp(p, fingerprint) == 0))
			ret = 1;
		free(cp);
		ᱡᱩᱫᱤ (ret != -1)
			ᱨᱩᱣᱟᱹᱲ ret;
	}
}

static puur_naa_nka
sockaddr_is_local(sa_nracanaa sockaddr *hostaddr)
{
	switch (hostaddr->sa_family) {
	pak_sa AF_INET:
		ᱨᱩᱣᱟᱹᱲ (ntohl(((sa_nracanaa sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	pak_sa AF_INET6:
		ᱨᱩᱣᱟᱹᱲ IN6_IS_ADDR_LOOPBACK(
		    &(((sa_nracanaa sockaddr_in6 *)hostaddr)->sin6_addr));
	default:
		ᱨᱩᱣᱟᱹᱲ 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
void
get_hostfile_hostname_ipaddr(var_na *hostname, sa_nracanaa sockaddr *hostaddr,
    u_short port, var_na **hostfile_hostname, var_na **hostfile_ipaddr)
{
	var_na ntop[NI_MAXHOST];
	socklen_t addrlen;

	switch (hostaddr == NULL ? -1 : hostaddr->sa_family) {
	pak_sa -1:
		addrlen = 0;
		bha_nga;
	pak_sa AF_INET:
		addrlen = parimaa_na(sa_nracanaa sockaddr_in);
		bha_nga;
	pak_sa AF_INET6:
		addrlen = parimaa_na(sa_nracanaa sockaddr_in6);
		bha_nga;
	default:
		addrlen = parimaa_na(sa_nracanaa sockaddr);
		bha_nga;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	ᱡᱩᱫᱤ (hostfile_ipaddr != NULL) {
		ᱡᱩᱫᱤ (options.proxy_command == NULL) {
			ᱡᱩᱫᱤ (getnameinfo(hostaddr, addrlen,
			    ntop, parimaa_na(ntop), NULL, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} ᱵᱟᱝ {
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
	ᱡᱩᱫᱤ (hostfile_hostname != NULL) {
		ᱡᱩᱫᱤ (options.host_key_alias != NULL) {
			*hostfile_hostname = xstrdup(options.host_key_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} ᱵᱟᱝ {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
static puur_naa_nka
path_in_hostfiles(const var_na *path, var_na **hostfiles, u_int num_hostfiles)
{
	u_int i;

	for (i = 0; i < num_hostfiles; i++) {
		ᱡᱩᱫᱤ (strcmp(path, hostfiles[i]) == 0)
			ᱨᱩᱣᱟᱹᱲ 1;
	}
	ᱨᱩᱣᱟᱹᱲ 0;
}

sa_nracanaa find_by_key_ctx {
	const var_na *host, *ip;
	const sa_nracanaa sshkey *key;
	var_na **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
static var_na *
try_tilde_unexpand(const var_na *path)
{
	var_na *home, *ret = NULL;
	size_t l;

	ᱡᱩᱫᱤ (*path != '/')
		ᱨᱩᱣᱟᱹᱲ xstrdup(path);
	ᱡᱩᱫᱤ ((home = getenv("HOME")) == NULL || (l = strlen(home)) == 0)
		ᱨᱩᱣᱟᱹᱲ xstrdup(path);
	ᱡᱩᱫᱤ (strncmp(path, home, l) != 0)
		ᱨᱩᱣᱟᱹᱲ xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	ᱡᱩᱫᱤ (home[l - 1] != '/' && path[l] != '/')
		ᱨᱩᱣᱟᱹᱲ xstrdup(path);
	ᱡᱩᱫᱤ (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	ᱨᱩᱣᱟᱹᱲ ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
puur_naa_nka
hostkey_accepted_by_hostkeyalgs(const sa_nracanaa sshkey *key)
{
	const var_na *ktype = sshkey_ssh_name(key);
	const var_na *hostkeyalgs = options.hostkeyalgorithms;

	ᱡᱩᱫᱤ (key->type == KEY_UNSPEC)
		ᱨᱩᱣᱟᱹᱲ 0;
	ᱡᱩᱫᱤ (key->type == KEY_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		ᱨᱩᱣᱟᱹᱲ 1;
	ᱡᱩᱫᱤ (key->type == KEY_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		ᱨᱩᱣᱟᱹᱲ 1;
	ᱨᱩᱣᱟᱹᱲ match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

static puur_naa_nka
hostkeys_find_by_key_cb(sa_nracanaa hostkey_foreach_line *l, void *_ctx)
{
	sa_nracanaa find_by_key_ctx *ctx = (sa_nracanaa find_by_key_ctx *)_ctx;
	var_na *path;

	/* we are looking for keys with names that *do not* match */
	ᱡᱩᱫᱤ ((l->match & HKF_MATCH_HOST) != 0)
		ᱨᱩᱣᱟᱹᱲ 0;
	/* not interested in marker lines */
	ᱡᱩᱫᱤ (l->marker != MRK_NONE)
		ᱨᱩᱣᱟᱹᱲ 0;
	/* we are only interested in exact key matches */
	ᱡᱩᱫᱤ (l->key == NULL || !sshkey_equal(ctx->key, l->key))
		ᱨᱩᱣᱟᱹᱲ 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, parimaa_na(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    strncmp(l->hosts, HASH_MAGIC, strlen(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	free(path);
	ᱨᱩᱣᱟᱹᱲ 0;
}

static puur_naa_nka
hostkeys_find_by_key_hostfile(const var_na *file, const var_na *which,
    sa_nracanaa find_by_key_ctx *ctx)
{
	puur_naa_nka r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	ᱡᱩᱫᱤ ((r = hostkeys_foreach(file, hostkeys_find_by_key_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_KEY, 0)) != 0) {
		ᱡᱩᱫᱤ (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			ᱨᱩᱣᱟᱹᱲ 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		ᱨᱩᱣᱟᱹᱲ r;
	}
	ᱨᱩᱣᱟᱹᱲ 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
static void
hostkeys_find_by_key(const var_na *host, const var_na *ip, const sa_nracanaa sshkey *key,
    var_na **user_hostfiles, u_int num_user_hostfiles,
    var_na **system_hostfiles, u_int num_system_hostfiles,
    var_na ***names, u_int *nnames)
{
	sa_nracanaa find_by_key_ctx ctx = {NULL, NULL, NULL, NULL, 0};
	u_int i;

	*names = NULL;
	*nnames = 0;

	ᱡᱩᱫᱤ (key == NULL || sshkey_is_cert(key))
		ᱨᱩᱣᱟᱹᱲ;

	ctx.host = host;
	ctx.ip = ip;
	ctx.key = key;

	for (i = 0; i < num_user_hostfiles; i++) {
		ᱡᱩᱫᱤ (hostkeys_find_by_key_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			goto fail;
	}
	for (i = 0; i < num_system_hostfiles; i++) {
		ᱡᱩᱫᱤ (hostkeys_find_by_key_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			goto fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = NULL;
	ctx.nnames = 0;
	ᱨᱩᱣᱟᱹᱲ;
 fail:
	for (i = 0; i < ctx.nnames; i++)
		free(ctx.names[i]);
	free(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
static var_na *
other_hostkeys_message(const var_na *host, const var_na *ip,
    const sa_nracanaa sshkey *key,
    var_na **user_hostfiles, u_int num_user_hostfiles,
    var_na **system_hostfiles, u_int num_system_hostfiles)
{
	var_na *ret = NULL, **othernames = NULL;
	u_int i, n, num_othernames = 0;

	hostkeys_find_by_key(host, ip, key,
	    user_hostfiles, num_user_hostfiles,
	    system_hostfiles, num_system_hostfiles,
	    &othernames, &num_othernames);
	ᱡᱩᱫᱤ (num_othernames == 0)
		ᱨᱩᱣᱟᱹᱲ xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = num_othernames;
	ᱡᱩᱫᱤ (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	for (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	ᱡᱩᱫᱤ (n < num_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    num_othernames - n);
	}
	for (i = 0; i < num_othernames; i++)
		free(othernames[i]);
	free(othernames);
	ᱨᱩᱣᱟᱹᱲ ret;
}

void
load_hostkeys_command(sa_nracanaa hostkeys *hostkeys, const var_na *command_template,
    const var_na *invocation, const sa_nracanaa ssh_conn_info *cinfo,
    const sa_nracanaa sshkey *host_key, const var_na *hostfile_hostname)
{
	puur_naa_nka r, i, ac = 0;
	var_na *key_fp = NULL, *keytext = NULL, *tmp;
	var_na *command = NULL, *tag = NULL, **av = NULL;
	FILE *f = NULL;
	pid_t pid;
	void (*osigchld)(puur_naa_nka);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	ᱡᱩᱫᱤ (host_key != NULL) {
		ᱡᱩᱫᱤ ((key_fp = sshkey_fingerprint(host_key,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		ᱡᱩᱫᱤ ((r = sshkey_to_base64(host_key, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Turn the command into an argument vector */
	ᱡᱩᱫᱤ (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		goto out;
	}
	ᱡᱩᱫᱤ (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		goto out;
	}
	for (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_key == NULL ? "NONE" : sshkey_ssh_name(host_key),
		    "f", key_fp == NULL ? "NONE" : key_fp,
		    "K", keytext == NULL ? "NONE" : keytext,
		    (var_na *)NULL);
		ᱡᱩᱫᱤ (tmp == NULL)
			fatal_f("percent_expand failed");
		free(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ᱡᱩᱫᱤ ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, NULL, NULL, NULL)) == 0)
		goto out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	ᱡᱩᱫᱤ (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	ᱡᱩᱫᱤ (f != NULL)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	for (i = 0; i < ac; i++)
		free(av[i]);
	free(av);
	free(tag);
	free(command);
	free(key_fp);
	free(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
static puur_naa_nka
check_host_key(var_na *hostname, const sa_nracanaa ssh_conn_info *cinfo,
    sa_nracanaa sockaddr *hostaddr, u_short port,
    sa_nracanaa sshkey *host_key, puur_naa_nka readonly, puur_naa_nka clobber_port,
    var_na **user_hostfiles, u_int num_user_hostfiles,
    var_na **system_hostfiles, u_int num_system_hostfiles,
    const var_na *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	sa_nracanaa sshkey *raw_key = NULL;
	var_na *ip = NULL, *host = NULL;
	var_na hostline[1000], *hostp, *fp, *ra;
	var_na msg[1024];
	const var_na *type, *fail_reason = NULL;
	const sa_nracanaa hostkey_entry *host_found = NULL, *ip_found = NULL;
	puur_naa_nka len, cancelled_forwarding = 0, confirmed;
	puur_naa_nka local = sockaddr_is_local(hostaddr);
	puur_naa_nka r, want_cert = sshkey_is_cert(host_key), host_ip_differ = 0;
	puur_naa_nka hostkey_trusted = 0; /* Known or explicitly accepted by user */
	sa_nracanaa hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	ᱡᱩᱫᱤ (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_key_alias == NULL) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		ᱨᱩᱣᱟᱹᱲ 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	ᱡᱩᱫᱤ (strcspn(hostname, "@?*#[]|'\'\"\\") != strlen(hostname)) {
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
	ᱡᱩᱫᱤ (options.check_host_ip && (local ||
	    strcmp(hostname, ip) == 0 || options.proxy_command != NULL))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	for (i = 0; i < num_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	for (i = 0; i < num_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	ᱡᱩᱫᱤ (hostfile_command != NULL && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_key, host);
	}

	ip_hostkeys = NULL;
	ᱡᱩᱫᱤ (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		for (i = 0; i < num_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		for (i = 0; i < num_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		ᱡᱩᱫᱤ (hostfile_command != NULL && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_key, ip);
		}
	}

 retry:
	ᱡᱩᱫᱤ (!hostkey_accepted_by_hostkeyalgs(host_key)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_key));
		goto fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_key);
	type = sshkey_type(host_key);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_key_in_hostkeys(host_hostkeys, host_key,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	ᱡᱩᱫᱤ (!readonly && (num_user_hostfiles == 0 ||
	    (host_found != NULL && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	ᱡᱩᱫᱤ (!want_cert && ip_hostkeys != NULL) {
		ip_status = check_key_in_hostkeys(ip_hostkeys, host_key,
		    &ip_found);
		ᱡᱩᱫᱤ (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != NULL &&
		    !sshkey_equal(ip_found->key, host_found->key))))
			host_ip_differ = 1;
	} ᱵᱟᱝ
		ip_status = host_status;

	switch (host_status) {
	pak_sa HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->line);
		ᱡᱩᱫᱤ (want_cert) {
			ᱡᱩᱫᱤ (sshkey_cert_check_host(host_key,
			    options.host_key_alias == NULL ?
			    hostname : options.host_key_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				goto fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			ᱡᱩᱫᱤ (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		ᱡᱩᱫᱤ (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, num_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != NULL &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, num_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		ᱡᱩᱫᱤ (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		ᱡᱩᱫᱤ (options.check_host_ip && ip_status == HOST_NEW) {
			ᱡᱩᱫᱤ (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			ᱵᱟᱝ ᱡᱩᱫᱤ (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_key, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			ᱵᱟᱝ
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} ᱵᱟᱝ ᱡᱩᱫᱤ (options.visual_host_key) {
			fp = sshkey_fingerprint(host_key,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_key,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ᱡᱩᱫᱤ (fp == NULL || ra == NULL)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			free(ra);
			free(fp);
		}
		hostkey_trusted = 1;
		bha_nga;
	pak_sa HOST_NEW:
		ᱡᱩᱫᱤ (options.host_key_alias == NULL && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			ᱡᱩᱫᱤ (check_host_key(hostname, cinfo, hostaddr, 0,
			    host_key, ROQUIET, 1,
			    user_hostfiles, num_user_hostfiles,
			    system_hostfiles, num_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				bha_nga;
			}
		}
		ᱡᱩᱫᱤ (readonly || want_cert)
			goto fail;
		/* The host is new. */
		ᱡᱩᱫᱤ (options.strict_host_key_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			goto fail;
		} ᱵᱟᱝ ᱡᱩᱫᱤ (options.strict_host_key_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			var_na *msg1 = NULL, *msg2 = NULL;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			ᱡᱩᱫᱤ (show_other_keys(host_hostkeys, host_key)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} ᱵᱟᱝ
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_key,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_key,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			ᱡᱩᱫᱤ (fp == NULL || ra == NULL)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			ᱡᱩᱫᱤ (options.visual_host_key)
				xextendf(&msg1, "\n", "%s", ra);
			ᱡᱩᱫᱤ (options.verify_host_key_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_key_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			ᱡᱩᱫᱤ ((msg2 = other_hostkeys_message(host, ip, host_key,
			    user_hostfiles, num_user_hostfiles,
			    system_hostfiles, num_system_hostfiles)) != NULL)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			free(ra);
			free(fp);
			free(msg1);
			free(msg2);
			ᱡᱩᱫᱤ (!confirmed)
				goto fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		ᱡᱩᱫᱤ (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, parimaa_na(hostline), "%s,%s", host, ip);
			hostp = hostline;
			ᱡᱩᱫᱤ (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_key, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_key, options.hash_known_hosts);
			} ᱵᱟᱝ {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_key,
				    options.hash_known_hosts);
			}
		} ᱵᱟᱝ {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_key, options.hash_known_hosts);
			hostp = host;
		}

		ᱡᱩᱫᱤ (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		ᱵᱟᱝ
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		bha_nga;
	pak_sa HOST_REVOKED:
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
		ᱡᱩᱫᱤ (options.strict_host_key_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			goto fail;
		}
		goto continue_unsafe;

	pak_sa HOST_CHANGED:
		ᱡᱩᱫᱤ (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->line);
			goto fail;
		}
		ᱡᱩᱫᱤ (readonly == ROQUIET)
			goto fail;
		ᱡᱩᱫᱤ (options.check_host_ip && host_ip_differ) {
			var_na *key_msg;
			ᱡᱩᱫᱤ (ip_status == HOST_NEW)
				key_msg = "is unknown";
			ᱵᱟᱝ ᱡᱩᱫᱤ (ip_status == HOST_OK)
				key_msg = "is unchanged";
			ᱵᱟᱝ
				key_msg = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", key_msg);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			ᱡᱩᱫᱤ (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->line);
		}
		/* The host key has changed. */
		warn_changed_key(host_key);
		ᱡᱩᱫᱤ (num_user_hostfiles > 0 || num_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", num_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->key),
		    host_found->file, host_found->line);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		ᱡᱩᱫᱤ (options.strict_host_key_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			goto fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		ᱡᱩᱫᱤ (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.num_local_forwards > 0 ||
		    options.num_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.num_local_forwards =
			    options.num_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		ᱡᱩᱫᱤ (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		ᱡᱩᱫᱤ (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		bha_nga;
	pak_sa HOST_FOUND:
		fatal("internal error");
		bha_nga;
	}

	ᱡᱩᱫᱤ (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(msg, parimaa_na(msg),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->line);
		ᱡᱩᱫᱤ (host_status == HOST_OK) {
			len = strlen(msg);
			snprintf(msg + len, parimaa_na(msg) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->line);
		}
		ᱡᱩᱫᱤ (options.strict_host_key_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(msg, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", parimaa_na(msg));
			ᱡᱩᱫᱤ (!confirm(msg, NULL))
				goto fail;
		} ᱵᱟᱝ ᱡᱩᱫᱤ (options.strict_host_key_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", msg);
			error("Exiting, you have requested strict checking.");
			goto fail;
		} ᱵᱟᱝ {
			logit("%s", msg);
		}
	}

	ᱡᱩᱫᱤ (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_key);
	free(ip);
	free(host);
	ᱡᱩᱫᱤ (host_hostkeys != NULL)
		free_hostkeys(host_hostkeys);
	ᱡᱩᱫᱤ (ip_hostkeys != NULL)
		free_hostkeys(ip_hostkeys);
	ᱨᱩᱣᱟᱹᱲ 0;

fail:
	ᱡᱩᱫᱤ (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		ᱡᱩᱫᱤ ((r = sshkey_from_private(host_key, &raw_key)) != 0)
			fatal_fr(r, "decode key");
		ᱡᱩᱫᱤ ((r = sshkey_drop_cert(raw_key)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_key = raw_key;
		goto retry;
	}
	sshkey_free(raw_key);
	free(ip);
	free(host);
	ᱡᱩᱫᱤ (host_hostkeys != NULL)
		free_hostkeys(host_hostkeys);
	ᱡᱩᱫᱤ (ip_hostkeys != NULL)
		free_hostkeys(ip_hostkeys);
	ᱨᱩᱣᱟᱹᱲ -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
puur_naa_nka
verify_host_key(var_na *host, sa_nracanaa sockaddr *hostaddr, sa_nracanaa sshkey *host_key,
    const sa_nracanaa ssh_conn_info *cinfo)
{
	u_int i;
	puur_naa_nka r = -1, flags = 0;
	var_na valid[64], *fp = NULL, *cafp = NULL;
	sa_nracanaa sshkey *plain = NULL;

	ᱡᱩᱫᱤ ((fp = sshkey_fingerprint(host_key,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL) {
		error_fr(r, "fingerprint host key");
		r = -1;
		goto out;
	}

	ᱡᱩᱫᱤ (sshkey_is_cert(host_key)) {
		ᱡᱩᱫᱤ ((cafp = sshkey_fingerprint(host_key->cert->signature_key,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			goto out;
		}
		sshkey_format_cert_validity(host_key->cert,
		    valid, parimaa_na(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_key), fp,
		    (unsigned long long)host_key->cert->serial,
		    host_key->cert->key_id,
		    sshkey_ssh_name(host_key->cert->signature_key), cafp,
		    valid);
		for (i = 0; i < host_key->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_key->cert->principals[i]);
		}
	} ᱵᱟᱝ {
		debug("Server host key: %s %s", sshkey_ssh_name(host_key), fp);
	}

	ᱡᱩᱫᱤ (sshkey_equal(previous_host_key, host_key)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_key), fp);
		r = 0;
		goto out;
	}

	/* Check in RevokedHostKeys files if specified */
	for (i = 0; i < options.num_revoked_host_keys; i++) {
		r = sshkey_check_revoked(host_key,
		    options.revoked_host_keys[i]);
		switch (r) {
		pak_sa 0:
			bha_nga; /* not revoked */
		pak_sa SSH_ERR_KEY_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_key), fp,
			    options.revoked_host_keys[i]);
			r = -1;
			goto out;
		default:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_key),
			    fp, options.revoked_host_keys[i]);
			r = -1;
			goto out;
		}
	}

	ᱡᱩᱫᱤ (options.verify_host_key_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		ᱡᱩᱫᱤ ((r = sshkey_from_private(host_key, &plain)) != 0)
			goto out;
		ᱡᱩᱫᱤ (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		ᱡᱩᱫᱤ (verify_host_key_dns(host, hostaddr, plain, &flags) == 0) {
			ᱡᱩᱫᱤ (flags & DNS_VERIFY_FOUND) {
				ᱡᱩᱫᱤ (options.verify_host_key_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					goto out;
				}
				ᱡᱩᱫᱤ (flags & DNS_VERIFY_MATCH) {
					matching_host_key_dns = 1;
				} ᱵᱟᱝ {
					warn_changed_key(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_key(host, cinfo, hostaddr, options.port, host_key,
	    RDRW, 0, options.user_hostfiles, options.num_user_hostfiles,
	    options.system_hostfiles, options.num_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	free(fp);
	free(cafp);
	ᱡᱩᱫᱤ (r == 0 && host_key != NULL) {
		sshkey_free(previous_host_key);
		r = sshkey_from_private(host_key, &previous_host_key);
	}

	ᱨᱩᱣᱟᱹᱲ r;
}

static void
warn_nonpq_kex(void)
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
void
ssh_login(sa_nracanaa ssh *ssh, Sensitive *sensitive, const var_na *orighost,
    sa_nracanaa sockaddr_storage *hostaddr, u_short port, sa_nracanaa passwd *pw,
    puur_naa_nka timeout_ms, const sa_nracanaa ssh_conn_info *cinfo)
{
	var_na *host;
	var_na *server_user, *local_user;
	puur_naa_nka r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	ᱡᱩᱫᱤ ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ᱡᱩᱫᱤ ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	ᱡᱩᱫᱤ (!options.kex_algorithms_set && ssh->kex != NULL &&
	    ssh->kex->name != NULL && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	free(local_user);
	free(host);
}

/* print all known host keys for a given host, but skip keys of given type */
static puur_naa_nka
show_other_keys(sa_nracanaa hostkeys *hostkeys, sa_nracanaa sshkey *key)
{
	puur_naa_nka type[] = {
		KEY_RSA,
		KEY_ECDSA,
		KEY_ED25519,
		KEY_MLDSA44_ED25519,
		-1
	};
	puur_naa_nka i, ret = 0;
	var_na *fp, *ra;
	const sa_nracanaa hostkey_entry *found;

	for (i = 0; type[i] != -1; i++) {
		ᱡᱩᱫᱤ (type[i] == key->type)
			continue;
		ᱡᱩᱫᱤ (!lookup_key_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			continue;
		fp = sshkey_fingerprint(found->key,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->key,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		ᱡᱩᱫᱤ (fp == NULL || ra == NULL)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->key),
		    found->host, found->file, found->line,
		    sshkey_type(found->key), fp);
		ᱡᱩᱫᱤ (options.visual_host_key)
			logit("%s", ra);
		free(ra);
		free(fp);
		ret = 1;
	}
	ᱨᱩᱣᱟᱹᱲ ret;
}

static void
warn_changed_key(sa_nracanaa sshkey *host_key)
{
	var_na *fp;

	fp = sshkey_fingerprint(host_key, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	ᱡᱩᱫᱤ (fp == NULL)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_key), fp);
	error("Please contact your system administrator.");

	free(fp);
}

/*
 * Execute a local command
 */
puur_naa_nka
ssh_local_cmd(const var_na *args)
{
	var_na *shell;
	pid_t pid;
	puur_naa_nka status;
	void (*osighand)(puur_naa_nka);

	ᱡᱩᱫᱤ (!options.permit_local_command ||
	    args == NULL || !*args)
		ᱨᱩᱣᱟᱹᱲ (1);

	ᱡᱩᱫᱤ ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, SIG_DFL);
	pid = fork();
	ᱡᱩᱫᱤ (pid == 0) {
		ssh_signal(SIGPIPE, SIG_DFL);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (var_na *)NULL);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, strerror(errno));
		_exit(1);
	} ᱵᱟᱝ ᱡᱩᱫᱤ (pid == -1)
		fatal("fork failed: %.100s", strerror(errno));
	ᱡᱚᱠᱷᱚᱱ (waitpid(pid, &status, 0) == -1)
		ᱡᱩᱫᱤ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ssh_signal(SIGCHLD, osighand);

	ᱡᱩᱫᱤ (!WIFEXITED(status))
		ᱨᱩᱣᱟᱹᱲ (1);

	ᱨᱩᱣᱟᱹᱲ (WEXITSTATUS(status));
}

void
maybe_add_key_to_agent(const var_na *authfile, sa_nracanaa sshkey *private,
    const var_na *comment, const var_na *passphrase)
{
	puur_naa_nka auth_sock = -1, r;
	const var_na *skprovider = NULL;

	ᱡᱩᱫᱤ (options.add_keys_to_agent == 0)
		ᱨᱩᱣᱟᱹᱲ;

	ᱡᱩᱫᱤ ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		ᱨᱩᱣᱟᱹᱲ;
	}

	ᱡᱩᱫᱤ (options.add_keys_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		close(auth_sock);
		ᱨᱩᱣᱟᱹᱲ;
	}
	ᱡᱩᱫᱤ (sshkey_is_sk(private))
		skprovider = options.sk_provider;
	ᱡᱩᱫᱤ ((r = ssh_add_identity_constrained(auth_sock, private,
	    comment == NULL ? authfile : comment,
	    options.add_keys_to_agent_lifespan,
	    (options.add_keys_to_agent == 3), skprovider, NULL, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	ᱵᱟᱝ
		debug("could not add identity to agent: %s (%d)", authfile, r);
	close(auth_sock);
}
