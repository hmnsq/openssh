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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <net/if.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <ifaddrs.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshconnect.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "monitor_fdpass.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "kex.h"

संरचना sshkey *previous_host_कुंजी = रिक्त;

स्थिर पूर्णाङ्क matching_host_कुंजी_dns = 0;

स्थिर pid_t proxy_command_pid = 0;

/* import */
बाह्य पूर्णाङ्क debug_flag;
बाह्य Options options;
बाह्य वर्ण *__progname;

स्थिर पूर्णाङ्क show_other_कुंजियाँ(संरचना hostkeys *, संरचना sshkey *);
स्थिर शून्य warn_changed_कुंजी(संरचना sshkey *);

शून्य
ssh_conn_info_free(संरचना ssh_conn_info *cinfo)
{
	यदि (cinfo == रिक्त)
		प्रत्यागम;
	मुक्त(cinfo->conn_hash_hex);
	मुक्त(cinfo->shorthost);
	मुक्त(cinfo->uidstr);
	मुक्त(cinfo->keyalias);
	मुक्त(cinfo->thishost);
	मुक्त(cinfo->host_arg);
	मुक्त(cinfo->portstr);
	मुक्त(cinfo->remhost);
	मुक्त(cinfo->remuser);
	मुक्त(cinfo->homedir);
	मुक्त(cinfo->locuser);
	मुक्त(cinfo->jmphost);
	freezero(cinfo, परिमाण(*cinfo));
}

संरचना ssh_conn_info *
ssh_conn_info_dup(ध्रुव संरचना ssh_conn_info *cinfo)
{
	संरचना ssh_conn_info *ret;

	यदि (cinfo == रिक्त)
		प्रत्यागम रिक्त;
	ret = xcalloc(1, परिमाण(*ret));
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
	प्रत्यागम ret;
}

/* Expand a proxy command */
स्थिर वर्ण *
expand_proxy_command(ध्रुव वर्ण *proxy_command, ध्रुव वर्ण *user,
    ध्रुव वर्ण *host, ध्रुव वर्ण *host_arg, पूर्णाङ्क port)
{
	वर्ण *tmp, *ret, strport[NI_MAXSERV];
	ध्रुव वर्ण *keyalias = options.host_कुंजी_alias ?
	    options.host_कुंजी_alias : host_arg;

	snprintf(strport, परिमाण strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (वर्ण *)रिक्त);
	मुक्त(tmp);
	प्रत्यागम ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
स्थिर पूर्णाङ्क
ssh_proxy_fdpass_connect(संरचना ssh *ssh, ध्रुव वर्ण *host,
    ध्रुव वर्ण *host_arg, u_short port, ध्रुव वर्ण *proxy_command)
{
	वर्ण *command_string;
	पूर्णाङ्क sp[2], sock;
	pid_t pid;
	वर्ण *shell;

	यदि ((shell = दो_पर्या("SHELL")) == रिक्त)
		shell = _PATH_BSHELL;

	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	यदि ((pid = विभाजन()) == 0) {
		वर्ण *argv[10];

		बंद(sp[1]);
		/* Redirect stdin and stdout. */
		यदि (sp[0] != 0) {
			यदि (dup2(sp[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
		}
		यदि (sp[0] != 1) {
			यदि (dup2(sp[0], 1) == -1)
				लिखो_त्रुटि("dup2 stdout");
		}
		यदि (sp[0] >= 2)
			बंद(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		यदि (!debug_flag && options.control_path != रिक्त &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = रिक्त;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		लिखो_त्रुटि(argv[0]);
		निकास(1);
	}
	/* Parent. */
	यदि (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	बंद(sp[0]);
	मुक्त(command_string);

	यदि ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	बंद(sp[1]);

	यावत् (waitpid(pid, रिक्त, 0) == -1)
		यदि (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));

	/* Set the connection file descriptors. */
	यदि (ssh_packet_set_connection(ssh, sock, sock) == रिक्त)
		प्रत्यागम -1; /* ssh_packet_set_connection logs error */

	प्रत्यागम 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
स्थिर पूर्णाङ्क
ssh_proxy_connect(संरचना ssh *ssh, ध्रुव वर्ण *host, ध्रुव वर्ण *host_arg,
    u_short port, ध्रुव वर्ण *proxy_command)
{
	वर्ण *command_string;
	पूर्णाङ्क pin[2], pout[2];
	pid_t pid;
	वर्ण *shell;

	यदि ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	यदि (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	यदि ((pid = विभाजन()) == 0) {
		वर्ण *argv[10];

		/* Redirect stdin and stdout. */
		बंद(pin[1]);
		यदि (pin[0] != 0) {
			यदि (dup2(pin[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
			बंद(pin[0]);
		}
		बंद(pout[0]);
		यदि (dup2(pout[1], 1) == -1)
			लिखो_त्रुटि("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		बंद(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		यदि (!debug_flag && options.control_path != रिक्त &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = रिक्त;

		/*
		 * Execute the proxy command.  Note that we gave up any
		 * extra privileges above.
		 */
		ssh_signal(SIGPIPE, संक_पूर्व);
		execv(argv[0], argv);
		लिखो_त्रुटि(argv[0]);
		निकास(1);
	}
	/* Parent. */
	यदि (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	अन्यथा
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	बंद(pin[0]);
	बंद(pout[1]);

	/* Free the command name. */
	मुक्त(command_string);

	/* Set the connection file descriptors. */
	यदि (ssh_packet_set_connection(ssh, pout[0], pin[1]) == रिक्त)
		प्रत्यागम -1; /* ssh_packet_set_connection logs error */

	प्रत्यागम 0;
}

शून्य
ssh_kill_proxy_command(शून्य)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	यदि (proxy_command_pid > 1)
		समाप्त(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
स्थिर पूर्णाङ्क
check_ifaddrs(ध्रुव वर्ण *ifname, पूर्णाङ्क af, ध्रुव संरचना ifaddrs *ifaddrs,
    संरचना sockaddr_storage *resultp, socklen_t *rlenp)
{
	संरचना sockaddr_in6 *sa6;
	संरचना sockaddr_in *sa;
	संरचना in6_addr *v6addr;
	ध्रुव संरचना ifaddrs *ifa;
	पूर्णाङ्क allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	प्रति (allow_local = 0; allow_local < 2; allow_local++) {
		प्रति (ifa = ifaddrs; ifa != रिक्त; ifa = ifa->ifa_next) {
			यदि (ifa->ifa_addr == रिक्त || ifa->ifa_name == रिक्त ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    म_भेद(ifa->ifa_name, options.bind_interface) != 0)
				अनुवर्त;
			विकल्प (ifa->ifa_addr->sa_family) {
			पक्ष AF_INET:
				sa = (संरचना sockaddr_in *)ifa->ifa_addr;
				यदि (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					अनुवर्त;
				यदि (*rlenp < परिमाण(संरचना sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					प्रत्यागम -1;
				}
				*rlenp = परिमाण(संरचना sockaddr_in);
				स_नकल(resultp, sa, *rlenp);
				प्रत्यागम 0;
			पक्ष AF_INET6:
				sa6 = (संरचना sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				यदि (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					अनुवर्त;
				यदि (*rlenp < परिमाण(संरचना sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					प्रत्यागम -1;
				}
				*rlenp = परिमाण(संरचना sockaddr_in6);
				स_नकल(resultp, sa6, *rlenp);
				प्रत्यागम 0;
			}
		}
	}
	प्रत्यागम -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
स्थिर पूर्णाङ्क
ssh_create_socket(संरचना addrinfo *ai)
{
	पूर्णाङ्क sock, r;
	संरचना sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	संरचना addrinfo hints, *res = रिक्त;
#ifdef HAVE_IFADDRS_H
	संरचना ifaddrs *ifaddrs = रिक्त;
#endif
	वर्ण ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	यदि (sock == -1) {
		error("socket: %s", म_त्रुटि(त्रुटि_सं));
		प्रत्यागम -1;
	}
	(शून्य)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	यदि (options.ip_qos_interactive != पूर्णांक_उच्च)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	यदि (options.bind_address == रिक्त && options.bind_interface == रिक्त)
		प्रत्यागम sock;

	यदि (options.bind_address != रिक्त) {
		स_रखो(&hints, 0, परिमाण(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		यदि ((r = getaddrinfo(options.bind_address, रिक्त,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			गच्छ fail;
		}
		यदि (res == रिक्त) {
			error("getaddrinfo: no addrs");
			गच्छ fail;
		}
		स_नकल(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} अन्यथा यदि (options.bind_interface != रिक्त) {
#ifdef HAVE_IFADDRS_H
		यदि ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    म_त्रुटि(त्रुटि_सं));
			गच्छ fail;
		}
		bindaddrlen = परिमाण(bindaddr);
		यदि (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			गच्छ fail;
		}
#अन्यथा
		error("BindInterface not supported on this platform.");
#endif
	}
	यदि ((r = getnameinfo((संरचना sockaddr *)&bindaddr, bindaddrlen,
	    ntop, परिमाण(ntop), रिक्त, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		गच्छ fail;
	}
	यदि (bind(sock, (संरचना sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	गच्छ out;
fail:
	बंद(sock);
	sock = -1;
 out:
	यदि (res != रिक्त)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	यदि (ifaddrs != रिक्त)
		freeifaddrs(ifaddrs);
#endif
	प्रत्यागम sock;
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
स्थिर पूर्णाङ्क
ssh_connect_direct(संरचना ssh *ssh, ध्रुव वर्ण *host, संरचना addrinfo *aitop,
    संरचना sockaddr_storage *hostaddr, u_short port, पूर्णाङ्क connection_attempts,
    पूर्णाङ्क *timeout_ms, पूर्णाङ्क want_keepalive)
{
	पूर्णाङ्क saved_timeout_ms = *timeout_ms;
	पूर्णाङ्क oerrno, sock = -1, attempt;
	वर्ण ntop[NI_MAXHOST], strport[NI_MAXSERV];
	संरचना addrinfo *ai;

	debug3_f("entering");
	स_रखो(ntop, 0, परिमाण(ntop));
	स_रखो(strport, 0, परिमाण(strport));

	प्रति (attempt = 0; attempt < connection_attempts; attempt++) {
		यदि (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		प्रति (ai = aitop; ai; ai = ai->ai_next) {
			यदि (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				त्रुटि_सं = EAFNOSUPPORT;
				अनुवर्त;
			}
			यदि (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, परिमाण(ntop), strport, परिमाण(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = त्रुटि_सं;
				error_f("getnameinfo failed");
				त्रुटि_सं = oerrno;
				अनुवर्त;
			}
			यदि (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				त्रुटि_सं = EAFNOSUPPORT;
				अनुवर्त;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			यदि (sock < 0) {
				/* Any error is already output */
				त्रुटि_सं = 0;
				अनुवर्त;
			}

			*timeout_ms = saved_timeout_ms;
			यदि (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				स_नकल(hostaddr, ai->ai_addr, ai->ai_addrlen);
				भङ्ग;
			} अन्यथा {
				oerrno = त्रुटि_सं;
				debug("connect to address %s port %s: %s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				त्रुटि_सं = oerrno;
			}
		}
		यदि (sock != -1)
			भङ्ग;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	यदि (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, त्रुटि_सं == 0 ? "failure" : म_त्रुटि(त्रुटि_सं));
		प्रत्यागम -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	यदि (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	यदि (ssh_packet_set_connection(ssh, sock, sock) == रिक्त)
		प्रत्यागम -1; /* ssh_packet_set_connection logs error */

	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_connect(संरचना ssh *ssh, ध्रुव वर्ण *host, ध्रुव वर्ण *host_arg,
    संरचना addrinfo *addrs, संरचना sockaddr_storage *hostaddr, u_short port,
    पूर्णाङ्क connection_attempts, पूर्णाङ्क *timeout_ms, पूर्णाङ्क want_keepalive)
{
	पूर्णाङ्क in, out;

	यदि (options.proxy_command == रिक्त) {
		प्रत्यागम ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} अन्यथा यदि (म_भेद(options.proxy_command, "-") == 0) {
		यदि ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			यदि (in >= 0)
				बंद(in);
			error_f("dup() in/out failed");
			प्रत्यागम -1; /* ssh_packet_set_connection logs error */
		}
		यदि ((ssh_packet_set_connection(ssh, in, out)) == रिक्त)
			प्रत्यागम -1; /* ssh_packet_set_connection logs error */
		प्रत्यागम 0;
	} अन्यथा यदि (options.proxy_use_fdpass) {
		प्रत्यागम ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	प्रत्यागम ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
स्थिर पूर्णाङ्क
confirm(ध्रुव वर्ण *prompt, ध्रुव वर्ण *fingerprint)
{
	ध्रुव वर्ण *संदेश, *again = "Please type 'yes' or 'no': ";
	ध्रुव वर्ण *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	वर्ण *p, *cp;
	पूर्णाङ्क ret = -1;

	यदि (options.batch_mode)
		प्रत्यागम 0;
	प्रति (संदेश = prompt;;संदेश = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(संदेश, RP_ECHO);
		यदि (p == रिक्त)
			प्रत्यागम 0;
		p += म_अखोज(p, " \t"); /* skip leading whitespace */
		p[म_खोज(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		यदि (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		अन्यथा यदि (strcasecmp(p, "yes") == 0 || (fingerprint != रिक्त &&
		    म_भेद(p, fingerprint) == 0))
			ret = 1;
		मुक्त(cp);
		यदि (ret != -1)
			प्रत्यागम ret;
	}
}

स्थिर पूर्णाङ्क
sockaddr_is_local(संरचना sockaddr *hostaddr)
{
	विकल्प (hostaddr->sa_family) {
	पक्ष AF_INET:
		प्रत्यागम (ntohl(((संरचना sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	पक्ष AF_INET6:
		प्रत्यागम IN6_IS_ADDR_LOOPBACK(
		    &(((संरचना sockaddr_in6 *)hostaddr)->sin6_addr));
	स्वभाव:
		प्रत्यागम 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
शून्य
get_hostfile_hostname_ipaddr(वर्ण *hostname, संरचना sockaddr *hostaddr,
    u_short port, वर्ण **hostfile_hostname, वर्ण **hostfile_ipaddr)
{
	वर्ण ntop[NI_MAXHOST];
	socklen_t addrlen;

	विकल्प (hostaddr == रिक्त ? -1 : hostaddr->sa_family) {
	पक्ष -1:
		addrlen = 0;
		भङ्ग;
	पक्ष AF_INET:
		addrlen = परिमाण(संरचना sockaddr_in);
		भङ्ग;
	पक्ष AF_INET6:
		addrlen = परिमाण(संरचना sockaddr_in6);
		भङ्ग;
	स्वभाव:
		addrlen = परिमाण(संरचना sockaddr);
		भङ्ग;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	यदि (hostfile_ipaddr != रिक्त) {
		यदि (options.proxy_command == रिक्त) {
			यदि (getnameinfo(hostaddr, addrlen,
			    ntop, परिमाण(ntop), रिक्त, 0, NI_NUMERICHOST) != 0)
				fatal_f("getnameinfo failed");
			*hostfile_ipaddr = put_host_port(ntop, port);
		} अन्यथा {
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
	यदि (hostfile_hostname != रिक्त) {
		यदि (options.host_कुंजी_alias != रिक्त) {
			*hostfile_hostname = xstrdup(options.host_कुंजी_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} अन्यथा {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
स्थिर पूर्णाङ्क
path_in_hostfiles(ध्रुव वर्ण *path, वर्ण **hostfiles, u_int अंक_hostfiles)
{
	u_int i;

	प्रति (i = 0; i < अंक_hostfiles; i++) {
		यदि (म_भेद(path, hostfiles[i]) == 0)
			प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

संरचना find_by_कुंजी_ctx {
	ध्रुव वर्ण *host, *ip;
	ध्रुव संरचना sshkey *कुंजी;
	वर्ण **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
स्थिर वर्ण *
try_tilde_unexpand(ध्रुव वर्ण *path)
{
	वर्ण *home, *ret = रिक्त;
	माप_प्रकार l;

	यदि (*path != '/')
		प्रत्यागम xstrdup(path);
	यदि ((home = दो_पर्या("HOME")) == रिक्त || (l = म_माप(home)) == 0)
		प्रत्यागम xstrdup(path);
	यदि (म_भेदन(path, home, l) != 0)
		प्रत्यागम xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	यदि (home[l - 1] != '/' && path[l] != '/')
		प्रत्यागम xstrdup(path);
	यदि (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	प्रत्यागम ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
पूर्णाङ्क
hostkey_accepted_by_hostkeyalgs(ध्रुव संरचना sshkey *कुंजी)
{
	ध्रुव वर्ण *ktype = sshkey_ssh_name(कुंजी);
	ध्रुव वर्ण *hostkeyalgs = options.hostkeyalgorithms;

	यदि (कुंजी->type == कुंजी_UNSPEC)
		प्रत्यागम 0;
	यदि (कुंजी->type == कुंजी_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		प्रत्यागम 1;
	यदि (कुंजी->type == कुंजी_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		प्रत्यागम 1;
	प्रत्यागम match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

स्थिर पूर्णाङ्क
hostkeys_find_by_कुंजी_cb(संरचना hostkey_foreach_पंक्ति *l, शून्य *_ctx)
{
	संरचना find_by_कुंजी_ctx *ctx = (संरचना find_by_कुंजी_ctx *)_ctx;
	वर्ण *path;

	/* we are looking for keys with names that *do not* match */
	यदि ((l->match & HKF_MATCH_HOST) != 0)
		प्रत्यागम 0;
	/* not interested in marker lines */
	यदि (l->marker != MRK_NONE)
		प्रत्यागम 0;
	/* we are only interested in exact key matches */
	यदि (l->कुंजी == रिक्त || !sshkey_equal(ctx->कुंजी, l->कुंजी))
		प्रत्यागम 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, परिमाण(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    म_भेदन(l->hosts, HASH_MAGIC, म_माप(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	मुक्त(path);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
hostkeys_find_by_कुंजी_hostfile(ध्रुव वर्ण *file, ध्रुव वर्ण *which,
    संरचना find_by_कुंजी_ctx *ctx)
{
	पूर्णाङ्क r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	यदि ((r = hostkeys_foreach(file, hostkeys_find_by_कुंजी_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_कुंजी, 0)) != 0) {
		यदि (r == SSH_ERR_SYSTEM_ERROR && त्रुटि_सं == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			प्रत्यागम 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
स्थिर शून्य
hostkeys_find_by_कुंजी(ध्रुव वर्ण *host, ध्रुव वर्ण *ip, ध्रुव संरचना sshkey *कुंजी,
    वर्ण **user_hostfiles, u_int अंक_user_hostfiles,
    वर्ण **system_hostfiles, u_int अंक_system_hostfiles,
    वर्ण ***names, u_int *nnames)
{
	संरचना find_by_कुंजी_ctx ctx = {रिक्त, रिक्त, रिक्त, रिक्त, 0};
	u_int i;

	*names = रिक्त;
	*nnames = 0;

	यदि (कुंजी == रिक्त || sshkey_is_cert(कुंजी))
		प्रत्यागम;

	ctx.host = host;
	ctx.ip = ip;
	ctx.कुंजी = कुंजी;

	प्रति (i = 0; i < अंक_user_hostfiles; i++) {
		यदि (hostkeys_find_by_कुंजी_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			गच्छ fail;
	}
	प्रति (i = 0; i < अंक_system_hostfiles; i++) {
		यदि (hostkeys_find_by_कुंजी_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			गच्छ fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = रिक्त;
	ctx.nnames = 0;
	प्रत्यागम;
 fail:
	प्रति (i = 0; i < ctx.nnames; i++)
		मुक्त(ctx.names[i]);
	मुक्त(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
स्थिर वर्ण *
other_hostkeys_message(ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    ध्रुव संरचना sshkey *कुंजी,
    वर्ण **user_hostfiles, u_int अंक_user_hostfiles,
    वर्ण **system_hostfiles, u_int अंक_system_hostfiles)
{
	वर्ण *ret = रिक्त, **othernames = रिक्त;
	u_int i, n, अंक_othernames = 0;

	hostkeys_find_by_कुंजी(host, ip, कुंजी,
	    user_hostfiles, अंक_user_hostfiles,
	    system_hostfiles, अंक_system_hostfiles,
	    &othernames, &अंक_othernames);
	यदि (अंक_othernames == 0)
		प्रत्यागम xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = अंक_othernames;
	यदि (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	प्रति (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	यदि (n < अंक_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    अंक_othernames - n);
	}
	प्रति (i = 0; i < अंक_othernames; i++)
		मुक्त(othernames[i]);
	मुक्त(othernames);
	प्रत्यागम ret;
}

शून्य
load_hostkeys_command(संरचना hostkeys *hostkeys, ध्रुव वर्ण *command_template,
    ध्रुव वर्ण *invocation, ध्रुव संरचना ssh_conn_info *cinfo,
    ध्रुव संरचना sshkey *host_कुंजी, ध्रुव वर्ण *hostfile_hostname)
{
	पूर्णाङ्क r, i, ac = 0;
	वर्ण *कुंजी_fp = रिक्त, *keytext = रिक्त, *tmp;
	वर्ण *command = रिक्त, *tag = रिक्त, **av = रिक्त;
	खाता *f = रिक्त;
	pid_t pid;
	शून्य (*osigchld)(पूर्णाङ्क);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	यदि (host_कुंजी != रिक्त) {
		यदि ((कुंजी_fp = sshkey_fingerprint(host_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		यदि ((r = sshkey_to_base64(host_कुंजी, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Turn the command into an argument vector */
	यदि (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		गच्छ out;
	}
	यदि (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		गच्छ out;
	}
	प्रति (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_कुंजी == रिक्त ? "NONE" : sshkey_ssh_name(host_कुंजी),
		    "f", कुंजी_fp == रिक्त ? "NONE" : कुंजी_fp,
		    "K", keytext == रिक्त ? "NONE" : keytext,
		    (वर्ण *)रिक्त);
		यदि (tmp == रिक्त)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	यदि ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, रिक्त, रिक्त, रिक्त)) == 0)
		गच्छ out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	यदि (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	यदि (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	प्रति (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	मुक्त(tag);
	मुक्त(command);
	मुक्त(कुंजी_fp);
	मुक्त(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
स्थिर पूर्णाङ्क
check_host_कुंजी(वर्ण *hostname, ध्रुव संरचना ssh_conn_info *cinfo,
    संरचना sockaddr *hostaddr, u_short port,
    संरचना sshkey *host_कुंजी, पूर्णाङ्क readonly, पूर्णाङ्क clobber_port,
    वर्ण **user_hostfiles, u_int अंक_user_hostfiles,
    वर्ण **system_hostfiles, u_int अंक_system_hostfiles,
    ध्रुव वर्ण *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	संरचना sshkey *raw_कुंजी = रिक्त;
	वर्ण *ip = रिक्त, *host = रिक्त;
	वर्ण hostline[1000], *hostp, *fp, *ra;
	वर्ण संदेश[1024];
	ध्रुव वर्ण *type, *fail_reason = रिक्त;
	ध्रुव संरचना hostkey_entry *host_found = रिक्त, *ip_found = रिक्त;
	पूर्णाङ्क len, cancelled_forwarding = 0, confirmed;
	पूर्णाङ्क local = sockaddr_is_local(hostaddr);
	पूर्णाङ्क r, want_cert = sshkey_is_cert(host_कुंजी), host_ip_differ = 0;
	पूर्णाङ्क hostkey_trusted = 0; /* Known or explicitly accepted by user */
	संरचना hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	यदि (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_कुंजी_alias == रिक्त) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		प्रत्यागम 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	यदि (म_खोज(hostname, "@?*#[]|'\'\"\\") != म_माप(hostname)) {
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
	यदि (options.check_host_ip && (local ||
	    म_भेद(hostname, ip) == 0 || options.proxy_command != रिक्त))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	प्रति (i = 0; i < अंक_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	प्रति (i = 0; i < अंक_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	यदि (hostfile_command != रिक्त && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_कुंजी, host);
	}

	ip_hostkeys = रिक्त;
	यदि (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		प्रति (i = 0; i < अंक_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		प्रति (i = 0; i < अंक_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		यदि (hostfile_command != रिक्त && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_कुंजी, ip);
		}
	}

 retry:
	यदि (!hostkey_accepted_by_hostkeyalgs(host_कुंजी)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_कुंजी));
		गच्छ fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_कुंजी);
	type = sshkey_type(host_कुंजी);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_कुंजी_in_hostkeys(host_hostkeys, host_कुंजी,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	यदि (!readonly && (अंक_user_hostfiles == 0 ||
	    (host_found != रिक्त && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	यदि (!want_cert && ip_hostkeys != रिक्त) {
		ip_status = check_कुंजी_in_hostkeys(ip_hostkeys, host_कुंजी,
		    &ip_found);
		यदि (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != रिक्त &&
		    !sshkey_equal(ip_found->कुंजी, host_found->कुंजी))))
			host_ip_differ = 1;
	} अन्यथा
		ip_status = host_status;

	विकल्प (host_status) {
	पक्ष HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->पंक्ति);
		यदि (want_cert) {
			यदि (sshkey_cert_check_host(host_कुंजी,
			    options.host_कुंजी_alias == रिक्त ?
			    hostname : options.host_कुंजी_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				गच्छ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			यदि (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		यदि (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, अंक_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != रिक्त &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, अंक_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		यदि (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		यदि (options.check_host_ip && ip_status == HOST_NEW) {
			यदि (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			अन्यथा यदि (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_कुंजी, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			अन्यथा
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} अन्यथा यदि (options.visual_host_कुंजी) {
			fp = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			यदि (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			मुक्त(ra);
			मुक्त(fp);
		}
		hostkey_trusted = 1;
		भङ्ग;
	पक्ष HOST_NEW:
		यदि (options.host_कुंजी_alias == रिक्त && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			यदि (check_host_कुंजी(hostname, cinfo, hostaddr, 0,
			    host_कुंजी, ROQUIET, 1,
			    user_hostfiles, अंक_user_hostfiles,
			    system_hostfiles, अंक_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				भङ्ग;
			}
		}
		यदि (readonly || want_cert)
			गच्छ fail;
		/* The host is new. */
		यदि (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			गच्छ fail;
		} अन्यथा यदि (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			वर्ण *msg1 = रिक्त, *msg2 = रिक्त;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			यदि (show_other_कुंजियाँ(host_hostkeys, host_कुंजी)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} अन्यथा
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			यदि (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			यदि (options.visual_host_कुंजी)
				xextendf(&msg1, "\n", "%s", ra);
			यदि (options.verify_host_कुंजी_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_कुंजी_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			यदि ((msg2 = other_hostkeys_message(host, ip, host_कुंजी,
			    user_hostfiles, अंक_user_hostfiles,
			    system_hostfiles, अंक_system_hostfiles)) != रिक्त)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			मुक्त(ra);
			मुक्त(fp);
			मुक्त(msg1);
			मुक्त(msg2);
			यदि (!confirmed)
				गच्छ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		यदि (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, परिमाण(hostline), "%s,%s", host, ip);
			hostp = hostline;
			यदि (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_कुंजी, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_कुंजी, options.hash_known_hosts);
			} अन्यथा {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_कुंजी,
				    options.hash_known_hosts);
			}
		} अन्यथा {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_कुंजी, options.hash_known_hosts);
			hostp = host;
		}

		यदि (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		अन्यथा
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		भङ्ग;
	पक्ष HOST_REVOKED:
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
		यदि (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			गच्छ fail;
		}
		गच्छ continue_unsafe;

	पक्ष HOST_CHANGED:
		यदि (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->पंक्ति);
			गच्छ fail;
		}
		यदि (readonly == ROQUIET)
			गच्छ fail;
		यदि (options.check_host_ip && host_ip_differ) {
			वर्ण *कुंजी_संदेश;
			यदि (ip_status == HOST_NEW)
				कुंजी_संदेश = "is unknown";
			अन्यथा यदि (ip_status == HOST_OK)
				कुंजी_संदेश = "is unchanged";
			अन्यथा
				कुंजी_संदेश = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", कुंजी_संदेश);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			यदि (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->पंक्ति);
		}
		/* The host key has changed. */
		warn_changed_कुंजी(host_कुंजी);
		यदि (अंक_user_hostfiles > 0 || अंक_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", अंक_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->कुंजी),
		    host_found->file, host_found->पंक्ति);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		यदि (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			गच्छ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		यदि (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		यदि (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		यदि (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		यदि (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		यदि (options.अंक_local_forwards > 0 ||
		    options.अंक_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.अंक_local_forwards =
			    options.अंक_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		यदि (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		यदि (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		यदि (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		भङ्ग;
	पक्ष HOST_FOUND:
		fatal("internal error");
		भङ्ग;
	}

	यदि (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(संदेश, परिमाण(संदेश),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->पंक्ति);
		यदि (host_status == HOST_OK) {
			len = म_माप(संदेश);
			snprintf(संदेश + len, परिमाण(संदेश) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->पंक्ति);
		}
		यदि (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(संदेश, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", परिमाण(संदेश));
			यदि (!confirm(संदेश, रिक्त))
				गच्छ fail;
		} अन्यथा यदि (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", संदेश);
			error("Exiting, you have requested strict checking.");
			गच्छ fail;
		} अन्यथा {
			logit("%s", संदेश);
		}
	}

	यदि (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_कुंजी);
	मुक्त(ip);
	मुक्त(host);
	यदि (host_hostkeys != रिक्त)
		free_hostkeys(host_hostkeys);
	यदि (ip_hostkeys != रिक्त)
		free_hostkeys(ip_hostkeys);
	प्रत्यागम 0;

fail:
	यदि (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		यदि ((r = sshkey_from_private(host_कुंजी, &raw_कुंजी)) != 0)
			fatal_fr(r, "decode key");
		यदि ((r = sshkey_drop_cert(raw_कुंजी)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_कुंजी = raw_कुंजी;
		गच्छ retry;
	}
	sshkey_free(raw_कुंजी);
	मुक्त(ip);
	मुक्त(host);
	यदि (host_hostkeys != रिक्त)
		free_hostkeys(host_hostkeys);
	यदि (ip_hostkeys != रिक्त)
		free_hostkeys(ip_hostkeys);
	प्रत्यागम -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
पूर्णाङ्क
verify_host_कुंजी(वर्ण *host, संरचना sockaddr *hostaddr, संरचना sshkey *host_कुंजी,
    ध्रुव संरचना ssh_conn_info *cinfo)
{
	u_int i;
	पूर्णाङ्क r = -1, flags = 0;
	वर्ण valid[64], *fp = रिक्त, *cafp = रिक्त;
	संरचना sshkey *plain = रिक्त;

	यदि ((fp = sshkey_fingerprint(host_कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_fr(r, "fingerprint host key");
		r = -1;
		गच्छ out;
	}

	यदि (sshkey_is_cert(host_कुंजी)) {
		यदि ((cafp = sshkey_fingerprint(host_कुंजी->cert->signature_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			गच्छ out;
		}
		sshkey_format_cert_validity(host_कुंजी->cert,
		    valid, परिमाण(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_कुंजी), fp,
		    (अचिन्हित दीर्घ दीर्घ)host_कुंजी->cert->serial,
		    host_कुंजी->cert->कुंजी_id,
		    sshkey_ssh_name(host_कुंजी->cert->signature_कुंजी), cafp,
		    valid);
		प्रति (i = 0; i < host_कुंजी->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_कुंजी->cert->principals[i]);
		}
	} अन्यथा {
		debug("Server host key: %s %s", sshkey_ssh_name(host_कुंजी), fp);
	}

	यदि (sshkey_equal(previous_host_कुंजी, host_कुंजी)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_कुंजी), fp);
		r = 0;
		गच्छ out;
	}

	/* Check in RevokedHostKeys files if specified */
	प्रति (i = 0; i < options.अंक_revoked_host_कुंजियाँ; i++) {
		r = sshkey_check_revoked(host_कुंजी,
		    options.revoked_host_कुंजियाँ[i]);
		विकल्प (r) {
		पक्ष 0:
			भङ्ग; /* not revoked */
		पक्ष SSH_ERR_कुंजी_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_कुंजी), fp,
			    options.revoked_host_कुंजियाँ[i]);
			r = -1;
			गच्छ out;
		स्वभाव:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_कुंजी),
			    fp, options.revoked_host_कुंजियाँ[i]);
			r = -1;
			गच्छ out;
		}
	}

	यदि (options.verify_host_कुंजी_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		यदि ((r = sshkey_from_private(host_कुंजी, &plain)) != 0)
			गच्छ out;
		यदि (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		यदि (verify_host_कुंजी_dns(host, hostaddr, plain, &flags) == 0) {
			यदि (flags & DNS_VERIFY_FOUND) {
				यदि (options.verify_host_कुंजी_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					गच्छ out;
				}
				यदि (flags & DNS_VERIFY_MATCH) {
					matching_host_कुंजी_dns = 1;
				} अन्यथा {
					warn_changed_कुंजी(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_कुंजी(host, cinfo, hostaddr, options.port, host_कुंजी,
	    RDRW, 0, options.user_hostfiles, options.अंक_user_hostfiles,
	    options.system_hostfiles, options.अंक_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	मुक्त(fp);
	मुक्त(cafp);
	यदि (r == 0 && host_कुंजी != रिक्त) {
		sshkey_free(previous_host_कुंजी);
		r = sshkey_from_private(host_कुंजी, &previous_host_कुंजी);
	}

	प्रत्यागम r;
}

स्थिर शून्य
warn_nonpq_kex(शून्य)
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
शून्य
ssh_login(संरचना ssh *ssh, Sensitive *sensitive, ध्रुव वर्ण *orighost,
    संरचना sockaddr_storage *hostaddr, u_short port, संरचना passwd *pw,
    पूर्णाङ्क timeout_ms, ध्रुव संरचना ssh_conn_info *cinfo)
{
	वर्ण *host;
	वर्ण *server_user, *local_user;
	पूर्णाङ्क r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	यदि ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	यदि ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	यदि (!options.kex_algorithms_set && ssh->kex != रिक्त &&
	    ssh->kex->name != रिक्त && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	मुक्त(local_user);
	मुक्त(host);
}

/* print all known host keys for a given host, but skip keys of given type */
स्थिर पूर्णाङ्क
show_other_कुंजियाँ(संरचना hostkeys *hostkeys, संरचना sshkey *कुंजी)
{
	पूर्णाङ्क type[] = {
		कुंजी_RSA,
		कुंजी_ECDSA,
		कुंजी_ED25519,
		कुंजी_MLDSA44_ED25519,
		-1
	};
	पूर्णाङ्क i, ret = 0;
	वर्ण *fp, *ra;
	ध्रुव संरचना hostkey_entry *found;

	प्रति (i = 0; type[i] != -1; i++) {
		यदि (type[i] == कुंजी->type)
			अनुवर्त;
		यदि (!lookup_कुंजी_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			अनुवर्त;
		fp = sshkey_fingerprint(found->कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->कुंजी,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		यदि (fp == रिक्त || ra == रिक्त)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->कुंजी),
		    found->host, found->file, found->पंक्ति,
		    sshkey_type(found->कुंजी), fp);
		यदि (options.visual_host_कुंजी)
			logit("%s", ra);
		मुक्त(ra);
		मुक्त(fp);
		ret = 1;
	}
	प्रत्यागम ret;
}

स्थिर शून्य
warn_changed_कुंजी(संरचना sshkey *host_कुंजी)
{
	वर्ण *fp;

	fp = sshkey_fingerprint(host_कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	यदि (fp == रिक्त)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_कुंजी), fp);
	error("Please contact your system administrator.");

	मुक्त(fp);
}

/*
 * Execute a local command
 */
पूर्णाङ्क
ssh_local_cmd(ध्रुव वर्ण *args)
{
	वर्ण *shell;
	pid_t pid;
	पूर्णाङ्क status;
	शून्य (*osighand)(पूर्णाङ्क);

	यदि (!options.permit_local_command ||
	    args == रिक्त || !*args)
		प्रत्यागम (1);

	यदि ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, संक_पूर्व);
	pid = विभाजन();
	यदि (pid == 0) {
		ssh_signal(SIGPIPE, संक_पूर्व);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (वर्ण *)रिक्त);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, म_त्रुटि(त्रुटि_सं));
		_exit(1);
	} अन्यथा यदि (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	यावत् (waitpid(pid, &status, 0) == -1)
		यदि (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, osighand);

	यदि (!WIFEXITED(status))
		प्रत्यागम (1);

	प्रत्यागम (WEXITSTATUS(status));
}

शून्य
maybe_add_कुंजी_to_agent(ध्रुव वर्ण *authfile, संरचना sshkey *गुप्त,
    ध्रुव वर्ण *comment, ध्रुव वर्ण *passphrase)
{
	पूर्णाङ्क auth_sock = -1, r;
	ध्रुव वर्ण *skprovider = रिक्त;

	यदि (options.add_कुंजियाँ_to_agent == 0)
		प्रत्यागम;

	यदि ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		प्रत्यागम;
	}

	यदि (options.add_कुंजियाँ_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		बंद(auth_sock);
		प्रत्यागम;
	}
	यदि (sshkey_is_sk(गुप्त))
		skprovider = options.sk_provider;
	यदि ((r = ssh_add_identity_constrained(auth_sock, गुप्त,
	    comment == रिक्त ? authfile : comment,
	    options.add_कुंजियाँ_to_agent_lifespan,
	    (options.add_कुंजियाँ_to_agent == 3), skprovider, रिक्त, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	अन्यथा
		debug("could not add identity to agent: %s (%d)", authfile, r);
	बंद(auth_sock);
}
