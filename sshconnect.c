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

संरचना sshkey *previous_host_किल्ली = रिक्त;

स्थिर पूर्णांक matching_host_किल्ली_dns = 0;

स्थिर pid_t proxy_command_pid = 0;

/* import */
बाह्य पूर्णांक debug_flag;
बाह्य Options options;
बाह्य अक्षर *__progname;

स्थिर पूर्णांक show_other_किल्ल्या(संरचना hostkeys *, संरचना sshkey *);
स्थिर शून्य warn_changed_किल्ली(संरचना sshkey *);

शून्य
ssh_conn_info_free(संरचना ssh_conn_info *cinfo)
{
	जर (cinfo == रिक्त)
		परत;
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
	freezero(cinfo, आकार(*cinfo));
}

संरचना ssh_conn_info *
ssh_conn_info_dup(स्थिरांक संरचना ssh_conn_info *cinfo)
{
	संरचना ssh_conn_info *ret;

	जर (cinfo == रिक्त)
		परत रिक्त;
	ret = xcalloc(1, आकार(*ret));
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
	परत ret;
}

/* Expand a proxy command */
स्थिर अक्षर *
expand_proxy_command(स्थिरांक अक्षर *proxy_command, स्थिरांक अक्षर *user,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *host_arg, पूर्णांक port)
{
	अक्षर *tmp, *ret, strport[NI_MAXSERV];
	स्थिरांक अक्षर *keyalias = options.host_किल्ली_alias ?
	    options.host_किल्ली_alias : host_arg;

	snprintf(strport, आकार strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (अक्षर *)रिक्त);
	मुक्त(tmp);
	परत ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
स्थिर पूर्णांक
ssh_proxy_fdpass_connect(संरचना ssh *ssh, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *host_arg, u_short port, स्थिरांक अक्षर *proxy_command)
{
	अक्षर *command_string;
	पूर्णांक sp[2], sock;
	pid_t pid;
	अक्षर *shell;

	जर ((shell = दो_पर्या("SHELL")) == रिक्त)
		shell = _PATH_BSHELL;

	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	जर ((pid = विभाजन()) == 0) {
		अक्षर *argv[10];

		बंद(sp[1]);
		/* Redirect stdin and stdout. */
		जर (sp[0] != 0) {
			जर (dup2(sp[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
		}
		जर (sp[0] != 1) {
			जर (dup2(sp[0], 1) == -1)
				लिखो_त्रुटि("dup2 stdout");
		}
		जर (sp[0] >= 2)
			बंद(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		जर (!debug_flag && options.control_path != रिक्त &&
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
	जर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	बंद(sp[0]);
	मुक्त(command_string);

	जर ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	बंद(sp[1]);

	पर्यंत (waitpid(pid, रिक्त, 0) == -1)
		जर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));

	/* Set the connection file descriptors. */
	जर (ssh_packet_set_connection(ssh, sock, sock) == रिक्त)
		परत -1; /* ssh_packet_set_connection logs error */

	परत 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
स्थिर पूर्णांक
ssh_proxy_connect(संरचना ssh *ssh, स्थिरांक अक्षर *host, स्थिरांक अक्षर *host_arg,
    u_short port, स्थिरांक अक्षर *proxy_command)
{
	अक्षर *command_string;
	पूर्णांक pin[2], pout[2];
	pid_t pid;
	अक्षर *shell;

	जर ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	जर (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	जर ((pid = विभाजन()) == 0) {
		अक्षर *argv[10];

		/* Redirect stdin and stdout. */
		बंद(pin[1]);
		जर (pin[0] != 0) {
			जर (dup2(pin[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
			बंद(pin[0]);
		}
		बंद(pout[0]);
		जर (dup2(pout[1], 1) == -1)
			लिखो_त्रुटि("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		बंद(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		जर (!debug_flag && options.control_path != रिक्त &&
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
	जर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	अन्यथा
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	बंद(pin[0]);
	बंद(pout[1]);

	/* Free the command name. */
	मुक्त(command_string);

	/* Set the connection file descriptors. */
	जर (ssh_packet_set_connection(ssh, pout[0], pin[1]) == रिक्त)
		परत -1; /* ssh_packet_set_connection logs error */

	परत 0;
}

शून्य
ssh_kill_proxy_command(शून्य)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	जर (proxy_command_pid > 1)
		समाप्त(proxy_command_pid, SIGHUP);
}

#ifdef HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
स्थिर पूर्णांक
check_ifaddrs(स्थिरांक अक्षर *ifname, पूर्णांक af, स्थिरांक संरचना ifaddrs *ifaddrs,
    संरचना sockaddr_storage *resultp, socklen_t *rlenp)
{
	संरचना sockaddr_in6 *sa6;
	संरचना sockaddr_in *sa;
	संरचना in6_addr *v6addr;
	स्थिरांक संरचना ifaddrs *ifa;
	पूर्णांक allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	साठी (allow_local = 0; allow_local < 2; allow_local++) {
		साठी (ifa = ifaddrs; ifa != रिक्त; ifa = ifa->ifa_next) {
			जर (ifa->ifa_addr == रिक्त || ifa->ifa_name == रिक्त ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    म_भेद(ifa->ifa_name, options.bind_interface) != 0)
				सुरूठेवा;
			निवड (ifa->ifa_addr->sa_family) {
			स्थिती AF_INET:
				sa = (संरचना sockaddr_in *)ifa->ifa_addr;
				जर (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					सुरूठेवा;
				जर (*rlenp < आकार(संरचना sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					परत -1;
				}
				*rlenp = आकार(संरचना sockaddr_in);
				स_नकल(resultp, sa, *rlenp);
				परत 0;
			स्थिती AF_INET6:
				sa6 = (संरचना sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				जर (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					सुरूठेवा;
				जर (*rlenp < आकार(संरचना sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					परत -1;
				}
				*rlenp = आकार(संरचना sockaddr_in6);
				स_नकल(resultp, sa6, *rlenp);
				परत 0;
			}
		}
	}
	परत -1;
}
#endif

/*
 * Creates a socket for use as the ssh connection.
 */
स्थिर पूर्णांक
ssh_create_socket(संरचना addrinfo *ai)
{
	पूर्णांक sock, r;
	संरचना sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	संरचना addrinfo hints, *res = रिक्त;
#ifdef HAVE_IFADDRS_H
	संरचना ifaddrs *ifaddrs = रिक्त;
#endif
	अक्षर ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	जर (sock == -1) {
		error("socket: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	(शून्य)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	जर (options.ip_qos_interactive != पूर्णांक_उच्च)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	जर (options.bind_address == रिक्त && options.bind_interface == रिक्त)
		परत sock;

	जर (options.bind_address != रिक्त) {
		स_रखो(&hints, 0, आकार(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		जर ((r = getaddrinfo(options.bind_address, रिक्त,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			जा fail;
		}
		जर (res == रिक्त) {
			error("getaddrinfo: no addrs");
			जा fail;
		}
		स_नकल(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} अन्यथा जर (options.bind_interface != रिक्त) {
#ifdef HAVE_IFADDRS_H
		जर ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    म_त्रुटि(त्रुटि_सं));
			जा fail;
		}
		bindaddrlen = आकार(bindaddr);
		जर (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			जा fail;
		}
#अन्यथा
		error("BindInterface not supported on this platform.");
#endif
	}
	जर ((r = getnameinfo((संरचना sockaddr *)&bindaddr, bindaddrlen,
	    ntop, आकार(ntop), रिक्त, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		जा fail;
	}
	जर (bind(sock, (संरचना sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, म_त्रुटि(त्रुटि_सं));
		जा fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	जा out;
fail:
	बंद(sock);
	sock = -1;
 out:
	जर (res != रिक्त)
		freeaddrinfo(res);
#ifdef HAVE_IFADDRS_H
	जर (ifaddrs != रिक्त)
		freeifaddrs(ifaddrs);
#endif
	परत sock;
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
स्थिर पूर्णांक
ssh_connect_direct(संरचना ssh *ssh, स्थिरांक अक्षर *host, संरचना addrinfo *aitop,
    संरचना sockaddr_storage *hostaddr, u_short port, पूर्णांक connection_attempts,
    पूर्णांक *timeout_ms, पूर्णांक want_keepalive)
{
	पूर्णांक saved_timeout_ms = *timeout_ms;
	पूर्णांक oerrno, sock = -1, attempt;
	अक्षर ntop[NI_MAXHOST], strport[NI_MAXSERV];
	संरचना addrinfo *ai;

	debug3_f("entering");
	स_रखो(ntop, 0, आकार(ntop));
	स_रखो(strport, 0, आकार(strport));

	साठी (attempt = 0; attempt < connection_attempts; attempt++) {
		जर (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		साठी (ai = aitop; ai; ai = ai->ai_next) {
			जर (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				त्रुटि_सं = EAFNOSUPPORT;
				सुरूठेवा;
			}
			जर (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, आकार(ntop), strport, आकार(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = त्रुटि_सं;
				error_f("getnameinfo failed");
				त्रुटि_सं = oerrno;
				सुरूठेवा;
			}
			जर (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				त्रुटि_सं = EAFNOSUPPORT;
				सुरूठेवा;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			जर (sock < 0) {
				/* Any error is already output */
				त्रुटि_सं = 0;
				सुरूठेवा;
			}

			*timeout_ms = saved_timeout_ms;
			जर (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				स_नकल(hostaddr, ai->ai_addr, ai->ai_addrlen);
				थांबा;
			} अन्यथा {
				oerrno = त्रुटि_सं;
				debug("connect to address %s port %s: %s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				त्रुटि_सं = oerrno;
			}
		}
		जर (sock != -1)
			थांबा;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	जर (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, त्रुटि_सं == 0 ? "failure" : म_त्रुटि(त्रुटि_सं));
		परत -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	जर (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	जर (ssh_packet_set_connection(ssh, sock, sock) == रिक्त)
		परत -1; /* ssh_packet_set_connection logs error */

	परत 0;
}

पूर्णांक
ssh_connect(संरचना ssh *ssh, स्थिरांक अक्षर *host, स्थिरांक अक्षर *host_arg,
    संरचना addrinfo *addrs, संरचना sockaddr_storage *hostaddr, u_short port,
    पूर्णांक connection_attempts, पूर्णांक *timeout_ms, पूर्णांक want_keepalive)
{
	पूर्णांक in, out;

	जर (options.proxy_command == रिक्त) {
		परत ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} अन्यथा जर (म_भेद(options.proxy_command, "-") == 0) {
		जर ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			जर (in >= 0)
				बंद(in);
			error_f("dup() in/out failed");
			परत -1; /* ssh_packet_set_connection logs error */
		}
		जर ((ssh_packet_set_connection(ssh, in, out)) == रिक्त)
			परत -1; /* ssh_packet_set_connection logs error */
		परत 0;
	} अन्यथा जर (options.proxy_use_fdpass) {
		परत ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	परत ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
स्थिर पूर्णांक
confirm(स्थिरांक अक्षर *prompt, स्थिरांक अक्षर *fingerprint)
{
	स्थिरांक अक्षर *संदेश, *again = "Please type 'yes' or 'no': ";
	स्थिरांक अक्षर *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	अक्षर *p, *cp;
	पूर्णांक ret = -1;

	जर (options.batch_mode)
		परत 0;
	साठी (संदेश = prompt;;संदेश = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(संदेश, RP_ECHO);
		जर (p == रिक्त)
			परत 0;
		p += म_अखोज(p, " \t"); /* skip leading whitespace */
		p[म_खोज(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		जर (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		अन्यथा जर (strcasecmp(p, "yes") == 0 || (fingerprint != रिक्त &&
		    म_भेद(p, fingerprint) == 0))
			ret = 1;
		मुक्त(cp);
		जर (ret != -1)
			परत ret;
	}
}

स्थिर पूर्णांक
sockaddr_is_local(संरचना sockaddr *hostaddr)
{
	निवड (hostaddr->sa_family) {
	स्थिती AF_INET:
		परत (ntohl(((संरचना sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	स्थिती AF_INET6:
		परत IN6_IS_ADDR_LOOPBACK(
		    &(((संरचना sockaddr_in6 *)hostaddr)->sin6_addr));
	पूर्वनिर्धारित:
		परत 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
शून्य
get_hostfile_hostname_ipaddr(अक्षर *hostname, संरचना sockaddr *hostaddr,
    u_short port, अक्षर **hostfile_hostname, अक्षर **hostfile_ipaddr)
{
	अक्षर ntop[NI_MAXHOST];
	socklen_t addrlen;

	निवड (hostaddr == रिक्त ? -1 : hostaddr->sa_family) {
	स्थिती -1:
		addrlen = 0;
		थांबा;
	स्थिती AF_INET:
		addrlen = आकार(संरचना sockaddr_in);
		थांबा;
	स्थिती AF_INET6:
		addrlen = आकार(संरचना sockaddr_in6);
		थांबा;
	पूर्वनिर्धारित:
		addrlen = आकार(संरचना sockaddr);
		थांबा;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	जर (hostfile_ipaddr != रिक्त) {
		जर (options.proxy_command == रिक्त) {
			जर (getnameinfo(hostaddr, addrlen,
			    ntop, आकार(ntop), रिक्त, 0, NI_NUMERICHOST) != 0)
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
	जर (hostfile_hostname != रिक्त) {
		जर (options.host_किल्ली_alias != रिक्त) {
			*hostfile_hostname = xstrdup(options.host_किल्ली_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} अन्यथा {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
स्थिर पूर्णांक
path_in_hostfiles(स्थिरांक अक्षर *path, अक्षर **hostfiles, u_int अंक_hostfiles)
{
	u_int i;

	साठी (i = 0; i < अंक_hostfiles; i++) {
		जर (म_भेद(path, hostfiles[i]) == 0)
			परत 1;
	}
	परत 0;
}

संरचना find_by_किल्ली_ctx {
	स्थिरांक अक्षर *host, *ip;
	स्थिरांक संरचना sshkey *किल्ली;
	अक्षर **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
स्थिर अक्षर *
try_tilde_unexpand(स्थिरांक अक्षर *path)
{
	अक्षर *home, *ret = रिक्त;
	माप_प्रकार l;

	जर (*path != '/')
		परत xstrdup(path);
	जर ((home = दो_पर्या("HOME")) == रिक्त || (l = म_माप(home)) == 0)
		परत xstrdup(path);
	जर (म_भेदन(path, home, l) != 0)
		परत xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	जर (home[l - 1] != '/' && path[l] != '/')
		परत xstrdup(path);
	जर (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	परत ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
पूर्णांक
hostkey_accepted_by_hostkeyalgs(स्थिरांक संरचना sshkey *किल्ली)
{
	स्थिरांक अक्षर *ktype = sshkey_ssh_name(किल्ली);
	स्थिरांक अक्षर *hostkeyalgs = options.hostkeyalgorithms;

	जर (किल्ली->type == किल्ली_UNSPEC)
		परत 0;
	जर (किल्ली->type == किल्ली_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		परत 1;
	जर (किल्ली->type == किल्ली_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		परत 1;
	परत match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

स्थिर पूर्णांक
hostkeys_find_by_किल्ली_cb(संरचना hostkey_foreach_ओळ *l, शून्य *_ctx)
{
	संरचना find_by_किल्ली_ctx *ctx = (संरचना find_by_किल्ली_ctx *)_ctx;
	अक्षर *path;

	/* we are looking for keys with names that *do not* match */
	जर ((l->match & HKF_MATCH_HOST) != 0)
		परत 0;
	/* not interested in marker lines */
	जर (l->marker != MRK_NONE)
		परत 0;
	/* we are only interested in exact key matches */
	जर (l->किल्ली == रिक्त || !sshkey_equal(ctx->किल्ली, l->किल्ली))
		परत 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, आकार(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    म_भेदन(l->hosts, HASH_MAGIC, म_माप(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	मुक्त(path);
	परत 0;
}

स्थिर पूर्णांक
hostkeys_find_by_किल्ली_hostfile(स्थिरांक अक्षर *file, स्थिरांक अक्षर *which,
    संरचना find_by_किल्ली_ctx *ctx)
{
	पूर्णांक r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	जर ((r = hostkeys_foreach(file, hostkeys_find_by_किल्ली_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_किल्ली, 0)) != 0) {
		जर (r == SSH_ERR_SYSTEM_ERROR && त्रुटि_सं == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			परत 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		परत r;
	}
	परत 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
स्थिर शून्य
hostkeys_find_by_किल्ली(स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, स्थिरांक संरचना sshkey *किल्ली,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles,
    अक्षर ***names, u_int *nnames)
{
	संरचना find_by_किल्ली_ctx ctx = {रिक्त, रिक्त, रिक्त, रिक्त, 0};
	u_int i;

	*names = रिक्त;
	*nnames = 0;

	जर (किल्ली == रिक्त || sshkey_is_cert(किल्ली))
		परत;

	ctx.host = host;
	ctx.ip = ip;
	ctx.किल्ली = किल्ली;

	साठी (i = 0; i < अंक_user_hostfiles; i++) {
		जर (hostkeys_find_by_किल्ली_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			जा fail;
	}
	साठी (i = 0; i < अंक_system_hostfiles; i++) {
		जर (hostkeys_find_by_किल्ली_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			जा fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = रिक्त;
	ctx.nnames = 0;
	परत;
 fail:
	साठी (i = 0; i < ctx.nnames; i++)
		मुक्त(ctx.names[i]);
	मुक्त(ctx.names);
}

#define MAX_OTHER_NAMES	8 /* Maximum number of names to list */
स्थिर अक्षर *
other_hostkeys_message(स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip,
    स्थिरांक संरचना sshkey *किल्ली,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles)
{
	अक्षर *ret = रिक्त, **othernames = रिक्त;
	u_int i, n, अंक_othernames = 0;

	hostkeys_find_by_किल्ली(host, ip, किल्ली,
	    user_hostfiles, अंक_user_hostfiles,
	    system_hostfiles, अंक_system_hostfiles,
	    &othernames, &अंक_othernames);
	जर (अंक_othernames == 0)
		परत xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = अंक_othernames;
	जर (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	साठी (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	जर (n < अंक_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    अंक_othernames - n);
	}
	साठी (i = 0; i < अंक_othernames; i++)
		मुक्त(othernames[i]);
	मुक्त(othernames);
	परत ret;
}

शून्य
load_hostkeys_command(संरचना hostkeys *hostkeys, स्थिरांक अक्षर *command_template,
    स्थिरांक अक्षर *invocation, स्थिरांक संरचना ssh_conn_info *cinfo,
    स्थिरांक संरचना sshkey *host_किल्ली, स्थिरांक अक्षर *hostfile_hostname)
{
	पूर्णांक r, i, ac = 0;
	अक्षर *किल्ली_fp = रिक्त, *keytext = रिक्त, *tmp;
	अक्षर *command = रिक्त, *tag = रिक्त, **av = रिक्त;
	खाता *f = रिक्त;
	pid_t pid;
	शून्य (*osigchld)(पूर्णांक);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	जर (host_किल्ली != रिक्त) {
		जर ((किल्ली_fp = sshkey_fingerprint(host_किल्ली,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		जर ((r = sshkey_to_base64(host_किल्ली, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Turn the command into an argument vector */
	जर (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		जा out;
	}
	जर (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		जा out;
	}
	साठी (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_किल्ली == रिक्त ? "NONE" : sshkey_ssh_name(host_किल्ली),
		    "f", किल्ली_fp == रिक्त ? "NONE" : किल्ली_fp,
		    "K", keytext == रिक्त ? "NONE" : keytext,
		    (अक्षर *)रिक्त);
		जर (tmp == रिक्त)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	जर ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, रिक्त, रिक्त, रिक्त)) == 0)
		जा out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	जर (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	जर (f != रिक्त)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	साठी (i = 0; i < ac; i++)
		मुक्त(av[i]);
	मुक्त(av);
	मुक्त(tag);
	मुक्त(command);
	मुक्त(किल्ली_fp);
	मुक्त(keytext);
}

/*
 * check whether the supplied host key is valid, return -1 if the key
 * is not valid. user_hostfile[0] will not be updated if 'readonly' is true.
 */
#define RDRW	0
#define RDONLY	1
#define ROQUIET	2
स्थिर पूर्णांक
check_host_किल्ली(अक्षर *hostname, स्थिरांक संरचना ssh_conn_info *cinfo,
    संरचना sockaddr *hostaddr, u_short port,
    संरचना sshkey *host_किल्ली, पूर्णांक readonly, पूर्णांक clobber_port,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles,
    स्थिरांक अक्षर *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	संरचना sshkey *raw_किल्ली = रिक्त;
	अक्षर *ip = रिक्त, *host = रिक्त;
	अक्षर hostline[1000], *hostp, *fp, *ra;
	अक्षर संदेश[1024];
	स्थिरांक अक्षर *type, *fail_reason = रिक्त;
	स्थिरांक संरचना hostkey_entry *host_found = रिक्त, *ip_found = रिक्त;
	पूर्णांक len, cancelled_forwarding = 0, confirmed;
	पूर्णांक local = sockaddr_is_local(hostaddr);
	पूर्णांक r, want_cert = sshkey_is_cert(host_किल्ली), host_ip_differ = 0;
	पूर्णांक hostkey_trusted = 0; /* Known or explicitly accepted by user */
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
	जर (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_किल्ली_alias == रिक्त) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		परत 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	जर (म_खोज(hostname, "@?*#[]|'\'\"\\") != म_माप(hostname)) {
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
	जर (options.check_host_ip && (local ||
	    म_भेद(hostname, ip) == 0 || options.proxy_command != रिक्त))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	साठी (i = 0; i < अंक_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	साठी (i = 0; i < अंक_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	जर (hostfile_command != रिक्त && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_किल्ली, host);
	}

	ip_hostkeys = रिक्त;
	जर (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		साठी (i = 0; i < अंक_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		साठी (i = 0; i < अंक_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		जर (hostfile_command != रिक्त && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_किल्ली, ip);
		}
	}

 retry:
	जर (!hostkey_accepted_by_hostkeyalgs(host_किल्ली)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_किल्ली));
		जा fail;
	}

	/* Reload these as they may have changed on cert->key downgrade */
	want_cert = sshkey_is_cert(host_किल्ली);
	type = sshkey_type(host_किल्ली);

	/*
	 * Check if the host key is present in the user's list of known
	 * hosts or in the systemwide list.
	 */
	host_status = check_किल्ली_in_hostkeys(host_hostkeys, host_किल्ली,
	    &host_found);

	/*
	 * If there are no hostfiles, or if the hostkey was found via
	 * KnownHostsCommand, then don't try to touch the disk.
	 */
	जर (!readonly && (अंक_user_hostfiles == 0 ||
	    (host_found != रिक्त && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	जर (!want_cert && ip_hostkeys != रिक्त) {
		ip_status = check_किल्ली_in_hostkeys(ip_hostkeys, host_किल्ली,
		    &ip_found);
		जर (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != रिक्त &&
		    !sshkey_equal(ip_found->किल्ली, host_found->किल्ली))))
			host_ip_differ = 1;
	} अन्यथा
		ip_status = host_status;

	निवड (host_status) {
	स्थिती HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->ओळ);
		जर (want_cert) {
			जर (sshkey_cert_check_host(host_किल्ली,
			    options.host_किल्ली_alias == रिक्त ?
			    hostname : options.host_किल्ली_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				जा fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			जर (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		जर (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, अंक_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != रिक्त &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, अंक_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		जर (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		जर (options.check_host_ip && ip_status == HOST_NEW) {
			जर (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			अन्यथा जर (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_किल्ली, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			अन्यथा
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} अन्यथा जर (options.visual_host_किल्ली) {
			fp = sshkey_fingerprint(host_किल्ली,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_किल्ली,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			जर (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			मुक्त(ra);
			मुक्त(fp);
		}
		hostkey_trusted = 1;
		थांबा;
	स्थिती HOST_NEW:
		जर (options.host_किल्ली_alias == रिक्त && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			जर (check_host_किल्ली(hostname, cinfo, hostaddr, 0,
			    host_किल्ली, ROQUIET, 1,
			    user_hostfiles, अंक_user_hostfiles,
			    system_hostfiles, अंक_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				थांबा;
			}
		}
		जर (readonly || want_cert)
			जा fail;
		/* The host is new. */
		जर (options.strict_host_किल्ली_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			जा fail;
		} अन्यथा जर (options.strict_host_किल्ली_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			अक्षर *msg1 = रिक्त, *msg2 = रिक्त;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			जर (show_other_किल्ल्या(host_hostkeys, host_किल्ली)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} अन्यथा
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_किल्ली,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_किल्ली,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			जर (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			जर (options.visual_host_किल्ली)
				xextendf(&msg1, "\n", "%s", ra);
			जर (options.verify_host_किल्ली_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_किल्ली_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			जर ((msg2 = other_hostkeys_message(host, ip, host_किल्ली,
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
			जर (!confirmed)
				जा fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		जर (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, आकार(hostline), "%s,%s", host, ip);
			hostp = hostline;
			जर (options.hash_known_hosts) {
				/* Add hash of host and IP separately */
				r = add_host_to_hostfile(user_hostfiles[0],
				    host, host_किल्ली, options.hash_known_hosts) &&
				    add_host_to_hostfile(user_hostfiles[0], ip,
				    host_किल्ली, options.hash_known_hosts);
			} अन्यथा {
				/* Add unhashed "host,ip" */
				r = add_host_to_hostfile(user_hostfiles[0],
				    hostline, host_किल्ली,
				    options.hash_known_hosts);
			}
		} अन्यथा {
			r = add_host_to_hostfile(user_hostfiles[0], host,
			    host_किल्ली, options.hash_known_hosts);
			hostp = host;
		}

		जर (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		अन्यथा
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		थांबा;
	स्थिती HOST_REVOKED:
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
		जर (options.strict_host_किल्ली_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			जा fail;
		}
		जा continue_unsafe;

	स्थिती HOST_CHANGED:
		जर (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->ओळ);
			जा fail;
		}
		जर (readonly == ROQUIET)
			जा fail;
		जर (options.check_host_ip && host_ip_differ) {
			अक्षर *किल्ली_संदेश;
			जर (ip_status == HOST_NEW)
				किल्ली_संदेश = "is unknown";
			अन्यथा जर (ip_status == HOST_OK)
				किल्ली_संदेश = "is unchanged";
			अन्यथा
				किल्ली_संदेश = "has a different value";
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
			error("The %s host key for %s has changed,", type, host);
			error("and the key for the corresponding IP address %s", ip);
			error("%s. This could either mean that", किल्ली_संदेश);
			error("DNS SPOOFING is happening or the IP address for the host");
			error("and its host key have changed at the same time.");
			जर (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->ओळ);
		}
		/* The host key has changed. */
		warn_changed_किल्ली(host_किल्ली);
		जर (अंक_user_hostfiles > 0 || अंक_system_hostfiles > 0) {
			error("Add correct host key in %.100s to get rid "
			    "of this message.", अंक_user_hostfiles > 0 ?
			    user_hostfiles[0] : system_hostfiles[0]);
		}
		error("Offending %s key in %s:%lu",
		    sshkey_type(host_found->किल्ली),
		    host_found->file, host_found->ओळ);

		/*
		 * If strict host key checking is in use, the user will have
		 * to edit the key manually and we can only abort.
		 */
		जर (options.strict_host_किल्ली_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			जा fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		जर (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		जर (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		जर (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		जर (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		जर (options.अंक_local_forwards > 0 ||
		    options.अंक_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.अंक_local_forwards =
			    options.अंक_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		जर (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		जर (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		जर (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		थांबा;
	स्थिती HOST_FOUND:
		fatal("internal error");
		थांबा;
	}

	जर (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(संदेश, आकार(संदेश),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->ओळ);
		जर (host_status == HOST_OK) {
			len = म_माप(संदेश);
			snprintf(संदेश + len, आकार(संदेश) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->ओळ);
		}
		जर (options.strict_host_किल्ली_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(संदेश, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", आकार(संदेश));
			जर (!confirm(संदेश, रिक्त))
				जा fail;
		} अन्यथा जर (options.strict_host_किल्ली_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", संदेश);
			error("Exiting, you have requested strict checking.");
			जा fail;
		} अन्यथा {
			logit("%s", संदेश);
		}
	}

	जर (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_किल्ली);
	मुक्त(ip);
	मुक्त(host);
	जर (host_hostkeys != रिक्त)
		free_hostkeys(host_hostkeys);
	जर (ip_hostkeys != रिक्त)
		free_hostkeys(ip_hostkeys);
	परत 0;

fail:
	जर (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		जर ((r = sshkey_from_private(host_किल्ली, &raw_किल्ली)) != 0)
			fatal_fr(r, "decode key");
		जर ((r = sshkey_drop_cert(raw_किल्ली)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_किल्ली = raw_किल्ली;
		जा retry;
	}
	sshkey_free(raw_किल्ली);
	मुक्त(ip);
	मुक्त(host);
	जर (host_hostkeys != रिक्त)
		free_hostkeys(host_hostkeys);
	जर (ip_hostkeys != रिक्त)
		free_hostkeys(ip_hostkeys);
	परत -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
पूर्णांक
verify_host_किल्ली(अक्षर *host, संरचना sockaddr *hostaddr, संरचना sshkey *host_किल्ली,
    स्थिरांक संरचना ssh_conn_info *cinfo)
{
	u_int i;
	पूर्णांक r = -1, flags = 0;
	अक्षर valid[64], *fp = रिक्त, *cafp = रिक्त;
	संरचना sshkey *plain = रिक्त;

	जर ((fp = sshkey_fingerprint(host_किल्ली,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
		error_fr(r, "fingerprint host key");
		r = -1;
		जा out;
	}

	जर (sshkey_is_cert(host_किल्ली)) {
		जर ((cafp = sshkey_fingerprint(host_किल्ली->cert->signature_किल्ली,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			जा out;
		}
		sshkey_format_cert_validity(host_किल्ली->cert,
		    valid, आकार(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_किल्ली), fp,
		    (अचिन्हित दीर्घ दीर्घ)host_किल्ली->cert->serial,
		    host_किल्ली->cert->किल्ली_id,
		    sshkey_ssh_name(host_किल्ली->cert->signature_किल्ली), cafp,
		    valid);
		साठी (i = 0; i < host_किल्ली->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_किल्ली->cert->principals[i]);
		}
	} अन्यथा {
		debug("Server host key: %s %s", sshkey_ssh_name(host_किल्ली), fp);
	}

	जर (sshkey_equal(previous_host_किल्ली, host_किल्ली)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_किल्ली), fp);
		r = 0;
		जा out;
	}

	/* Check in RevokedHostKeys files if specified */
	साठी (i = 0; i < options.अंक_revoked_host_किल्ल्या; i++) {
		r = sshkey_check_revoked(host_किल्ली,
		    options.revoked_host_किल्ल्या[i]);
		निवड (r) {
		स्थिती 0:
			थांबा; /* not revoked */
		स्थिती SSH_ERR_किल्ली_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_किल्ली), fp,
			    options.revoked_host_किल्ल्या[i]);
			r = -1;
			जा out;
		पूर्वनिर्धारित:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_किल्ली),
			    fp, options.revoked_host_किल्ल्या[i]);
			r = -1;
			जा out;
		}
	}

	जर (options.verify_host_किल्ली_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		जर ((r = sshkey_from_private(host_किल्ली, &plain)) != 0)
			जा out;
		जर (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		जर (verify_host_किल्ली_dns(host, hostaddr, plain, &flags) == 0) {
			जर (flags & DNS_VERIFY_FOUND) {
				जर (options.verify_host_किल्ली_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					जा out;
				}
				जर (flags & DNS_VERIFY_MATCH) {
					matching_host_किल्ली_dns = 1;
				} अन्यथा {
					warn_changed_किल्ली(plain);
					error("Update the SSHFP RR in DNS "
					    "with the new host key to get rid "
					    "of this message.");
				}
			}
		}
	}
	r = check_host_किल्ली(host, cinfo, hostaddr, options.port, host_किल्ली,
	    RDRW, 0, options.user_hostfiles, options.अंक_user_hostfiles,
	    options.system_hostfiles, options.अंक_system_hostfiles,
	    options.known_hosts_command);

out:
	sshkey_free(plain);
	मुक्त(fp);
	मुक्त(cafp);
	जर (r == 0 && host_किल्ली != रिक्त) {
		sshkey_free(previous_host_किल्ली);
		r = sshkey_from_private(host_किल्ली, &previous_host_किल्ली);
	}

	परत r;
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
ssh_login(संरचना ssh *ssh, Sensitive *sensitive, स्थिरांक अक्षर *orighost,
    संरचना sockaddr_storage *hostaddr, u_short port, संरचना passwd *pw,
    पूर्णांक timeout_ms, स्थिरांक संरचना ssh_conn_info *cinfo)
{
	अक्षर *host;
	अक्षर *server_user, *local_user;
	पूर्णांक r;

	local_user = xstrdup(pw->pw_name);
	server_user = options.user ? options.user : local_user;

	/* Convert the user-supplied hostname into all lowercase. */
	host = xstrdup(orighost);
	lowercase(host);

	/* Exchange protocol version identification strings with the server. */
	जर ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	जर ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	जर (!options.kex_algorithms_set && ssh->kex != रिक्त &&
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
स्थिर पूर्णांक
show_other_किल्ल्या(संरचना hostkeys *hostkeys, संरचना sshkey *किल्ली)
{
	पूर्णांक type[] = {
		किल्ली_RSA,
		किल्ली_ECDSA,
		किल्ली_ED25519,
		किल्ली_MLDSA44_ED25519,
		-1
	};
	पूर्णांक i, ret = 0;
	अक्षर *fp, *ra;
	स्थिरांक संरचना hostkey_entry *found;

	साठी (i = 0; type[i] != -1; i++) {
		जर (type[i] == किल्ली->type)
			सुरूठेवा;
		जर (!lookup_किल्ली_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			सुरूठेवा;
		fp = sshkey_fingerprint(found->किल्ली,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->किल्ली,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		जर (fp == रिक्त || ra == रिक्त)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->किल्ली),
		    found->host, found->file, found->ओळ,
		    sshkey_type(found->किल्ली), fp);
		जर (options.visual_host_किल्ली)
			logit("%s", ra);
		मुक्त(ra);
		मुक्त(fp);
		ret = 1;
	}
	परत ret;
}

स्थिर शून्य
warn_changed_किल्ली(संरचना sshkey *host_किल्ली)
{
	अक्षर *fp;

	fp = sshkey_fingerprint(host_किल्ली, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	जर (fp == रिक्त)
		fatal_f("sshkey_fingerprint fail");

	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
	error("It is also possible that a host key has just been changed.");
	error("The fingerprint for the %s key sent by the remote host is\n%s.",
	    sshkey_type(host_किल्ली), fp);
	error("Please contact your system administrator.");

	मुक्त(fp);
}

/*
 * Execute a local command
 */
पूर्णांक
ssh_local_cmd(स्थिरांक अक्षर *args)
{
	अक्षर *shell;
	pid_t pid;
	पूर्णांक status;
	शून्य (*osighand)(पूर्णांक);

	जर (!options.permit_local_command ||
	    args == रिक्त || !*args)
		परत (1);

	जर ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, संक_पूर्व);
	pid = विभाजन();
	जर (pid == 0) {
		ssh_signal(SIGPIPE, संक_पूर्व);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (अक्षर *)रिक्त);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, म_त्रुटि(त्रुटि_सं));
		_exit(1);
	} अन्यथा जर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	पर्यंत (waitpid(pid, &status, 0) == -1)
		जर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, osighand);

	जर (!WIFEXITED(status))
		परत (1);

	परत (WEXITSTATUS(status));
}

शून्य
maybe_add_किल्ली_to_agent(स्थिरांक अक्षर *authfile, संरचना sshkey *खाजगी,
    स्थिरांक अक्षर *comment, स्थिरांक अक्षर *passphrase)
{
	पूर्णांक auth_sock = -1, r;
	स्थिरांक अक्षर *skprovider = रिक्त;

	जर (options.add_किल्ल्या_to_agent == 0)
		परत;

	जर ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		परत;
	}

	जर (options.add_किल्ल्या_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		बंद(auth_sock);
		परत;
	}
	जर (sshkey_is_sk(खाजगी))
		skprovider = options.sk_provider;
	जर ((r = ssh_add_identity_constrained(auth_sock, खाजगी,
	    comment == रिक्त ? authfile : comment,
	    options.add_किल्ल्या_to_agent_lifespan,
	    (options.add_किल्ल्या_to_agent == 3), skprovider, रिक्त, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	अन्यथा
		debug("could not add identity to agent: %s (%d)", authfile, r);
	बंद(auth_sock);
}
