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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>
#समावेश <sys/socket.h>

#समावेश <net/if.h>
#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <ifaddrs.h>

#समावेश "xmalloc.h"
#समावेश "hostfile.h"
#समावेश "ssh.h"
#समावेश "compat.h"
#समावेश "packet.h"
#समावेश "sshkey.h"
#समावेश "sshconnect.h"
#समावेश "log.h"
#समावेश "match.h"
#समावेश "misc.h"
#समावेश "readconf.h"
#समावेश "dns.h"
#समावेश "monitor_fdpass.h"
#समावेश "authfile.h"
#समावेश "ssherr.h"
#समावेश "authfd.h"
#समावेश "kex.h"

काष्ठा sshkey *previous_host_कुंजी = शून्य;

अटल पूर्णांक matching_host_कुंजी_dns = 0;

अटल pid_t proxy_command_pid = 0;

/* import */
बाह्य पूर्णांक debug_flag;
बाह्य Options options;
बाह्य अक्षर *__progname;

अटल पूर्णांक show_other_कुंजियाँ(काष्ठा hostkeys *, काष्ठा sshkey *);
अटल व्योम warn_changed_कुंजी(काष्ठा sshkey *);

व्योम
ssh_conn_info_free(काष्ठा ssh_conn_info *cinfo)
{
	अगर (cinfo == शून्य)
		वापस;
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
	freezero(cinfo, माप(*cinfo));
}

काष्ठा ssh_conn_info *
ssh_conn_info_dup(स्थिर काष्ठा ssh_conn_info *cinfo)
{
	काष्ठा ssh_conn_info *ret;

	अगर (cinfo == शून्य)
		वापस शून्य;
	ret = xcalloc(1, माप(*ret));
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
	वापस ret;
}

/* Expand a proxy command */
अटल अक्षर *
expand_proxy_command(स्थिर अक्षर *proxy_command, स्थिर अक्षर *user,
    स्थिर अक्षर *host, स्थिर अक्षर *host_arg, पूर्णांक port)
{
	अक्षर *tmp, *ret, strport[NI_MAXSERV];
	स्थिर अक्षर *keyalias = options.host_कुंजी_alias ?
	    options.host_कुंजी_alias : host_arg;

	snprintf(strport, माप strport, "%d", port);
	xasprintf(&tmp, "exec %s", proxy_command);
	ret = percent_expand(tmp,
	    "h", host,
	    "k", keyalias,
	    "n", host_arg,
	    "p", strport,
	    "r", options.user,
	    (अक्षर *)शून्य);
	मुक्त(tmp);
	वापस ret;
}

/*
 * Connect to the given ssh server using a proxy command that passes a
 * a connected fd back to us.
 */
अटल पूर्णांक
ssh_proxy_fdpass_connect(काष्ठा ssh *ssh, स्थिर अक्षर *host,
    स्थिर अक्षर *host_arg, u_short port, स्थिर अक्षर *proxy_command)
{
	अक्षर *command_string;
	पूर्णांक sp[2], sock;
	pid_t pid;
	अक्षर *shell;

	अगर ((shell = दो_पर्या("SHELL")) == शून्य)
		shell = _PATH_BSHELL;

	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		fatal("Could not create socketpair to communicate with "
		    "proxy dialer: %.100s", म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy dialer command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	अगर ((pid = विभाजन()) == 0) {
		अक्षर *argv[10];

		बंद(sp[1]);
		/* Redirect stdin and stdout. */
		अगर (sp[0] != 0) {
			अगर (dup2(sp[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
		}
		अगर (sp[0] != 1) {
			अगर (dup2(sp[0], 1) == -1)
				लिखो_त्रुटि("dup2 stdout");
		}
		अगर (sp[0] >= 2)
			बंद(sp[0]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		अगर (!debug_flag && options.control_path != शून्य &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = शून्य;

		/*
		 * Execute the proxy command.
		 * Note that we gave up any extra privileges above.
		 */
		execv(argv[0], argv);
		लिखो_त्रुटि(argv[0]);
		निकास(1);
	}
	/* Parent. */
	अगर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	बंद(sp[0]);
	मुक्त(command_string);

	अगर ((sock = mm_receive_fd(sp[1])) == -1)
		fatal("proxy dialer did not pass back a connection");
	बंद(sp[1]);

	जबतक (waitpid(pid, शून्य, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));

	/* Set the connection file descriptors. */
	अगर (ssh_packet_set_connection(ssh, sock, sock) == शून्य)
		वापस -1; /* ssh_packet_set_connection logs error */

	वापस 0;
}

/*
 * Connect to the given ssh server using a proxy command.
 */
अटल पूर्णांक
ssh_proxy_connect(काष्ठा ssh *ssh, स्थिर अक्षर *host, स्थिर अक्षर *host_arg,
    u_short port, स्थिर अक्षर *proxy_command)
{
	अक्षर *command_string;
	पूर्णांक pin[2], pout[2];
	pid_t pid;
	अक्षर *shell;

	अगर ((shell = दो_पर्या("SHELL")) == शून्य || *shell == '\0')
		shell = _PATH_BSHELL;

	/* Create pipes for communicating with the proxy. */
	अगर (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("Could not create pipes to communicate with the proxy: %.100s",
		    म_त्रुटि(त्रुटि_सं));

	command_string = expand_proxy_command(proxy_command, options.user,
	    host, host_arg, port);
	debug("Executing proxy command: %.500s", command_string);

	/* Fork and execute the proxy command. */
	अगर ((pid = विभाजन()) == 0) {
		अक्षर *argv[10];

		/* Redirect stdin and stdout. */
		बंद(pin[1]);
		अगर (pin[0] != 0) {
			अगर (dup2(pin[0], 0) == -1)
				लिखो_त्रुटि("dup2 stdin");
			बंद(pin[0]);
		}
		बंद(pout[0]);
		अगर (dup2(pout[1], 1) == -1)
			लिखो_त्रुटि("dup2 stdout");
		/* Cannot be 1 because pin allocated two descriptors. */
		बंद(pout[1]);

		/*
		 * Stderr is left for non-ControlPersist connections is so
		 * error messages may be printed on the user's terminal.
		 */
		अगर (!debug_flag && options.control_path != शून्य &&
		    options.control_persist && stdfd_devnull(0, 0, 1) == -1)
			error_f("stdfd_devnull failed");

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = शून्य;

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
	अगर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	अन्यथा
		proxy_command_pid = pid; /* save pid to clean up later */

	/* Close child side of the descriptors. */
	बंद(pin[0]);
	बंद(pout[1]);

	/* Free the command name. */
	मुक्त(command_string);

	/* Set the connection file descriptors. */
	अगर (ssh_packet_set_connection(ssh, pout[0], pin[1]) == शून्य)
		वापस -1; /* ssh_packet_set_connection logs error */

	वापस 0;
}

व्योम
ssh_kill_proxy_command(व्योम)
{
	/*
	 * Send SIGHUP to proxy command if used. We don't wait() in
	 * case it hangs and instead rely on init to reap the child
	 */
	अगर (proxy_command_pid > 1)
		समाप्त(proxy_command_pid, SIGHUP);
}

#अगर_घोषित HAVE_IFADDRS_H
/*
 * Search a interface address list (returned from getifaddrs(3)) for an
 * address that matches the desired address family on the specified interface.
 * Returns 0 and fills in *resultp and *rlenp on success. Returns -1 on failure.
 */
अटल पूर्णांक
check_ifaddrs(स्थिर अक्षर *ifname, पूर्णांक af, स्थिर काष्ठा ifaddrs *ifaddrs,
    काष्ठा sockaddr_storage *resultp, socklen_t *rlenp)
{
	काष्ठा sockaddr_in6 *sa6;
	काष्ठा sockaddr_in *sa;
	काष्ठा in6_addr *v6addr;
	स्थिर काष्ठा ifaddrs *ifa;
	पूर्णांक allow_local;

	/*
	 * Prefer addresses that are not loopback or linklocal, but use them
	 * if nothing else matches.
	 */
	क्रम (allow_local = 0; allow_local < 2; allow_local++) {
		क्रम (ifa = ifaddrs; ifa != शून्य; ifa = ifa->ifa_अग्र) {
			अगर (ifa->ifa_addr == शून्य || ifa->ifa_name == शून्य ||
			    (ifa->ifa_flags & IFF_UP) == 0 ||
			    ifa->ifa_addr->sa_family != af ||
			    म_भेद(ifa->ifa_name, options.bind_interface) != 0)
				जारी;
			चयन (ifa->ifa_addr->sa_family) {
			हाल AF_INET:
				sa = (काष्ठा sockaddr_in *)ifa->ifa_addr;
				अगर (!allow_local && sa->sin_addr.s_addr ==
				    htonl(INADDR_LOOPBACK))
					जारी;
				अगर (*rlenp < माप(काष्ठा sockaddr_in)) {
					error_f("v4 addr doesn't fit");
					वापस -1;
				}
				*rlenp = माप(काष्ठा sockaddr_in);
				स_नकल(resultp, sa, *rlenp);
				वापस 0;
			हाल AF_INET6:
				sa6 = (काष्ठा sockaddr_in6 *)ifa->ifa_addr;
				v6addr = &sa6->sin6_addr;
				अगर (!allow_local &&
				    (IN6_IS_ADDR_LINKLOCAL(v6addr) ||
				    IN6_IS_ADDR_LOOPBACK(v6addr)))
					जारी;
				अगर (*rlenp < माप(काष्ठा sockaddr_in6)) {
					error_f("v6 addr doesn't fit");
					वापस -1;
				}
				*rlenp = माप(काष्ठा sockaddr_in6);
				स_नकल(resultp, sa6, *rlenp);
				वापस 0;
			}
		}
	}
	वापस -1;
}
#पूर्ण_अगर

/*
 * Creates a socket for use as the ssh connection.
 */
अटल पूर्णांक
ssh_create_socket(काष्ठा addrinfo *ai)
{
	पूर्णांक sock, r;
	काष्ठा sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	काष्ठा addrinfo hints, *res = शून्य;
#अगर_घोषित HAVE_IFADDRS_H
	काष्ठा ifaddrs *ifaddrs = शून्य;
#पूर्ण_अगर
	अक्षर ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	अगर (sock == -1) {
		error("socket: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	(व्योम)fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Use interactive QOS (if specified) until authentication completed */
	अगर (options.ip_qos_interactive != पूर्णांक_उच्च)
		set_sock_tos(sock, options.ip_qos_interactive);

	/* Bind the socket to an alternative local IP address */
	अगर (options.bind_address == शून्य && options.bind_interface == शून्य)
		वापस sock;

	अगर (options.bind_address != शून्य) {
		स_रखो(&hints, 0, माप(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		अगर ((r = getaddrinfo(options.bind_address, शून्य,
		    &hints, &res)) != 0) {
			error("getaddrinfo: %s: %s", options.bind_address,
			    ssh_gai_strerror(r));
			जाओ fail;
		}
		अगर (res == शून्य) {
			error("getaddrinfo: no addrs");
			जाओ fail;
		}
		स_नकल(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	} अन्यथा अगर (options.bind_interface != शून्य) {
#अगर_घोषित HAVE_IFADDRS_H
		अगर ((r = getifaddrs(&ifaddrs)) != 0) {
			error("getifaddrs: %s: %s", options.bind_interface,
			    म_त्रुटि(त्रुटि_सं));
			जाओ fail;
		}
		bindaddrlen = माप(bindaddr);
		अगर (check_ifaddrs(options.bind_interface, ai->ai_family,
		    ifaddrs, &bindaddr, &bindaddrlen) != 0) {
			logit("getifaddrs: %s: no suitable addresses",
			    options.bind_interface);
			जाओ fail;
		}
#अन्यथा
		error("BindInterface not supported on this platform.");
#पूर्ण_अगर
	}
	अगर ((r = getnameinfo((काष्ठा sockaddr *)&bindaddr, bindaddrlen,
	    ntop, माप(ntop), शून्य, 0, NI_NUMERICHOST)) != 0) {
		error_f("getnameinfo failed: %s", ssh_gai_strerror(r));
		जाओ fail;
	}
	अगर (bind(sock, (काष्ठा sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("bind %s: %s", ntop, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	debug_f("bound to %s", ntop);
	/* success */
	जाओ out;
fail:
	बंद(sock);
	sock = -1;
 out:
	अगर (res != शून्य)
		freeaddrinfo(res);
#अगर_घोषित HAVE_IFADDRS_H
	अगर (ifaddrs != शून्य)
		freeifaddrs(ifaddrs);
#पूर्ण_अगर
	वापस sock;
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
अटल पूर्णांक
ssh_connect_direct(काष्ठा ssh *ssh, स्थिर अक्षर *host, काष्ठा addrinfo *aitop,
    काष्ठा sockaddr_storage *hostaddr, u_short port, पूर्णांक connection_attempts,
    पूर्णांक *timeout_ms, पूर्णांक want_keepalive)
{
	पूर्णांक saved_timeout_ms = *timeout_ms;
	पूर्णांक oerrno, sock = -1, attempt;
	अक्षर ntop[NI_MAXHOST], strport[NI_MAXSERV];
	काष्ठा addrinfo *ai;

	debug3_f("entering");
	स_रखो(ntop, 0, माप(ntop));
	स_रखो(strport, 0, माप(strport));

	क्रम (attempt = 0; attempt < connection_attempts; attempt++) {
		अगर (attempt > 0) {
			/* Sleep a moment before retrying. */
			sleep(1);
			debug("Trying again...");
		}
		/*
		 * Loop through addresses for this host, and try each one in
		 * sequence until the connection succeeds.
		 */
		क्रम (ai = aitop; ai; ai = ai->ai_next) {
			अगर (ai->ai_family != AF_INET &&
			    ai->ai_family != AF_INET6) {
				त्रुटि_सं = EAFNOSUPPORT;
				जारी;
			}
			अगर (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, माप(ntop), strport, माप(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				oerrno = त्रुटि_सं;
				error_f("getnameinfo failed");
				त्रुटि_सं = oerrno;
				जारी;
			}
			अगर (options.address_family != AF_UNSPEC &&
			    ai->ai_family != options.address_family) {
				debug2_f("skipping address [%s]:%s: "
				    "wrong address family", ntop, strport);
				त्रुटि_सं = EAFNOSUPPORT;
				जारी;
			}

			debug("Connecting to %.200s [%.100s] port %s.",
				host, ntop, strport);

			/* Create a socket for connecting. */
			sock = ssh_create_socket(ai);
			अगर (sock < 0) {
				/* Any error is already output */
				त्रुटि_सं = 0;
				जारी;
			}

			*timeout_ms = saved_timeout_ms;
			अगर (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen,
			    timeout_ms) >= 0) {
				/* Successful connection. */
				स_नकल(hostaddr, ai->ai_addr, ai->ai_addrlen);
				अवरोध;
			} अन्यथा {
				oerrno = त्रुटि_सं;
				debug("connect to address %s port %s: %s",
				    ntop, strport, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				त्रुटि_सं = oerrno;
			}
		}
		अगर (sock != -1)
			अवरोध;	/* Successful connection. */
	}

	/* Return failure if we didn't get a successful connection. */
	अगर (sock == -1) {
		error("ssh: connect to host %s port %s: %s",
		    host, strport, त्रुटि_सं == 0 ? "failure" : म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	अगर (want_keepalive)
		set_keepalive(sock); /* logs errors */

	/* Set the connection. */
	अगर (ssh_packet_set_connection(ssh, sock, sock) == शून्य)
		वापस -1; /* ssh_packet_set_connection logs error */

	वापस 0;
}

पूर्णांक
ssh_connect(काष्ठा ssh *ssh, स्थिर अक्षर *host, स्थिर अक्षर *host_arg,
    काष्ठा addrinfo *addrs, काष्ठा sockaddr_storage *hostaddr, u_short port,
    पूर्णांक connection_attempts, पूर्णांक *timeout_ms, पूर्णांक want_keepalive)
{
	पूर्णांक in, out;

	अगर (options.proxy_command == शून्य) {
		वापस ssh_connect_direct(ssh, host, addrs, hostaddr, port,
		    connection_attempts, timeout_ms, want_keepalive);
	} अन्यथा अगर (म_भेद(options.proxy_command, "-") == 0) {
		अगर ((in = dup(STDIN_FILENO)) == -1 ||
		    (out = dup(STDOUT_FILENO)) == -1) {
			अगर (in >= 0)
				बंद(in);
			error_f("dup() in/out failed");
			वापस -1; /* ssh_packet_set_connection logs error */
		}
		अगर ((ssh_packet_set_connection(ssh, in, out)) == शून्य)
			वापस -1; /* ssh_packet_set_connection logs error */
		वापस 0;
	} अन्यथा अगर (options.proxy_use_fdpass) {
		वापस ssh_proxy_fdpass_connect(ssh, host, host_arg, port,
		    options.proxy_command);
	}
	वापस ssh_proxy_connect(ssh, host, host_arg, port,
	    options.proxy_command);
}

/* defaults to 'no' */
अटल पूर्णांक
confirm(स्थिर अक्षर *prompt, स्थिर अक्षर *fingerprint)
{
	स्थिर अक्षर *संदेश, *again = "Please type 'yes' or 'no': ";
	स्थिर अक्षर *again_fp = "Please type 'yes', 'no' or the fingerprint: ";
	अक्षर *p, *cp;
	पूर्णांक ret = -1;

	अगर (options.batch_mode)
		वापस 0;
	क्रम (संदेश = prompt;;संदेश = fingerprint ? again_fp : again) {
		cp = p = read_passphrase(संदेश, RP_ECHO);
		अगर (p == शून्य)
			वापस 0;
		p += म_अखोज(p, " \t"); /* skip leading whitespace */
		p[म_खोज(p, " \t\n")] = '\0'; /* remove trailing whitespace */
		अगर (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		अन्यथा अगर (strcasecmp(p, "yes") == 0 || (fingerprint != शून्य &&
		    म_भेद(p, fingerprint) == 0))
			ret = 1;
		मुक्त(cp);
		अगर (ret != -1)
			वापस ret;
	}
}

अटल पूर्णांक
sockaddr_is_local(काष्ठा sockaddr *hostaddr)
{
	चयन (hostaddr->sa_family) {
	हाल AF_INET:
		वापस (ntohl(((काष्ठा sockaddr_in *)hostaddr)->
		    sin_addr.s_addr) >> 24) == IN_LOOPBACKNET;
	हाल AF_INET6:
		वापस IN6_IS_ADDR_LOOPBACK(
		    &(((काष्ठा sockaddr_in6 *)hostaddr)->sin6_addr));
	शेष:
		वापस 0;
	}
}

/*
 * Prepare the hostname and ip address strings that are used to lookup
 * host keys in known_hosts files. These may have a port number appended.
 */
व्योम
get_hostfile_hostname_ipaddr(अक्षर *hostname, काष्ठा sockaddr *hostaddr,
    u_short port, अक्षर **hostfile_hostname, अक्षर **hostfile_ipaddr)
{
	अक्षर ntop[NI_MAXHOST];
	socklen_t addrlen;

	चयन (hostaddr == शून्य ? -1 : hostaddr->sa_family) {
	हाल -1:
		addrlen = 0;
		अवरोध;
	हाल AF_INET:
		addrlen = माप(काष्ठा sockaddr_in);
		अवरोध;
	हाल AF_INET6:
		addrlen = माप(काष्ठा sockaddr_in6);
		अवरोध;
	शेष:
		addrlen = माप(काष्ठा sockaddr);
		अवरोध;
	}

	/*
	 * We don't have the remote ip-address for connections
	 * using a proxy command
	 */
	अगर (hostfile_ipaddr != शून्य) {
		अगर (options.proxy_command == शून्य) {
			अगर (getnameinfo(hostaddr, addrlen,
			    ntop, माप(ntop), शून्य, 0, NI_NUMERICHOST) != 0)
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
	अगर (hostfile_hostname != शून्य) {
		अगर (options.host_कुंजी_alias != शून्य) {
			*hostfile_hostname = xstrdup(options.host_कुंजी_alias);
			debug("using hostkeyalias: %s", *hostfile_hostname);
		} अन्यथा {
			*hostfile_hostname = put_host_port(hostname, port);
		}
	}
}

/* returns non-zero if path appears in hostfiles, or 0 if not. */
अटल पूर्णांक
path_in_hostfiles(स्थिर अक्षर *path, अक्षर **hostfiles, u_int अंक_hostfiles)
{
	u_int i;

	क्रम (i = 0; i < अंक_hostfiles; i++) {
		अगर (म_भेद(path, hostfiles[i]) == 0)
			वापस 1;
	}
	वापस 0;
}

काष्ठा find_by_कुंजी_ctx {
	स्थिर अक्षर *host, *ip;
	स्थिर काष्ठा sshkey *कुंजी;
	अक्षर **names;
	u_int nnames;
};

/* Try to replace home directory prefix (per $HOME) with a ~/ sequence */
अटल अक्षर *
try_tilde_unexpand(स्थिर अक्षर *path)
{
	अक्षर *home, *ret = शून्य;
	माप_प्रकार l;

	अगर (*path != '/')
		वापस xstrdup(path);
	अगर ((home = दो_पर्या("HOME")) == शून्य || (l = म_माप(home)) == 0)
		वापस xstrdup(path);
	अगर (म_भेदन(path, home, l) != 0)
		वापस xstrdup(path);
	/*
	 * ensure we have matched on a path boundary: either the $HOME that
	 * we just compared ends with a '/' or the next character of the path
	 * must be a '/'.
	 */
	अगर (home[l - 1] != '/' && path[l] != '/')
		वापस xstrdup(path);
	अगर (path[l] == '/')
		l++;
	xasprintf(&ret, "~/%s", path + l);
	वापस ret;
}

/*
 * Returns non-zero if the key is accepted by HostkeyAlgorithms.
 * Made slightly less trivial by the multiple RSA signature algorithm names.
 */
पूर्णांक
hostkey_accepted_by_hostkeyalgs(स्थिर काष्ठा sshkey *कुंजी)
{
	स्थिर अक्षर *ktype = sshkey_ssh_name(कुंजी);
	स्थिर अक्षर *hostkeyalgs = options.hostkeyalgorithms;

	अगर (कुंजी->type == कुंजी_UNSPEC)
		वापस 0;
	अगर (कुंजी->type == कुंजी_RSA &&
	    (match_pattern_list("rsa-sha2-256", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-512", hostkeyalgs, 0) == 1))
		वापस 1;
	अगर (कुंजी->type == कुंजी_RSA_CERT &&
	    (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com", hostkeyalgs, 0) == 1 ||
	    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com", hostkeyalgs, 0) == 1))
		वापस 1;
	वापस match_pattern_list(ktype, hostkeyalgs, 0) == 1;
}

अटल पूर्णांक
hostkeys_find_by_कुंजी_cb(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा find_by_कुंजी_ctx *ctx = (काष्ठा find_by_कुंजी_ctx *)_ctx;
	अक्षर *path;

	/* we are looking for keys with names that *do not* match */
	अगर ((l->match & HKF_MATCH_HOST) != 0)
		वापस 0;
	/* not interested in marker lines */
	अगर (l->marker != MRK_NONE)
		वापस 0;
	/* we are only interested in exact key matches */
	अगर (l->कुंजी == शून्य || !sshkey_equal(ctx->कुंजी, l->कुंजी))
		वापस 0;
	path = try_tilde_unexpand(l->path);
	debug_f("found matching key in %s:%lu", path, l->linenum);
	ctx->names = xrecallocarray(ctx->names,
	    ctx->nnames, ctx->nnames + 1, माप(*ctx->names));
	xasprintf(&ctx->names[ctx->nnames], "%s:%lu: %s", path, l->linenum,
	    म_भेदन(l->hosts, HASH_MAGIC, म_माप(HASH_MAGIC)) == 0 ?
	    "[hashed name]" : l->hosts);
	ctx->nnames++;
	मुक्त(path);
	वापस 0;
}

अटल पूर्णांक
hostkeys_find_by_कुंजी_hostfile(स्थिर अक्षर *file, स्थिर अक्षर *which,
    काष्ठा find_by_कुंजी_ctx *ctx)
{
	पूर्णांक r;

	debug3_f("trying %s hostfile \"%s\"", which, file);
	अगर ((r = hostkeys_foreach(file, hostkeys_find_by_कुंजी_cb, ctx,
	    ctx->host, ctx->ip, HKF_WANT_PARSE_कुंजी, 0)) != 0) {
		अगर (r == SSH_ERR_SYSTEM_ERROR && त्रुटि_सं == ENOENT) {
			debug_f("hostkeys file %s does not exist", file);
			वापस 0;
		}
		error_fr(r, "hostkeys_foreach failed for %s", file);
		वापस r;
	}
	वापस 0;
}

/*
 * Find 'key' in known hosts file(s) that do not match host/ip.
 * Used to display also-known-as information for previously-unseen hostkeys.
 */
अटल व्योम
hostkeys_find_by_कुंजी(स्थिर अक्षर *host, स्थिर अक्षर *ip, स्थिर काष्ठा sshkey *कुंजी,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles,
    अक्षर ***names, u_int *nnames)
{
	काष्ठा find_by_कुंजी_ctx ctx = {शून्य, शून्य, शून्य, शून्य, 0};
	u_int i;

	*names = शून्य;
	*nnames = 0;

	अगर (कुंजी == शून्य || sshkey_is_cert(कुंजी))
		वापस;

	ctx.host = host;
	ctx.ip = ip;
	ctx.कुंजी = कुंजी;

	क्रम (i = 0; i < अंक_user_hostfiles; i++) {
		अगर (hostkeys_find_by_कुंजी_hostfile(user_hostfiles[i],
		    "user", &ctx) != 0)
			जाओ fail;
	}
	क्रम (i = 0; i < अंक_system_hostfiles; i++) {
		अगर (hostkeys_find_by_कुंजी_hostfile(system_hostfiles[i],
		    "system", &ctx) != 0)
			जाओ fail;
	}
	/* success */
	*names = ctx.names;
	*nnames = ctx.nnames;
	ctx.names = शून्य;
	ctx.nnames = 0;
	वापस;
 fail:
	क्रम (i = 0; i < ctx.nnames; i++)
		मुक्त(ctx.names[i]);
	मुक्त(ctx.names);
}

#घोषणा MAX_OTHER_NAMES	8 /* Maximum number of names to list */
अटल अक्षर *
other_hostkeys_message(स्थिर अक्षर *host, स्थिर अक्षर *ip,
    स्थिर काष्ठा sshkey *कुंजी,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles)
{
	अक्षर *ret = शून्य, **othernames = शून्य;
	u_int i, n, अंक_othernames = 0;

	hostkeys_find_by_कुंजी(host, ip, कुंजी,
	    user_hostfiles, अंक_user_hostfiles,
	    system_hostfiles, अंक_system_hostfiles,
	    &othernames, &अंक_othernames);
	अगर (अंक_othernames == 0)
		वापस xstrdup("This key is not known by any other names.");

	xasprintf(&ret, "This host key is known by the following other "
	    "names/addresses:");

	n = अंक_othernames;
	अगर (n > MAX_OTHER_NAMES)
		n = MAX_OTHER_NAMES;
	क्रम (i = 0; i < n; i++) {
		xextendf(&ret, "\n", "    %s", othernames[i]);
	}
	अगर (n < अंक_othernames) {
		xextendf(&ret, "\n", "    (%d additional names omitted)",
		    अंक_othernames - n);
	}
	क्रम (i = 0; i < अंक_othernames; i++)
		मुक्त(othernames[i]);
	मुक्त(othernames);
	वापस ret;
}

व्योम
load_hostkeys_command(काष्ठा hostkeys *hostkeys, स्थिर अक्षर *command_template,
    स्थिर अक्षर *invocation, स्थिर काष्ठा ssh_conn_info *cinfo,
    स्थिर काष्ठा sshkey *host_कुंजी, स्थिर अक्षर *hostfile_hostname)
{
	पूर्णांक r, i, ac = 0;
	अक्षर *कुंजी_fp = शून्य, *keytext = शून्य, *tmp;
	अक्षर *command = शून्य, *tag = शून्य, **av = शून्य;
	खाता *f = शून्य;
	pid_t pid;
	व्योम (*osigchld)(पूर्णांक);

	xasprintf(&tag, "KnownHostsCommand-%s", invocation);

	अगर (host_कुंजी != शून्य) {
		अगर ((कुंजी_fp = sshkey_fingerprint(host_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint failed");
		अगर ((r = sshkey_to_base64(host_कुंजी, &keytext)) != 0)
			fatal_fr(r, "sshkey_to_base64 failed");
	}
	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);

	/* Turn the command into an argument vector */
	अगर (argv_split(command_template, &ac, &av, 0) != 0) {
		error("%s \"%s\" contains invalid quotes", tag,
		    command_template);
		जाओ out;
	}
	अगर (ac == 0) {
		error("%s \"%s\" yielded no arguments", tag,
		    command_template);
		जाओ out;
	}
	क्रम (i = 1; i < ac; i++) {
		tmp = percent_dollar_expand(av[i],
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "H", hostfile_hostname,
		    "I", invocation,
		    "t", host_कुंजी == शून्य ? "NONE" : sshkey_ssh_name(host_कुंजी),
		    "f", कुंजी_fp == शून्य ? "NONE" : कुंजी_fp,
		    "K", keytext == शून्य ? "NONE" : keytext,
		    (अक्षर *)शून्य);
		अगर (tmp == शून्य)
			fatal_f("percent_expand failed");
		मुक्त(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	अगर ((pid = subprocess(tag, command, ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_UNSAFE_PATH|
	    SSH_SUBPROCESS_PRESERVE_ENV, शून्य, शून्य, शून्य)) == 0)
		जाओ out;

	load_hostkeys_file(hostkeys, hostfile_hostname, tag, f, 1);

	अगर (exited_cleanly(pid, tag, command, 0) != 0)
		fatal("KnownHostsCommand failed");

 out:
	अगर (f != शून्य)
		ख_बंद(f);
	ssh_signal(SIGCHLD, osigchld);
	क्रम (i = 0; i < ac; i++)
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
#घोषणा RDRW	0
#घोषणा RDONLY	1
#घोषणा ROQUIET	2
अटल पूर्णांक
check_host_कुंजी(अक्षर *hostname, स्थिर काष्ठा ssh_conn_info *cinfo,
    काष्ठा sockaddr *hostaddr, u_short port,
    काष्ठा sshkey *host_कुंजी, पूर्णांक readonly, पूर्णांक clobber_port,
    अक्षर **user_hostfiles, u_int अंक_user_hostfiles,
    अक्षर **system_hostfiles, u_int अंक_system_hostfiles,
    स्थिर अक्षर *hostfile_command)
{
	HostStatus host_status = -1, ip_status = -1;
	काष्ठा sshkey *raw_कुंजी = शून्य;
	अक्षर *ip = शून्य, *host = शून्य;
	अक्षर hostline[1000], *hostp, *fp, *ra;
	अक्षर संदेश[1024];
	स्थिर अक्षर *type, *fail_reason = शून्य;
	स्थिर काष्ठा hostkey_entry *host_found = शून्य, *ip_found = शून्य;
	पूर्णांक len, cancelled_forwarding = 0, confirmed;
	पूर्णांक local = sockaddr_is_local(hostaddr);
	पूर्णांक r, want_cert = sshkey_is_cert(host_कुंजी), host_ip_differ = 0;
	पूर्णांक hostkey_trusted = 0; /* Known or explicitly accepted by user */
	काष्ठा hostkeys *host_hostkeys, *ip_hostkeys;
	u_int i;

	/*
	 * Force accepting of the host key for loopback/localhost. The
	 * problem is that if the home directory is NFS-mounted to multiple
	 * machines, localhost will refer to a different machine in each of
	 * them, and the user will get bogus HOST_CHANGED warnings.  This
	 * essentially disables host authentication for localhost; however,
	 * this is probably not a real problem.
	 */
	अगर (options.no_host_authentication_for_localhost == 1 && local &&
	    options.host_कुंजी_alias == शून्य) {
		debug("Forcing accepting of host key for "
		    "loopback/localhost.");
		options.update_hostkeys = 0;
		वापस 0;
	}

	/*
	 * Don't ever try to write an invalid name to a known hosts file.
	 * Note: do this before get_hostfile_hostname_ipaddr() to catch
	 * '[' or ']' in the name before they are added.
	 */
	अगर (म_खोज(hostname, "@?*#[]|'\'\"\\") != म_माप(hostname)) {
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
	अगर (options.check_host_ip && (local ||
	    म_भेद(hostname, ip) == 0 || options.proxy_command != शून्य))
		options.check_host_ip = 0;

	host_hostkeys = init_hostkeys();
	क्रम (i = 0; i < अंक_user_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, user_hostfiles[i], 0);
	क्रम (i = 0; i < अंक_system_hostfiles; i++)
		load_hostkeys(host_hostkeys, host, system_hostfiles[i], 0);
	अगर (hostfile_command != शून्य && !clobber_port) {
		load_hostkeys_command(host_hostkeys, hostfile_command,
		    "HOSTNAME", cinfo, host_कुंजी, host);
	}

	ip_hostkeys = शून्य;
	अगर (!want_cert && options.check_host_ip) {
		ip_hostkeys = init_hostkeys();
		क्रम (i = 0; i < अंक_user_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, user_hostfiles[i], 0);
		क्रम (i = 0; i < अंक_system_hostfiles; i++)
			load_hostkeys(ip_hostkeys, ip, system_hostfiles[i], 0);
		अगर (hostfile_command != शून्य && !clobber_port) {
			load_hostkeys_command(ip_hostkeys, hostfile_command,
			    "ADDRESS", cinfo, host_कुंजी, ip);
		}
	}

 retry:
	अगर (!hostkey_accepted_by_hostkeyalgs(host_कुंजी)) {
		error("host key %s not permitted by HostkeyAlgorithms",
		    sshkey_ssh_name(host_कुंजी));
		जाओ fail;
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
	अगर (!readonly && (अंक_user_hostfiles == 0 ||
	    (host_found != शून्य && host_found->note != 0)))
		readonly = RDONLY;

	/*
	 * Also perform check for the ip address, skip the check if we are
	 * localhost, looking for a certificate, or the hostname was an ip
	 * address to begin with.
	 */
	अगर (!want_cert && ip_hostkeys != शून्य) {
		ip_status = check_कुंजी_in_hostkeys(ip_hostkeys, host_कुंजी,
		    &ip_found);
		अगर (host_status == HOST_CHANGED &&
		    (ip_status != HOST_CHANGED ||
		    (ip_found != शून्य &&
		    !sshkey_equal(ip_found->कुंजी, host_found->कुंजी))))
			host_ip_differ = 1;
	} अन्यथा
		ip_status = host_status;

	चयन (host_status) {
	हाल HOST_OK:
		/* The host is known and the key matches. */
		debug("Host '%.200s' is known and matches the %s host %s.",
		    host, type, want_cert ? "certificate" : "key");
		debug("Found %s in %s:%lu", want_cert ? "CA key" : "key",
		    host_found->file, host_found->पंक्ति);
		अगर (want_cert) {
			अगर (sshkey_cert_check_host(host_कुंजी,
			    options.host_कुंजी_alias == शून्य ?
			    hostname : options.host_कुंजी_alias,
			    options.ca_sign_algorithms, &fail_reason) != 0) {
				error("%s", fail_reason);
				जाओ fail;
			}
			/*
			 * Do not attempt hostkey update if a certificate was
			 * successfully matched.
			 */
			अगर (options.update_hostkeys != 0) {
				options.update_hostkeys = 0;
				debug3_f("certificate host key in use; "
				    "disabling UpdateHostkeys");
			}
		}
		/* Turn off UpdateHostkeys if key was in system known_hosts */
		अगर (options.update_hostkeys != 0 &&
		    (path_in_hostfiles(host_found->file,
		    system_hostfiles, अंक_system_hostfiles) ||
		    (ip_status == HOST_OK && ip_found != शून्य &&
		    path_in_hostfiles(ip_found->file,
		    system_hostfiles, अंक_system_hostfiles)))) {
			options.update_hostkeys = 0;
			debug3_f("host key found in GlobalKnownHostsFile; "
			    "disabling UpdateHostkeys");
		}
		अगर (options.update_hostkeys != 0 && host_found->note) {
			options.update_hostkeys = 0;
			debug3_f("host key found via KnownHostsCommand; "
			    "disabling UpdateHostkeys");
		}
		अगर (options.check_host_ip && ip_status == HOST_NEW) {
			अगर (readonly || want_cert)
				logit("%s host key for IP address "
				    "'%.128s' not in list of known hosts.",
				    type, ip);
			अन्यथा अगर (!add_host_to_hostfile(user_hostfiles[0], ip,
			    host_कुंजी, options.hash_known_hosts))
				logit("Failed to add the %s host key for IP "
				    "address '%.128s' to the list of known "
				    "hosts (%.500s).", type, ip,
				    user_hostfiles[0]);
			अन्यथा
				logit("Warning: Permanently added the %s host "
				    "key for IP address '%.128s' to the list "
				    "of known hosts.", type, ip);
		} अन्यथा अगर (options.visual_host_कुंजी) {
			fp = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			अगर (fp == शून्य || ra == शून्य)
				fatal_f("sshkey_fingerprint failed");
			logit("Host key fingerprint is: %s\n%s", fp, ra);
			मुक्त(ra);
			मुक्त(fp);
		}
		hostkey_trusted = 1;
		अवरोध;
	हाल HOST_NEW:
		अगर (options.host_कुंजी_alias == शून्य && port != 0 &&
		    port != SSH_DEFAULT_PORT && !clobber_port) {
			debug("checking without port identifier");
			अगर (check_host_कुंजी(hostname, cinfo, hostaddr, 0,
			    host_कुंजी, ROQUIET, 1,
			    user_hostfiles, अंक_user_hostfiles,
			    system_hostfiles, अंक_system_hostfiles,
			    hostfile_command) == 0) {
				debug("found matching key w/out port");
				अवरोध;
			}
		}
		अगर (readonly || want_cert)
			जाओ fail;
		/* The host is new. */
		अगर (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_YES) {
			/*
			 * User has requested strict host key checking.  We
			 * will not add the host key automatically.  The only
			 * alternative left is to abort.
			 */
			error("No %s host key is known for %.200s and you "
			    "have requested strict checking.", type, host);
			जाओ fail;
		} अन्यथा अगर (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			अक्षर *msg1 = शून्य, *msg2 = शून्य;

			xasprintf(&msg1, "The authenticity of host "
			    "'%.200s (%s)' can't be established", host, ip);

			अगर (show_other_कुंजियाँ(host_hostkeys, host_कुंजी)) {
				xextendf(&msg1, "\n", "but keys of different "
				    "type are already known for this host.");
			} अन्यथा
				xextendf(&msg1, "", ".");

			fp = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			ra = sshkey_fingerprint(host_कुंजी,
			    options.fingerprint_hash, SSH_FP_RANDOMART);
			अगर (fp == शून्य || ra == शून्य)
				fatal_f("sshkey_fingerprint failed");
			xextendf(&msg1, "\n", "%s key fingerprint is: %s",
			    type, fp);
			अगर (options.visual_host_कुंजी)
				xextendf(&msg1, "\n", "%s", ra);
			अगर (options.verify_host_कुंजी_dns) {
				xextendf(&msg1, "\n",
				    "%s host key fingerprint found in DNS.",
				    matching_host_कुंजी_dns ?
				    "Matching" : "No matching");
			}
			/* msg2 informs for other names matching this key */
			अगर ((msg2 = other_hostkeys_message(host, ip, host_कुंजी,
			    user_hostfiles, अंक_user_hostfiles,
			    system_hostfiles, अंक_system_hostfiles)) != शून्य)
				xextendf(&msg1, "\n", "%s", msg2);

			xextendf(&msg1, "\n",
			    "Are you sure you want to continue connecting "
			    "(yes/no/[fingerprint])? ");

			confirmed = confirm(msg1, fp);
			मुक्त(ra);
			मुक्त(fp);
			मुक्त(msg1);
			मुक्त(msg2);
			अगर (!confirmed)
				जाओ fail;
			hostkey_trusted = 1; /* user explicitly confirmed */
		}
		/*
		 * If in "new" or "off" strict mode, add the key automatically
		 * to the local known_hosts file.
		 */
		अगर (options.check_host_ip && ip_status == HOST_NEW) {
			snprintf(hostline, माप(hostline), "%s,%s", host, ip);
			hostp = hostline;
			अगर (options.hash_known_hosts) {
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

		अगर (!r)
			logit("Failed to add the host to the list of known "
			    "hosts (%.500s).", user_hostfiles[0]);
		अन्यथा
			logit("Warning: Permanently added '%.200s' (%s) to the "
			    "list of known hosts.", hostp, type);
		अवरोध;
	हाल HOST_REVOKED:
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
		अगर (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("%s host key for %.200s was revoked and you have "
			    "requested strict checking.", type, host);
			जाओ fail;
		}
		जाओ continue_unsafe;

	हाल HOST_CHANGED:
		अगर (want_cert) {
			/*
			 * This is only a debug() since it is valid to have
			 * CAs with wildcard DNS matches that don't match
			 * all hosts that one might visit.
			 */
			debug("Host certificate authority does not "
			    "match %s in %s:%lu", CA_MARKER,
			    host_found->file, host_found->पंक्ति);
			जाओ fail;
		}
		अगर (readonly == ROQUIET)
			जाओ fail;
		अगर (options.check_host_ip && host_ip_differ) {
			अक्षर *कुंजी_संदेश;
			अगर (ip_status == HOST_NEW)
				कुंजी_संदेश = "is unknown";
			अन्यथा अगर (ip_status == HOST_OK)
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
			अगर (ip_status != HOST_NEW)
				error("Offending key for IP in %s:%lu",
				    ip_found->file, ip_found->पंक्ति);
		}
		/* The host key has changed. */
		warn_changed_कुंजी(host_कुंजी);
		अगर (अंक_user_hostfiles > 0 || अंक_system_hostfiles > 0) {
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
		अगर (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			error("Host key for %.200s has changed and you have "
			    "requested strict checking.", host);
			जाओ fail;
		}

 continue_unsafe:
		/*
		 * If strict host key checking has not been requested, allow
		 * the connection but without MITM-able authentication or
		 * forwarding.
		 */
		अगर (options.password_authentication) {
			error("Password authentication is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.password_authentication = 0;
			cancelled_forwarding = 1;
		}
		अगर (options.kbd_interactive_authentication) {
			error("Keyboard-interactive authentication is disabled"
			    " to avoid man-in-the-middle attacks.");
			options.kbd_interactive_authentication = 0;
			cancelled_forwarding = 1;
		}
		अगर (options.forward_agent) {
			error("Agent forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_agent = 0;
			cancelled_forwarding = 1;
		}
		अगर (options.forward_x11) {
			error("X11 forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.forward_x11 = 0;
			cancelled_forwarding = 1;
		}
		अगर (options.अंक_local_forwards > 0 ||
		    options.अंक_remote_forwards > 0) {
			error("Port forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.अंक_local_forwards =
			    options.अंक_remote_forwards = 0;
			cancelled_forwarding = 1;
		}
		अगर (options.tun_open != SSH_TUNMODE_NO) {
			error("Tunnel forwarding is disabled to avoid "
			    "man-in-the-middle attacks.");
			options.tun_open = SSH_TUNMODE_NO;
			cancelled_forwarding = 1;
		}
		अगर (options.update_hostkeys != 0) {
			error("UpdateHostkeys is disabled because the host "
			    "key is not trusted.");
			options.update_hostkeys = 0;
		}
		अगर (options.exit_on_forward_failure && cancelled_forwarding)
			fatal("Error: forwarding disabled due to host key "
			    "check failure");

		/*
		 * XXX Should permit the user to change to use the new id.
		 * This could be done by converting the host key to an
		 * identifying sentence, tell that the host identifies itself
		 * by that sentence, and ask the user if they wish to
		 * accept the authentication.
		 */
		अवरोध;
	हाल HOST_FOUND:
		fatal("internal error");
		अवरोध;
	}

	अगर (options.check_host_ip && host_status != HOST_CHANGED &&
	    ip_status == HOST_CHANGED) {
		snprintf(संदेश, माप(संदेश),
		    "Warning: the %s host key for '%.200s' "
		    "differs from the key for the IP address '%.128s'"
		    "\nOffending key for IP in %s:%lu",
		    type, host, ip, ip_found->file, ip_found->पंक्ति);
		अगर (host_status == HOST_OK) {
			len = म_माप(संदेश);
			snprintf(संदेश + len, माप(संदेश) - len,
			    "\nMatching host key in %s:%lu",
			    host_found->file, host_found->पंक्ति);
		}
		अगर (options.strict_host_कुंजी_checking ==
		    SSH_STRICT_HOSTKEY_ASK) {
			strlcat(संदेश, "\nAre you sure you want "
			    "to continue connecting (yes/no)? ", माप(संदेश));
			अगर (!confirm(संदेश, शून्य))
				जाओ fail;
		} अन्यथा अगर (options.strict_host_कुंजी_checking !=
		    SSH_STRICT_HOSTKEY_OFF) {
			logit("%s", संदेश);
			error("Exiting, you have requested strict checking.");
			जाओ fail;
		} अन्यथा {
			logit("%s", संदेश);
		}
	}

	अगर (!hostkey_trusted && options.update_hostkeys) {
		debug_f("hostkey not known or explicitly trusted: "
		    "disabling UpdateHostkeys");
		options.update_hostkeys = 0;
	}

	sshkey_free(raw_कुंजी);
	मुक्त(ip);
	मुक्त(host);
	अगर (host_hostkeys != शून्य)
		free_hostkeys(host_hostkeys);
	अगर (ip_hostkeys != शून्य)
		free_hostkeys(ip_hostkeys);
	वापस 0;

fail:
	अगर (want_cert && host_status != HOST_REVOKED) {
		/*
		 * No matching certificate. Downgrade cert to raw key and
		 * search normally.
		 */
		debug("No matching CA found. Retry with plain key");
		अगर ((r = sshkey_from_private(host_कुंजी, &raw_कुंजी)) != 0)
			fatal_fr(r, "decode key");
		अगर ((r = sshkey_drop_cert(raw_कुंजी)) != 0)
			fatal_r(r, "Couldn't drop certificate");
		host_कुंजी = raw_कुंजी;
		जाओ retry;
	}
	sshkey_free(raw_कुंजी);
	मुक्त(ip);
	मुक्त(host);
	अगर (host_hostkeys != शून्य)
		free_hostkeys(host_hostkeys);
	अगर (ip_hostkeys != शून्य)
		free_hostkeys(ip_hostkeys);
	वापस -1;
}

/* returns 0 if key verifies or -1 if key does NOT verify */
पूर्णांक
verify_host_कुंजी(अक्षर *host, काष्ठा sockaddr *hostaddr, काष्ठा sshkey *host_कुंजी,
    स्थिर काष्ठा ssh_conn_info *cinfo)
{
	u_int i;
	पूर्णांक r = -1, flags = 0;
	अक्षर valid[64], *fp = शून्य, *cafp = शून्य;
	काष्ठा sshkey *plain = शून्य;

	अगर ((fp = sshkey_fingerprint(host_कुंजी,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य) {
		error_fr(r, "fingerprint host key");
		r = -1;
		जाओ out;
	}

	अगर (sshkey_is_cert(host_कुंजी)) {
		अगर ((cafp = sshkey_fingerprint(host_कुंजी->cert->signature_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य) {
			error_fr(r, "fingerprint CA key");
			r = -1;
			जाओ out;
		}
		sshkey_format_cert_validity(host_कुंजी->cert,
		    valid, माप(valid));
		debug("Server host certificate: %s %s, serial %llu "
		    "ID \"%s\" CA %s %s valid %s",
		    sshkey_ssh_name(host_कुंजी), fp,
		    (अचिन्हित दीर्घ दीर्घ)host_कुंजी->cert->serial,
		    host_कुंजी->cert->कुंजी_id,
		    sshkey_ssh_name(host_कुंजी->cert->signature_कुंजी), cafp,
		    valid);
		क्रम (i = 0; i < host_कुंजी->cert->nprincipals; i++) {
			debug2("Server host certificate hostname: %s",
			    host_कुंजी->cert->principals[i]);
		}
	} अन्यथा {
		debug("Server host key: %s %s", sshkey_ssh_name(host_कुंजी), fp);
	}

	अगर (sshkey_equal(previous_host_कुंजी, host_कुंजी)) {
		debug2_f("server host key %s %s matches cached key",
		    sshkey_type(host_कुंजी), fp);
		r = 0;
		जाओ out;
	}

	/* Check in RevokedHostKeys files if specified */
	क्रम (i = 0; i < options.अंक_revoked_host_कुंजियाँ; i++) {
		r = sshkey_check_revoked(host_कुंजी,
		    options.revoked_host_कुंजियाँ[i]);
		चयन (r) {
		हाल 0:
			अवरोध; /* not revoked */
		हाल SSH_ERR_कुंजी_REVOKED:
			error("Host key %s %s revoked by file %s",
			    sshkey_type(host_कुंजी), fp,
			    options.revoked_host_कुंजियाँ[i]);
			r = -1;
			जाओ out;
		शेष:
			error_r(r, "Error checking host key %s %s in "
			    "revoked keys file %s", sshkey_type(host_कुंजी),
			    fp, options.revoked_host_कुंजियाँ[i]);
			r = -1;
			जाओ out;
		}
	}

	अगर (options.verify_host_कुंजी_dns) {
		/*
		 * XXX certs are not yet supported for DNS, so downgrade
		 * them and try the plain key.
		 */
		अगर ((r = sshkey_from_private(host_कुंजी, &plain)) != 0)
			जाओ out;
		अगर (sshkey_is_cert(plain))
			sshkey_drop_cert(plain);
		अगर (verify_host_कुंजी_dns(host, hostaddr, plain, &flags) == 0) {
			अगर (flags & DNS_VERIFY_FOUND) {
				अगर (options.verify_host_कुंजी_dns == 1 &&
				    flags & DNS_VERIFY_MATCH &&
				    flags & DNS_VERIFY_SECURE) {
					r = 0;
					जाओ out;
				}
				अगर (flags & DNS_VERIFY_MATCH) {
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
	अगर (r == 0 && host_कुंजी != शून्य) {
		sshkey_free(previous_host_कुंजी);
		r = sshkey_from_private(host_कुंजी, &previous_host_कुंजी);
	}

	वापस r;
}

अटल व्योम
warn_nonpq_kex(व्योम)
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
व्योम
ssh_login(काष्ठा ssh *ssh, Sensitive *sensitive, स्थिर अक्षर *orighost,
    काष्ठा sockaddr_storage *hostaddr, u_short port, काष्ठा passwd *pw,
    पूर्णांक timeout_ms, स्थिर काष्ठा ssh_conn_info *cinfo)
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
	अगर ((r = kex_exchange_identification(ssh, timeout_ms,
	    options.version_addendum)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	अगर ((ssh->compat & SSH_BUG_NOREKEY)) {
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
	अगर (!options.kex_algorithms_set && ssh->kex != शून्य &&
	    ssh->kex->name != शून्य && options.warn_weak_crypto &&
	    !kex_is_pq_from_name(ssh->kex->name)) {
		warn_nonpq_kex();
		ssh->kex->non_pq_kex_warned = 1;
	}
	ssh_userauth2(ssh, local_user, server_user, host, sensitive);
	मुक्त(local_user);
	मुक्त(host);
}

/* print all known host keys for a given host, but skip keys of given type */
अटल पूर्णांक
show_other_कुंजियाँ(काष्ठा hostkeys *hostkeys, काष्ठा sshkey *कुंजी)
{
	पूर्णांक type[] = {
		कुंजी_RSA,
		कुंजी_ECDSA,
		कुंजी_ED25519,
		कुंजी_MLDSA44_ED25519,
		-1
	};
	पूर्णांक i, ret = 0;
	अक्षर *fp, *ra;
	स्थिर काष्ठा hostkey_entry *found;

	क्रम (i = 0; type[i] != -1; i++) {
		अगर (type[i] == कुंजी->type)
			जारी;
		अगर (!lookup_कुंजी_in_hostkeys_by_type(hostkeys, type[i],
		    -1, &found))
			जारी;
		fp = sshkey_fingerprint(found->कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(found->कुंजी,
		    options.fingerprint_hash, SSH_FP_RANDOMART);
		अगर (fp == शून्य || ra == शून्य)
			fatal_f("sshkey_fingerprint fail");
		logit("WARNING: %s key found for host %s\n"
		    "in %s:%lu\n"
		    "%s key fingerprint %s.",
		    sshkey_type(found->कुंजी),
		    found->host, found->file, found->पंक्ति,
		    sshkey_type(found->कुंजी), fp);
		अगर (options.visual_host_कुंजी)
			logit("%s", ra);
		मुक्त(ra);
		मुक्त(fp);
		ret = 1;
	}
	वापस ret;
}

अटल व्योम
warn_changed_कुंजी(काष्ठा sshkey *host_कुंजी)
{
	अक्षर *fp;

	fp = sshkey_fingerprint(host_कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT);
	अगर (fp == शून्य)
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
पूर्णांक
ssh_local_cmd(स्थिर अक्षर *args)
{
	अक्षर *shell;
	pid_t pid;
	पूर्णांक status;
	व्योम (*osighand)(पूर्णांक);

	अगर (!options.permit_local_command ||
	    args == शून्य || !*args)
		वापस (1);

	अगर ((shell = दो_पर्या("SHELL")) == शून्य || *shell == '\0')
		shell = _PATH_BSHELL;

	osighand = ssh_signal(SIGCHLD, संक_पूर्व);
	pid = विभाजन();
	अगर (pid == 0) {
		ssh_signal(SIGPIPE, संक_पूर्व);
		debug3("Executing %s -c \"%s\"", shell, args);
		execl(shell, shell, "-c", args, (अक्षर *)शून्य);
		error("Couldn't execute %s -c \"%s\": %s",
		    shell, args, म_त्रुटि(त्रुटि_सं));
		_निकास(1);
	} अन्यथा अगर (pid == -1)
		fatal("fork failed: %.100s", म_त्रुटि(त्रुटि_सं));
	जबतक (waitpid(pid, &status, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, osighand);

	अगर (!WIFEXITED(status))
		वापस (1);

	वापस (WEXITSTATUS(status));
}

व्योम
maybe_add_कुंजी_to_agent(स्थिर अक्षर *authfile, काष्ठा sshkey *निजी,
    स्थिर अक्षर *comment, स्थिर अक्षर *passphrase)
{
	पूर्णांक auth_sock = -1, r;
	स्थिर अक्षर *skprovider = शून्य;

	अगर (options.add_कुंजियाँ_to_agent == 0)
		वापस;

	अगर ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
		debug3("no authentication agent, not adding key");
		वापस;
	}

	अगर (options.add_कुंजियाँ_to_agent == 2 &&
	    !ask_permission("Add key %s (%s) to agent?", authfile, comment)) {
		debug3("user denied adding this key");
		बंद(auth_sock);
		वापस;
	}
	अगर (sshkey_is_sk(निजी))
		skprovider = options.sk_provider;
	अगर ((r = ssh_add_identity_constrained(auth_sock, निजी,
	    comment == शून्य ? authfile : comment,
	    options.add_कुंजियाँ_to_agent_lifespan,
	    (options.add_कुंजियाँ_to_agent == 3), skprovider, शून्य, 0)) == 0)
		debug("identity added to agent: %s", authfile);
	अन्यथा
		debug("could not add identity to agent: %s (%d)", authfile, r);
	बंद(auth_sock);
}
