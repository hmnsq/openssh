/* $OpenBSD: ssh-keyscan.c,v 1.171 2026/09/02 00:37:59 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

#अन्तर्भाव "includes.h"
 
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/resource.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "addr.h"

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
पूर्णांक IPv4or6 = AF_UNSPEC;

पूर्णांक ssh_port = SSH_DEFAULT_PORT;

#define KT_RSA		(1)
#define KT_ECDSA	(1<<1)
#define KT_ED25519	(1<<2)
#define KT_ECDSA_SK	(1<<4)
#define KT_ED25519_SK	(1<<5)
#define KT_MLDSA44_ED25519 (1<<6)

#define KT_MIN		KT_RSA
#define KT_MAX		KT_MLDSA44_ED25519

पूर्णांक get_cert = 0;
पूर्णांक get_keytypes = KT_RSA|KT_ECDSA|KT_ED25519|KT_ECDSA_SK|KT_ED25519_SK|KT_MLDSA44_ED25519;

पूर्णांक hash_hosts = 0;		/* Hash hostname on output */

पूर्णांक print_sshfp = 0;		/* Print SSHFP records instead of known_hosts */

पूर्णांक found_one = 0;		/* Successfully found a key */

पूर्णांक hashalg = -1;		/* Hash for SSHFP records or -1 for all */

पूर्णांक quiet = 0;			/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
पूर्णांक timeout = 5;

पूर्णांक maxfd;
#define MAXCON (maxfd - 10)

बाह्य अक्षर *__progname;
संरचना pollfd *read_wait;
पूर्णांक ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
प्रकारव्याख्या संरचना Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	पूर्णांक c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	पूर्णांक c_keytype;		/* Only one of KT_* */
	संक_पूर्ण_प्रकार c_done;	/* SSH2 done */
	अक्षर *c_namebase;	/* Address to free for c_name and c_namelist */
	अक्षर *c_name;		/* Hostname of connection for errors */
	अक्षर *c_namelist;	/* Pointer to other possible addresses */
	अक्षर *c_output_name;	/* Hostname of connection for output */
	संरचना ssh *c_ssh;	/* SSH-connection */
	अक्षर c_banner[256];	/* Partial server greeting */
	माप_प्रकार c_banner_len;	/* Length of partial server greeting */
	पूर्णांक c_banner_sent;	/* Client greeting has been sent */
	संरचना timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

स्थिर शून्य keyprint(con *c, संरचना sshkey *किल्ली);

स्थिर पूर्णांक
fdlim_get(पूर्णांक hard)
{
#जर defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	संरचना rlimit rlfd;
	rlim_t lim;

	जर (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		परत -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	जर (lim <= 0)
		परत -1;
	जर (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
	जर (lim >= पूर्णांक_उच्च)
		lim = पूर्णांक_उच्च;
	परत lim;
#अन्यथा
	परत (SSH_SYSFDMAX <= 0) ? -1 :
	    ((SSH_SYSFDMAX >= पूर्णांक_उच्च) ? पूर्णांक_उच्च : SSH_SYSFDMAX);
#endif
}

स्थिर पूर्णांक
fdlim_set(पूर्णांक lim)
{
#जर defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	संरचना rlimit rlfd;
#endif

	जर (lim <= 0)
		परत (-1);
#जर defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
	जर (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		परत (-1);
	rlfd.rlim_cur = lim;
	जर (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		परत (-1);
#किंवाजर defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	परत (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
स्थिर अक्षर *
xstrsep(अक्षर **str, स्थिरांक अक्षर *delim)
{
	अक्षर *s, *e;

	जर (!**str)
		परत (रिक्त);

	s = *str;
	e = s + म_खोज(s, delim);

	जर (*e != '\0')
		*e++ = '\0';
	*str = e;

	परत (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
स्थिर अक्षर *
strnnsep(अक्षर **stringp, अक्षर *delim)
{
	अक्षर *tok;

	करा {
		tok = xstrsep(stringp, delim);
	} पर्यंत (tok && *tok == '\0');
	परत (tok);
}


स्थिर पूर्णांक
किल्ली_print_wrapper(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	con *c;

	जर ((c = ssh_get_app_data(ssh)) != रिक्त)
		keyprint(c, hostkey);
	/* always abort key exchange */
	परत -1;
}

स्थिर पूर्णांक
ssh2_capable(पूर्णांक remote_major, पूर्णांक remote_minor)
{
	निवड (remote_major) {
	स्थिती 1:
		जर (remote_minor == 99)
			परत 1;
		थांबा;
	स्थिती 2:
		परत 1;
	पूर्वनिर्धारित:
		थांबा;
	}
	परत 0;
}

स्थिर शून्य
keygrab_ssh2(con *c)
{
	अक्षर *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	पूर्णांक r;

	निवड (c->c_keytype) {
	स्थिती KT_RSA:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "rsa-sha2-512-cert-v01@openssh.com,"
		    "rsa-sha2-256-cert-v01@openssh.com,"
		    "ssh-rsa-cert-v01@openssh.com" :
		    "rsa-sha2-512,"
		    "rsa-sha2-256,"
		    "ssh-rsa";
		थांबा;
	स्थिती KT_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "ssh-ed25519-cert-v01@openssh.com" : "ssh-ed25519";
		थांबा;
	स्थिती KT_ECDSA:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		    "ecdsa-sha2-nistp521-cert-v01@openssh.com" :
		    "ecdsa-sha2-nistp256,"
		    "ecdsa-sha2-nistp384,"
		    "ecdsa-sha2-nistp521";
		थांबा;
	स्थिती KT_MLDSA44_ED25519:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "ssh-mldsa44-ed25519-cert" :
		    "ssh-mldsa44-ed25519";
		थांबा;
	स्थिती KT_ECDSA_SK:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" :
		    "sk-ecdsa-sha2-nistp256@openssh.com";
		थांबा;
	स्थिती KT_ED25519_SK:
		myproposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = get_cert ?
		    "sk-ssh-ed25519-cert-v01@openssh.com" :
		    "sk-ssh-ed25519@openssh.com";
		थांबा;
	पूर्वनिर्धारित:
		fatal("unknown key type %d", c->c_keytype);
		थांबा;
	}
	जर ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		मुक्त(c->c_ssh);
		ख_लिखो(मानक_त्रुटि, "kex_setup: %s\n", ssh_err(r));
		निकास(1);
	}
#ifdef WITH_OPENSSL
	c->c_ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	c->c_ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	c->c_ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif
	c->c_ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	c->c_ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh_set_verify_host_किल्ली_callback(c->c_ssh, किल्ली_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

स्थिर शून्य
keyprint_one(स्थिरांक अक्षर *host, संरचना sshkey *किल्ली)
{
	अक्षर *hostport = रिक्त, *hashed = रिक्त;
	स्थिरांक अक्षर *known_host;
	पूर्णांक r = 0;

	found_one = 1;

	जर (print_sshfp) {
		export_dns_rr(host, किल्ली, मानक_निकास, 0, hashalg);
		परत;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	जर (hash_hosts && (hashed = host_hash(hostport, रिक्त, 0)) == रिक्त)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;
	जर (!get_cert)
		r = ख_लिखो(मानक_निकास, "%s ", known_host);
	जर (r >= 0 && sshkey_write(किल्ली, मानक_निकास) == 0)
		(शून्य)ख_माला_दो("\n", मानक_निकास);
	मुक्त(hashed);
	मुक्त(hostport);
}

स्थिर शून्य
keyprint(con *c, संरचना sshkey *किल्ली)
{
	अक्षर *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	अक्षर *host, *ohosts;

	जर (किल्ली == रिक्त)
		परत;
	जर (get_cert || (!hash_hosts && ssh_port == SSH_DEFAULT_PORT)) {
		keyprint_one(hosts, किल्ली);
		परत;
	}
	ohosts = hosts = xstrdup(hosts);
	पर्यंत ((host = strsep(&hosts, ",")) != रिक्त)
		keyprint_one(host, किल्ली);
	मुक्त(ohosts);
}

स्थिर पूर्णांक
tcpconnect(अक्षर *host)
{
	संरचना addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr, s = -1;

	snprintf(strport, आकार strport, "%d", ssh_port);
	स_रखो(&hints, 0, आकार(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	जर ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		परत -1;
	}
	साठी (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		जर (s == -1) {
			error("socket: %s", म_त्रुटि(त्रुटि_सं));
			सुरूठेवा;
		}
		जर (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		जर (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    त्रुटि_सं != EINPROGRESS)
			error("connect (`%s'): %s", host, म_त्रुटि(त्रुटि_सं));
		अन्यथा
			थांबा;
		बंद(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	परत s;
}

स्थिर पूर्णांक
conalloc(स्थिरांक अक्षर *iname, स्थिरांक अक्षर *oname, पूर्णांक keytype)
{
	अक्षर *namebase, *name, *namelist;
	पूर्णांक s;

	namebase = namelist = xstrdup(iname);

	करा {
		name = xstrsep(&namelist, ",");
		जर (!name) {
			मुक्त(namebase);
			परत (-1);
		}
	} पर्यंत ((s = tcpconnect(name)) < 0);

	जर (s >= maxfd)
		fatal("conalloc: fdno %d too high", s);
	जर (fdcon[s].c_status)
		fatal("conalloc: attempt to reuse fdno %d", s);

	debug3_f("oname %s kt %d", oname, keytype);
	fdcon[s].c_fd = s;
	fdcon[s].c_status = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keytype = keytype;
	fdcon[s].c_banner_len = 0;
	fdcon[s].c_banner_sent = 0;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	परत (s);
}

स्थिर शून्य
confree(पूर्णांक s)
{
	जर (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal("confree: attempt to free bad fdno %d", s);
	मुक्त(fdcon[s].c_namebase);
	मुक्त(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keytype = 0;
	जर (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		मुक्त(fdcon[s].c_ssh);
		fdcon[s].c_ssh = रिक्त;
	} अन्यथा
		बंद(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

स्थिर पूर्णांक
conrecycle(पूर्णांक s)
{
	con *c = &fdcon[s];
	पूर्णांक ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keytype);
	confree(s);
	परत (ret);
}

स्थिर शून्य
congreet(पूर्णांक s)
{
	पूर्णांक remote_major = 0, remote_minor = 0;
	ssize_t n;
	अक्षर buf[256], ch;
	अक्षर remote_version[आकार buf];
	con *c = &fdcon[s];

	जर (!c->c_banner_sent) {
		/* send client banner */
		n = snprintf(buf, आकार buf, "SSH-%d.%d-OpenSSH-keyscan\r\n",
		    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2);
		जर (n < 0 || (माप_प्रकार)n >= आकार(buf)) {
			error("snprintf: buffer too small");
			confree(s);
			परत;
		}
		जर (atomicio(vwrite, s, buf, n) != (माप_प्रकार)n) {
			error("write (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			confree(s);
			परत;
		}
		c->c_banner_sent = 1;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Read a single byte
	 * at a time so that the event loop retains control of connection
	 * timeouts.  Partial lines are retained in the connection state
	 * between calls.
	 */
	n = पठ(s, &ch, आकार(ch));
	जर (n == -1 && (त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK ||
	    त्रुटि_सं == EINTR))
		परत;
	जर (n != 1) {
		जर (n == 0)
			त्रुटि_सं = EPIPE;
		निवड (त्रुटि_सं) {
		स्थिती EPIPE:
			error("%s: Connection closed by remote host",
			    c->c_name);
			थांबा;
		स्थिती ECONNREFUSED:
			थांबा;
		पूर्वनिर्धारित:
			error("read (%s): %s", c->c_name, म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		conrecycle(s);
		परत;
	}
	c->c_banner[c->c_banner_len++] = ch == '\r' ? '\n' : ch;
	जर (ch != '\n') {
		जर (c->c_banner_len < आकार(c->c_banner) - 1)
			परत; /* incomplete line */
		जर (म_भेदन(c->c_banner, "SSH-", 4) == 0) {
			/* banner exceeds RFC 4253 s4.2 length limit */
			error("%s: greeting exceeds allowable length",
			    c->c_name);
			confree(s);
			परत;
		}
		/* Discard an oversized pre-identification banner chunk. */
		c->c_banner_len = 0;
		परत;
	}
	जर (म_भेदन(c->c_banner, "SSH-", 4) != 0) {
		/* Ignore non-banner lines */
		c->c_banner_len = 0;
		परत;
	}
	c->c_banner[c->c_banner_len++] = '\0';
	स_नकल(buf, c->c_banner, c->c_banner_len);
	जर ((c->c_ssh = ssh_packet_set_connection(रिक्त, s, s)) == रिक्त)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	c->c_ssh->compat = 0;
	जर (माला_पूछो(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		compat_banner(c->c_ssh, remote_version);
	जर (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		परत;
	}
	जर (!quiet) {
		ख_लिखो(मानक_निकास, "%c %s:%d %s\n", print_sshfp ? ';' : '#',
		    c->c_name, ssh_port, chop(buf));
	}
	keygrab_ssh2(c);
	confree(s);
}

स्थिर शून्य
conread(पूर्णांक s)
{
	con *c = &fdcon[s];

	जर (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

स्थिर शून्य
conloop(शून्य)
{
	संरचना timespec seltime, now;
	con *c;
	पूर्णांक i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	जर (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	अन्यथा
		timespecclear(&seltime);

	पर्यंत (ppoll(read_wait, maxfd, &seltime, रिक्त) == -1) {
		जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR || त्रुटि_सं == EWOULDBLOCK)
			सुरूठेवा;
		error("poll error");
	}

	साठी (i = 0; i < maxfd; i++) {
		जर (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		अन्यथा जर (read_wait[i].revents & (POLLIN))
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	पर्यंत (c && timespeccmp(&c->c_ts, &now, <)) {
		पूर्णांक s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

स्थिर शून्य
do_one_host(अक्षर *host)
{
	अक्षर *name = strnnsep(&host, " \t\n");
	पूर्णांक j;

	जर (name == रिक्त)
		परत;
	साठी (j = KT_MIN; j <= KT_MAX; j *= 2) {
		जर (get_keytypes & j) {
			पर्यंत (ncon >= MAXCON)
				conloop();
			conalloc(name, *host ? host : name, j);
		}
	}
}

स्थिर शून्य
do_host(अक्षर *host)
{
	अक्षर daddr[128];
	संरचना xaddr addr, end_addr;
	u_int masklen;

	जर (host == रिक्त)
		परत;
	जर (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} अन्यथा {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		जर (addr_host_to_all1s(&end_addr, masklen) != 0)
			जा badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		साठी (;;) {
			जर (addr_ntop(&addr, daddr, आकार(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				परत;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			जर (addr_cmp(&addr, &end_addr) == 0)
				थांबा;
			addr_increment(&addr);
		}
	}
}

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "                   [-t type] [host | addrlist namelist]\n");
	निकास(1);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	पूर्णांक opt, fopt_मोजणी = 0, j;
	अक्षर *tname, *cp, *ओळ = रिक्त;
	माप_प्रकार linesize = 0;
	खाता *fp;

	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	जर (argc <= 1)
		usage();

	पर्यंत ((opt = getopt(argc, argv, "cDHqv46O:p:T:t:f:")) != -1) {
		निवड (opt) {
		स्थिती 'H':
			hash_hosts = 1;
			थांबा;
		स्थिती 'c':
			get_cert = 1;
			थांबा;
		स्थिती 'D':
			print_sshfp = 1;
			थांबा;
		स्थिती 'p':
			ssh_port = a2port(optarg);
			जर (ssh_port <= 0) {
				ख_लिखो(मानक_त्रुटि, "Bad port '%s'\n", optarg);
				निकास(1);
			}
			थांबा;
		स्थिती 'T':
			timeout = convtime(optarg);
			जर (timeout == -1 || timeout == 0) {
				ख_लिखो(मानक_त्रुटि, "Bad timeout '%s'\n", optarg);
				usage();
			}
			थांबा;
		स्थिती 'v':
			जर (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			अन्यथा जर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अन्यथा
				fatal("Too high debugging level.");
			थांबा;
		स्थिती 'q':
			quiet = 1;
			थांबा;
		स्थिती 'f':
			जर (म_भेद(optarg, "-") == 0)
				optarg = रिक्त;
			argv[fopt_मोजणी++] = optarg;
			थांबा;
		स्थिती 'O':
			/* Maybe other misc options in the future too */
			जर (म_भेदन(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			जर ((hashalg = ssh_digest_alg_by_name(
			    optarg + 8)) == -1)
				fatal("Unsupported hash algorithm");
			थांबा;
		स्थिती 't':
			get_keytypes = 0;
			tname = म_मोहर(optarg, ",");
			पर्यंत (tname) {
				पूर्णांक type = sshkey_type_from_shortname(tname);

				निवड (type) {
				स्थिती किल्ली_ECDSA:
					get_keytypes |= KT_ECDSA;
					थांबा;
				स्थिती किल्ली_RSA:
					get_keytypes |= KT_RSA;
					थांबा;
				स्थिती किल्ली_ED25519:
					get_keytypes |= KT_ED25519;
					थांबा;
				स्थिती किल्ली_ED25519_SK:
					get_keytypes |= KT_ED25519_SK;
					थांबा;
				स्थिती किल्ली_ECDSA_SK:
					get_keytypes |= KT_ECDSA_SK;
					थांबा;
				स्थिती किल्ली_MLDSA44_ED25519:
					get_keytypes |= KT_MLDSA44_ED25519;
					थांबा;
				स्थिती किल्ली_UNSPEC:
				पूर्वनिर्धारित:
					fatal("Unknown key type \"%s\"", tname);
				}
				tname = म_मोहर(रिक्त, ",");
			}
			थांबा;
		स्थिती '4':
			IPv4or6 = AF_INET;
			थांबा;
		स्थिती '6':
			IPv4or6 = AF_INET6;
			थांबा;
		पूर्वनिर्धारित:
			usage();
		}
	}
	जर (optind == argc && !fopt_मोजणी)
		usage();

	log_init("ssh-keyscan", log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	जर (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	जर (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	जर (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	जर (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, आकार(con));
	read_wait = xcalloc(maxfd, आकार(संरचना pollfd));
	साठी (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	ssh_signal(SIGPIPE, संक_छोड़ो);
	साठी (j = 0; j < fopt_मोजणी; j++) {
		जर (argv[j] == रिक्त)
			fp = मानक_निवेश;
		अन्यथा जर ((fp = ख_खोलो(argv[j], "r")) == रिक्त)
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		पर्यंत (getline(&ओळ, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			जर ((cp = म_अक्षर(ओळ, '#')) == रिक्त)
				cp = ओळ + म_माप(ओळ) - 1;
			पर्यंत (cp >= ओळ) {
				जर (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				अन्यथा
					थांबा;
			}

			/* Skip empty lines */
			जर (*ओळ == '\0')
				सुरूठेवा;

			do_host(ओळ);
		}

		जर (ख_त्रुटि(fp))
			fatal("%s: %s: %s", __progname,
			    fp == मानक_निवेश ? "<stdin>" : argv[j], म_त्रुटि(त्रुटि_सं));

		जर (fp != मानक_निवेश)
			ख_बंद(fp);
	}
	मुक्त(ओळ);

	पर्यंत (optind < argc)
		do_host(argv[optind++]);

	पर्यंत (ncon > 0)
		conloop();

	परत found_one ? 0 : 1;
}
