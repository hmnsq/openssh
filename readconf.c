/* $OpenBSD: readconf.c,v 1.419 2026/10/05 06:03:40 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <net/if.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <ifaddrs.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>
#जर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "version.h"

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     User foo

   Host fake.com
     Hostname another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Ciphers 3des-cbc

   Host fascist.blob.com
     Port 23123
     User tylonen
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p
     ProxyCommand ssh-proxy %h %p

   Host *.fr
     PublicKeyAuthentication no

   Host *.su
     Ciphers aes128-ctr
     PasswordAuthentication no

   Host vpn.fake.com
     Tunnel yes
     TunnelDevice 3

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 no
     PasswordAuthentication yes
     StrictHostKeyChecking yes
     TcpKeepAlive no
     IdentityFile ~/.ssh/identity
     Port 22
     EscapeChar ~

*/

स्थिर पूर्णांक read_config_file_depth(स्थिरांक अक्षर *filename, संरचना passwd *pw,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command,
    Options *options, पूर्णांक flags, पूर्णांक *activep, पूर्णांक *want_final_pass, पूर्णांक depth);
स्थिर पूर्णांक process_config_ओळ_depth(Options *options, संरचना passwd *pw,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command,
    अक्षर *ओळ, स्थिरांक अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags,
    पूर्णांक *want_final_pass, पूर्णांक depth);

/* Keyword tokens. */

प्रकारव्याख्या गणना {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_किल्ल्या_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_किल्ली_Checking, oCompression,
	oTCPKeepAlive, o_संख्या_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_किल्ली_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_किल्ली_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_किल्ली_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_मोजणी_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_किल्ली,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_किल्ल्या,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_किल्ली_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

स्थिर संरचना {
	स्थिरांक अक्षर *name;
	OpCodes opcode;
} keywords[] = {
	/* Deprecated options */
	{ "protocol", oIgnore }, /* NB. silently ignored */
	{ "cipher", oDeprecated },
	{ "fallbacktorsh", oDeprecated },
	{ "globalknownhostsfile2", oDeprecated },
	{ "rhostsauthentication", oDeprecated },
	{ "userknownhostsfile2", oDeprecated },
	{ "useroaming", oDeprecated },
	{ "usersh", oDeprecated },
	{ "useprivilegedport", oDeprecated },

	/* Unsupported options */
	{ "afstokenpassing", oUnsupported },
	{ "kerberosauthentication", oUnsupported },
	{ "kerberostgtpassing", oUnsupported },
	{ "rsaauthentication", oUnsupported },
	{ "rhostsrsaauthentication", oUnsupported },
	{ "compressionlevel", oUnsupported },

	/* Sometimes-unsupported options */
#जर defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# अन्यथा
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# अन्यथा
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#endif

	{ "forwardagent", oForwardAgent },
	{ "forwardx11", oForwardX11 },
	{ "forwardx11trusted", oForwardX11Trusted },
	{ "forwardx11timeout", oForwardX11Timeout },
	{ "exitonforwardfailure", oExitOnForwardFailure },
	{ "xauthlocation", oXAuthLocation },
	{ "gatewayports", oGatewayPorts },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "kbdinteractiveauthentication", oKbdInteractiveAuthentication },
	{ "kbdinteractivedevices", oKbdInteractiveDevices },
	{ "challengeresponseauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "skeyauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "tisauthentication", oKbdInteractiveAuthentication },  /* alias */
	{ "pubkeyauthentication", oPubkeyAuthentication },
	{ "dsaauthentication", oPubkeyAuthentication },		    /* alias */
	{ "hostbasedauthentication", oHostbasedAuthentication },
	{ "identityfile", oIdentityFile },
	{ "identityfile2", oIdentityFile },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_Add_किल्ल्या_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_किल्ली_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", oPort },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", oMatch },
	{ "tag", oTag },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", oGlobalKnownHostsFile },
	{ "userknownhostsfile", oUserKnownHostsFile },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", oBatchMode },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_किल्ली_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_संख्या_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_किल्ली_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_किल्ली_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_मोजणी_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", oSetEnv },
	{ "controlpath", oControlPath },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", oHashKnownHosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_किल्ली },
	{ "kexalgorithms", oKexAlgorithms },
	{ "ipqos", oIPQoS },
	{ "requesttty", oRequestTTY },
	{ "sessiontype", oSessionType },
	{ "stdinnull", oStdinNull },
	{ "forkafterauthentication", oForkAfterAuthentication },
	{ "proxyusefdpass", oProxyUseFdpass },
	{ "canonicaldomains", oCanonicalDomains },
	{ "canonicalizefallbacklocal", oCanonicalizeFallbackLocal },
	{ "canonicalizehostname", oCanonicalizeHostname },
	{ "canonicalizemaxdots", oCanonicalizeMaxDots },
	{ "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs },
	{ "streamlocalbindmask", oStreamLocalBindMask },
	{ "streamlocalbindunlink", oStreamLocalBindUnlink },
	{ "revokedhostkeys", o_Revoked_Host_किल्ल्या },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_किल्ली_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ रिक्त, oBadOption }
};

स्थिर स्थिरांक अक्षर *lookup_opcode_name(OpCodes code);

स्थिरांक अक्षर *
kex_default_pk_alg(शून्य)
{
	स्थिर अक्षर *pkalgs;

	जर (pkalgs == रिक्त) {
		अक्षर *all_किल्ली;

		all_किल्ली = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_किल्ली);
		मुक्त(all_किल्ली);
	}
	परत pkalgs;
}

अक्षर *
ssh_connection_hash(स्थिरांक अक्षर *thishost, स्थिरांक अक्षर *host, स्थिरांक अक्षर *portstr,
    स्थिरांक अक्षर *user, स्थिरांक अक्षर *jumphost)
{
	संरचना ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	जर ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == रिक्त ||
	    ssh_digest_update(md, thishost, म_माप(thishost)) < 0 ||
	    ssh_digest_update(md, host, म_माप(host)) < 0 ||
	    ssh_digest_update(md, portstr, म_माप(portstr)) < 0 ||
	    ssh_digest_update(md, user, म_माप(user)) < 0 ||
	    ssh_digest_update(md, jumphost, म_माप(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, आकार(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	परत tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

शून्य
add_local_forward(Options *options, स्थिरांक संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णांक i;

	/* Don't add duplicates */
	साठी (i = 0; i < options->अंक_local_forwards; i++) {
		जर (forward_equals(newfwd, options->local_forwards + i))
			परत;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->अंक_local_forwards + 1,
	    आकार(*options->local_forwards));
	fwd = &options->local_forwards[options->अंक_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

शून्य
add_remote_forward(Options *options, स्थिरांक संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णांक i;

	/* Don't add duplicates */
	साठी (i = 0; i < options->अंक_remote_forwards; i++) {
		जर (forward_equals(newfwd, options->remote_forwards + i))
			परत;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->अंक_remote_forwards + 1,
	    आकार(*options->remote_forwards));
	fwd = &options->remote_forwards[options->अंक_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

स्थिर शून्य
clear_forwardings(Options *options)
{
	पूर्णांक i;

	साठी (i = 0; i < options->अंक_local_forwards; i++) {
		मुक्त(options->local_forwards[i].listen_host);
		मुक्त(options->local_forwards[i].listen_path);
		मुक्त(options->local_forwards[i].connect_host);
		मुक्त(options->local_forwards[i].connect_path);
	}
	जर (options->अंक_local_forwards > 0) {
		मुक्त(options->local_forwards);
		options->local_forwards = रिक्त;
	}
	options->अंक_local_forwards = 0;
	साठी (i = 0; i < options->अंक_remote_forwards; i++) {
		मुक्त(options->remote_forwards[i].listen_host);
		मुक्त(options->remote_forwards[i].listen_path);
		मुक्त(options->remote_forwards[i].connect_host);
		मुक्त(options->remote_forwards[i].connect_path);
	}
	जर (options->अंक_remote_forwards > 0) {
		मुक्त(options->remote_forwards);
		options->remote_forwards = रिक्त;
	}
	options->अंक_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

शून्य
add_certificate_file(Options *options, स्थिरांक अक्षर *path, पूर्णांक userprovided)
{
	पूर्णांक i;

	जर (options->अंक_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	साठी (i = 0; i < options->अंक_certificate_files; i++) {
		जर (options->certificate_file_userprovided[i] == userprovided &&
		    म_भेद(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			परत;
		}
	}

	options->certificate_file_userprovided[options->अंक_certificate_files] =
	    userprovided;
	options->certificate_files[options->अंक_certificate_files++] =
	    xstrdup(path);
}

शून्य
add_identity_file(Options *options, स्थिरांक अक्षर *dir, स्थिरांक अक्षर *filename,
    पूर्णांक userprovided)
{
	अक्षर *path;
	पूर्णांक i;

	जर (options->अंक_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	जर (dir == रिक्त) /* no dir, filename is absolute */
		path = xstrdup(filename);
	अन्यथा जर (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	साठी (i = 0; i < options->अंक_identity_files; i++) {
		जर (options->identity_file_userprovided[i] == userprovided &&
		    म_भेद(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			मुक्त(path);
			परत;
		}
	}

	options->identity_file_userprovided[options->अंक_identity_files] =
	    userprovided;
	options->identity_files[options->अंक_identity_files++] = path;
}

पूर्णांक
default_ssh_port(शून्य)
{
	स्थिर पूर्णांक port;
	संरचना servent *sp;

	जर (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	परत port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
स्थिर पूर्णांक
execute_in_shell(स्थिरांक अक्षर *cmd)
{
	अक्षर *shell;
	pid_t pid;
	पूर्णांक status;

	जर ((shell = दो_पर्या("SHELL")) == रिक्त)
		shell = _PATH_BSHELL;

	जर (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, म_त्रुटि(त्रुटि_सं));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	जर ((pid = विभाजन()) == 0) {
		अक्षर *argv[4];

		जर (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = रिक्त;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, म_त्रुटि(त्रुटि_सं));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(संक_इति, संक_पूर्व);
		समाप्त(getpid(), संक_इति);
		_exit(1);
	}
	/* Parent. */
	जर (pid == -1)
		fatal_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));

	पर्यंत (waitpid(pid, &status, 0) == -1) {
		जर (त्रुटि_सं != EINTR && त्रुटि_सं != EAGAIN)
			fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	जर (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		परत -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	परत WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
स्थिर पूर्णांक
check_match_ifaddrs(स्थिरांक अक्षर *addrlist)
{
#ifdef HAVE_IFADDRS_H
	संरचना ifaddrs *ifa, *ifaddrs = रिक्त;
	पूर्णांक r, found = 0;
	अक्षर addr[NI_MAXHOST];
	socklen_t salen;

	जर (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    म_त्रुटि(त्रुटि_सं));
		परत 0;
	}
	साठी (ifa = ifaddrs; ifa != रिक्त; ifa = ifa->ifa_next) {
		जर (ifa->ifa_addr == रिक्त || ifa->ifa_name == रिक्त ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			सुरूठेवा;
		निवड (ifa->ifa_addr->sa_family) {
		स्थिती AF_INET:
			salen = आकार(संरचना sockaddr_in);
			थांबा;
		स्थिती AF_INET6:
			salen = आकार(संरचना sockaddr_in6);
			थांबा;
#ifdef AF_LINK
		स्थिती AF_LINK:
			/* ignore */
			सुरूठेवा;
#endif /* AF_LINK */
		पूर्वनिर्धारित:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			सुरूठेवा;
		}
		जर ((r = getnameinfo(ifa->ifa_addr, salen, addr, आकार(addr),
		    रिक्त, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			सुरूठेवा;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		जर (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			थांबा;
		}
	}
	freeifaddrs(ifaddrs);
	परत found;
#अन्यथा /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	परत 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
स्थिर अक्षर *
expand_match_exec_or_include_path(स्थिरांक अक्षर *path, Options *options,
    संरचना passwd *pw, स्थिरांक अक्षर *host_arg, स्थिरांक अक्षर *original_host,
    पूर्णांक final_pass, पूर्णांक is_include_path)
{
	अक्षर thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	अक्षर uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	अक्षर *host, *ret;
	पूर्णांक port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	जर (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा जर (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (अक्षर *)रिक्त);
	} अन्यथा {
		host = xstrdup(host_arg);
	}
	जर (gethostname(thishost, आकार(thishost)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, आकार(shorthost));
	shorthost[म_खोज(thishost, ".")] = '\0';
	snprintf(portstr, आकार(portstr), "%d", port);
	snprintf(uidstr, आकार(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_किल्ली_alias ?  options->host_किल्ली_alias : host;

	ret = (is_include_path ? percent_dollar_expand : percent_expand)(path,
	    "C", conn_hash_hex,
	    "L", shorthost,
	    "d", pw->pw_dir,
	    "h", host,
	    "k", keyalias,
	    "l", thishost,
	    "n", original_host,
	    "p", portstr,
	    "r", ruser,
	    "u", pw->pw_name,
	    "i", uidstr,
	    "j", jmphost,
	    (अक्षर *)रिक्त);
	मुक्त(host);
	मुक्त(conn_hash_hex);
	परत ret;
}

/*
 * Parse and execute a Match directive.
 */
स्थिर पूर्णांक
match_cfg_ओळ(Options *options, स्थिरांक अक्षर *full_ओळ, पूर्णांक *acp, अक्षर ***avp,
    संरचना passwd *pw, स्थिरांक अक्षर *host_arg, स्थिरांक अक्षर *original_host,
    स्थिरांक अक्षर *remote_command, पूर्णांक final_pass, पूर्णांक *want_final_pass,
    स्थिरांक अक्षर *filename, पूर्णांक linenum)
{
	अक्षर *arg, *oattrib = रिक्त, *attrib = रिक्त, *cmd, *host, *criteria;
	स्थिरांक अक्षर *ruser;
	पूर्णांक r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	जर (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा जर (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (अक्षर *)रिक्त);
	} अन्यथा {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_ओळ, host, original_host);
	पर्यंत ((attrib = argv_next(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		जर (*attrib == '#') {
			argv_consume(acp);
			थांबा;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = रिक्त;
		this_result = 1;
		जर ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		जर (strcasecmp(attrib, "all") == 0) {
			जर (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				जा out;
			}
			जर (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			जर (result)
				result = negate ? 0 : 1;
			जा out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		जर (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			जर (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != रिक्त)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			जा next;
		}

		/* Keep this list in sync with below */
		जर (strprefix(attrib, "host=", 1)  != रिक्त ||
		    strprefix(attrib, "originalhost=", 1) != रिक्त ||
		    strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "localuser=", 1) != रिक्त ||
		    strprefix(attrib, "localnetwork=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त ||
		    strprefix(attrib, "tagged=", 1) != रिक्त ||
		    strprefix(attrib, "command=", 1) != रिक्त ||
		    strprefix(attrib, "exec=", 1) != रिक्त) {
			arg = म_अक्षर(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा जर ((arg = argv_next(acp, avp)) == रिक्त) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			जा out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		जर (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = रिक्त;
		जर (arg == रिक्त || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			जा out;
		}
		जर (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "localnetwork") == 0) {
			जर (addr_match_cidr_list(रिक्त, arg) == -1) {
				/* Error already printed */
				result = -1;
				जा out;
			}
			r = check_match_ifaddrs(arg) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == रिक्त ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == रिक्त ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "sessiontype") == 0) {
			जर (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			अन्यथा जर (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			अन्यथा जर (remote_command != रिक्त &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			अन्यथा
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा जर (strcasecmp(attrib, "exec") == 0) {
			जर ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == रिक्त) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			जर (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				मुक्त(cmd);
				जा next;
			}
			r = execute_in_shell(cmd);
			जर (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			मुक्त(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			जर (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अन्यथा {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			जा out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == रिक्त ? "" : " \"",
		    criteria == रिक्त ? "" : criteria,
		    criteria == रिक्त ? "" : "\"");
 next:
		मुक्त(criteria);
		मुक्त(oattrib);
		oattrib = attrib = रिक्त;
	}
	जर (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		जा out;
	}
 out:
	जर (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	मुक्त(oattrib);
	मुक्त(host);
	परत result;
}

/* Remove environment variable by pattern */
स्थिर शून्य
rm_env(Options *options, स्थिरांक अक्षर *arg, स्थिरांक अक्षर *filename, पूर्णांक linenum)
{
	u_int i, j, onum_send_env = options->अंक_send_env;

	/* Remove an environment variable */
	साठी (i = 0; i < options->अंक_send_env; ) {
		जर (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			सुरूठेवा;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		मुक्त(options->send_env[i]);
		options->send_env[i] = रिक्त;
		साठी (j = i; j < options->अंक_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = रिक्त;
		}
		options->अंक_send_env--;
		/* NB. don't increment i */
	}
	जर (onum_send_env != options->अंक_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->अंक_send_env,
		    आकार(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
स्थिर OpCodes
parse_token(स्थिरांक अक्षर *cp, स्थिरांक अक्षर *filename, पूर्णांक linenum,
    स्थिरांक अक्षर *ignored_unknown)
{
	पूर्णांक i;

	साठी (i = 0; keywords[i].name; i++)
		जर (म_भेद(cp, keywords[i].name) == 0)
			परत keywords[i].opcode;
	जर (ignored_unknown != रिक्त &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		परत oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	परत oBadOption;
}

स्थिर शून्य
free_canon_cnames(संरचना allowed_cname *cnames, u_int n)
{
	u_int i;

	जर (cnames == रिक्त || n == 0)
		परत;
	साठी (i = 0; i < n; i++) {
		मुक्त(cnames[i].source_list);
		मुक्त(cnames[i].target_list);
	}
	मुक्त(cnames);
}

/* Multistate option parsing */
संरचना multistate {
	अक्षर *किल्ली;
	पूर्णांक मूल्य;
};
स्थिर स्थिरांक संरचना multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
स्थिर स्थिरांक संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णांक
parse_multistate_मूल्य(स्थिरांक अक्षर *arg, स्थिरांक अक्षर *filename, पूर्णांक linenum,
    स्थिरांक संरचना multistate *multistate_ptr)
{
	पूर्णांक i;

	जर (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		परत -1;
	}
	साठी (i = 0; multistate_ptr[i].किल्ली != रिक्त; i++) {
		जर (strcasecmp(arg, multistate_ptr[i].किल्ली) == 0)
			परत multistate_ptr[i].मूल्य;
	}
	परत -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
पूर्णांक
process_config_ओळ(Options *options, संरचना passwd *pw, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command, अक्षर *ओळ,
    स्थिरांक अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags)
{
	परत process_config_ओळ_depth(options, pw, host, original_host,
	    remote_command, ओळ, filename, linenum, activep, flags, रिक्त, 0);
}

#define WHITESPACE " \t\r\n"
स्थिर पूर्णांक
process_config_ओळ_depth(Options *options, संरचना passwd *pw, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command, अक्षर *ओळ,
    स्थिरांक अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags,
    पूर्णांक *want_final_pass, पूर्णांक depth)
{
	अक्षर *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	अक्षर **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	पूर्णांक r, oactive, negated, opcode, *intptr, मूल्य, value2, cmdline = 0;
	पूर्णांक remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	दीर्घ दीर्घ val64;
	माप_प्रकार len;
	संरचना Forward fwd;
	स्थिरांक संरचना multistate *multistate_ptr;
	glob_t gl;
	स्थिरांक अक्षर *errstr;
	अक्षर **oav = रिक्त, **av;
	पूर्णांक oac = 0, ac;
	पूर्णांक ret = -1;
	संरचना allowed_cname *cnames = रिक्त;
	u_int ncnames = 0;
	अक्षर **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	जर (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	जर ((len = म_माप(ओळ)) == 0)
		परत 0;
	साठी (len--; len > 0; len--) {
		जर (म_अक्षर(WHITESPACE "\f", ओळ[len]) == रिक्त)
			थांबा;
		ओळ[len] = '\0';
	}

	str = ओळ;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	जर ((keyword = strdelim(&str)) == रिक्त)
		परत 0;
	/* Ignore leading whitespace. */
	जर (*keyword == '\0')
		keyword = strdelim(&str);
	जर (keyword == रिक्त || !*keyword || *keyword == '\n' || *keyword == '#')
		परत 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	जर (str != रिक्त)
		str += म_अखोज(str, WHITESPACE);
	जर (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		परत -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	जर (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		परत -1;
	}
	ac = oac;
	av = oav;

	निवड (opcode) {
	स्थिती oBadOption:
		/* don't panic, but count bad options */
		जा out;
	स्थिती oIgnore:
		argv_consume(&ac);
		थांबा;
	स्थिती oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		थांबा;
	स्थिती oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			जा out;
		}
		जर (म_भेद(arg, "none") == 0)
			मूल्य = -1;
		अन्यथा जर ((मूल्य = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			जा out;
		}
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			जा out;
		}

		मूल्य = -1;
		multistate_ptr = multistate_flag;
		साठी (i = 0; multistate_ptr[i].किल्ली != रिक्त; i++) {
			जर (strcasecmp(arg, multistate_ptr[i].किल्ली) == 0) {
				मूल्य = multistate_ptr[i].मूल्य;
				थांबा;
			}
		}
		जर (मूल्य != -1) {
			जर (*activep && *intptr == -1)
				*intptr = मूल्य;
			थांबा;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		जर (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		जा parse_agent_path;

	स्थिती oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		जर ((मूल्य = parse_multistate_मूल्य(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			जा out;
		}
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		जा parse_flag;

	स्थिती oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		जा parse_time;

	स्थिती oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		जा parse_flag;

	स्थिती oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		जा parse_flag;

	स्थिती oPasswordAuthentication:
		intptr = &options->password_authentication;
		जा parse_flag;

	स्थिती oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		जा parse_flag;

	स्थिती oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		जा parse_string;

	स्थिती oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		जा parse_multistate;

	स्थिती oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		जा parse_flag;

	स्थिती oGssAuthentication:
		intptr = &options->gss_authentication;
		जा parse_flag;

	स्थिती oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		जा parse_flag;

	स्थिती oBatchMode:
		intptr = &options->batch_mode;
		जा parse_flag;

	स्थिती oCheckHostIP:
		intptr = &options->check_host_ip;
		जा parse_flag;

	स्थिती o_Verify_Host_किल्ली_DNS:
		intptr = &options->verify_host_किल्ली_dns;
		multistate_ptr = multistate_yesnoask;
		जा parse_multistate;

	स्थिती o_Strict_Host_किल्ली_Checking:
		intptr = &options->strict_host_किल्ली_checking;
		multistate_ptr = multistate_strict_hostkey;
		जा parse_multistate;

	स्थिती oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		जा parse_multistate;

	स्थिती oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		जा parse_multistate;

	स्थिती oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		जा parse_flag;

	स्थिती o_संख्या_Of_Password_Prompts:
		intptr = &options->संख्या_of_password_prompts;
		जा parse_int;

	स्थिती oRekeyLimit:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			जा out;
		}
		जर (म_भेद(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			जर (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, म_त्रुटि(त्रुटि_सं));
				जा out;
			}
			जर (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				जा out;
			}
		}
		जर (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		जर (ac != 0) { /* optional rekey interval present */
			जर (म_भेद(av[0], "none") == 0) {
				(शून्य)argv_next(&ac, &av);	/* discard */
				थांबा;
			}
			intptr = &options->rekey_interval;
			जा parse_time;
		}
		थांबा;

	स्थिती oIdentityFile:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*activep) {
			intptr = &options->अंक_identity_files;
			जर (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				जा out;
			}
			add_identity_file(options, रिक्त,
			    arg, flags & SSHCONF_USERCONF);
		}
		थांबा;

	स्थिती oCertificateFile:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*activep) {
			intptr = &options->अंक_certificate_files;
			जर (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				जा out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		थांबा;

	स्थिती oXAuthLocation:
		charptr=&options->xauth_location;
		जा parse_string;

	स्थिती oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती oGlobalKnownHostsFile:
		cpptr = (अक्षर **)&options->system_hostfiles;
		uintptr = &options->अंक_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		मूल्य = *uintptr == 0; /* was array empty when we started? */
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			i++;
			जर (*activep && मूल्य) {
				जर ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					जा out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		थांबा;

	स्थिती oUserKnownHostsFile:
		cpptr = (अक्षर **)&options->user_hostfiles;
		uintptr = &options->अंक_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		जा parse_char_array;

	स्थिती oHostname:
		charptr = &options->hostname;
		जा parse_string;

	स्थिती oTag:
		charptr = &options->tag;
		जा parse_string;

	स्थिती o_Host_किल्ली_Alias:
		charptr = &options->host_किल्ली_alias;
		जा parse_string;

	स्थिती oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		जा parse_string;

	स्थिती oBindAddress:
		charptr = &options->bind_address;
		जा parse_string;

	स्थिती oBindInterface:
		charptr = &options->bind_interface;
		जा parse_string;

	स्थिती oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		जा parse_string;

	स्थिती o_Security_किल्ली_Provider:
		charptr = &options->sk_provider;
		जा parse_string;

	स्थिती oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		जा parse_command;

	स्थिती oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		जर (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		len = म_अखोज(str, WHITESPACE "=");
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		थांबा;

	स्थिती oProxyJump:
		जर (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		len = म_अखोज(str, WHITESPACE "=");
		/* XXX use argv? */
		जर (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			जा out;
		}
		argv_consume(&ac);
		थांबा;

	स्थिती oPort:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		मूल्य = a2port(arg);
		जर (मूल्य <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			जा out;
		}
		जर (*activep && options->port == -1)
			options->port = मूल्य;
		थांबा;

	स्थिती oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		जर ((errstr = atoi_err(arg, &मूल्य)) != रिक्त) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			जा out;
		}
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oCiphers:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*activep && options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		थांबा;

	स्थिती oMacs:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*activep && options->macs == रिक्त)
			options->macs = xstrdup(arg);
		थांबा;

	स्थिती oKexAlgorithms:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*activep && options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		थांबा;

	स्थिती o_Host_किल्ली_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		जा parse_pubkey_algos;

	स्थिती oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		मूल्य = log_level_संख्या(arg);
		जर (मूल्य == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) मूल्य;
		थांबा;

	स्थिती oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		मूल्य = log_facility_संख्या(arg);
		जर (मूल्य == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			जा out;
		}
		जर (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मूल्य;
		थांबा;

	स्थिती oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->अंक_log_verbose;
		i = 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			i++;
			जर (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, आकार(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		थांबा;

	स्थिती oLocalForward:
	स्थिती oRemoteForward:
	स्थिती oDynamicForward:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		जर (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			जर (arg2 == रिक्त || *arg2 == '\0') {
				जर (remotefwd)
					dynamicfwd = 1;
				अन्यथा {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					जा out;
				}
			} अन्यथा {
				/* construct a string for parse_forward */
				snprintf(fwdarg, आकार(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		जर (dynamicfwd)
			strlcpy(fwdarg, arg, आकार(fwdarg));

		जर (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			जा out;
		}

		जर (*activep) {
			जर (remotefwd) {
				add_remote_forward(options, &fwd);
			} अन्यथा {
				add_local_forward(options, &fwd);
			}
		}
		थांबा;

	स्थिती oPermitRemoteOpen:
		uintptr = &options->अंक_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			जर (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					मुक्त(arg2);
					जा out;
				}
			} अन्यथा {
				p = hpdelim(&arg);
				जर (p == रिक्त) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				जर (arg == रिक्त || (म_भेद(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		जर (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		जर (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती oClearAllForwardings:
		intptr = &options->clear_forwardings;
		जा parse_flag;

	स्थिती oHost:
		जर (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			जा out;
		}
		*activep = 0;
		arg2 = रिक्त;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			जर ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				थांबा;
			}
			negated = *arg == '!';
			जर (negated)
				arg++;
			जर (match_pattern(host, arg)) {
				जर (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					थांबा;
				}
				जर (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		जर (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		थांबा;

	स्थिती oMatch:
		जर (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			जा out;
		}
		मूल्य = match_cfg_ओळ(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		जर (मूल्य < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			जा out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : मूल्य;
		थांबा;

	स्थिती oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (म_भेद(arg, "none") == 0)
			मूल्य = SSH_ESCAPECHAR_NONE;
		अन्यथा जर (arg[1] == '\0')
			मूल्य = (u_char) arg[0];
		अन्यथा जर (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			मूल्य = (u_char) arg[1] & 31;
		अन्यथा {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			जा out;
		}
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		जा parse_multistate;

	स्थिती oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		जा parse_flag;

	स्थिती oIdentitiesOnly:
		intptr = &options->identities_only;
		जा parse_flag;

	स्थिती oServerAliveInterval:
		intptr = &options->server_alive_interval;
		जा parse_time;

	स्थिती o_Server_Alive_मोजणी_Max:
		intptr = &options->server_alive_मोजणी_max;
		जा parse_int;

	स्थिती oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0' || म_अक्षर(arg, '=') != रिक्त) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				जा out;
			}
			found = 1;
			जर (!*activep)
				सुरूठेवा;
			जर (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				सुरूठेवा;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->अंक_send_env, arg);
		}
		जर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती oSetEnv:
		found = options->अंक_setenv == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (म_अक्षर(arg, '=') == रिक्त) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				जा out;
			}
			जर (lookup_setenv_in_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				सुरूठेवा;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->setenv = strs;
			options->अंक_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती oControlPath:
		charptr = &options->control_path;
		जा parse_string;

	स्थिती oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		जा parse_multistate;

	स्थिती oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			जा out;
		}
		मूल्य = 0;
		value2 = 0;	/* timeout */
		जर (म_भेद(arg, "no") == 0 || म_भेद(arg, "false") == 0)
			मूल्य = 0;
		अन्यथा जर (म_भेद(arg, "yes") == 0 || म_भेद(arg, "true") == 0)
			मूल्य = 1;
		अन्यथा जर ((value2 = convtime(arg)) >= 0)
			मूल्य = 1;
		अन्यथा {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			जा out;
		}
		जर (*activep && *intptr == -1) {
			*intptr = मूल्य;
			options->control_persist_timeout = value2;
		}
		थांबा;

	स्थिती oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		जा parse_flag;

	स्थिती oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		जा parse_multistate;

	स्थिती oTunnelDevice:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		मूल्य = a2tun(arg, &value2);
		जर (मूल्य == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			जा out;
		}
		जर (*activep && options->tun_local == -1) {
			options->tun_local = मूल्य;
			options->tun_remote = value2;
		}
		थांबा;

	स्थिती oLocalCommand:
		charptr = &options->local_command;
		जा parse_command;

	स्थिती oPermitLocalCommand:
		intptr = &options->permit_local_command;
		जा parse_flag;

	स्थिती oRemoteCommand:
		charptr = &options->remote_command;
		जा parse_command;

	स्थिती o_Visual_Host_किल्ली:
		intptr = &options->visual_host_किल्ली;
		जा parse_flag;

	स्थिती oInclude:
		जर (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			जा out;
		}
		मूल्य = 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Expand %tokens and environment variables */
			जर ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == रिक्त) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				सुरूठेवा;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			जर (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				जा out;
			}
			जर (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} अन्यथा {
				arg2 = xstrdup(p);
			}
			मुक्त(p);
			स_रखो(&gl, 0, आकार(gl));
			r = glob(arg2, GLOB_TILDE, रिक्त, &gl);
			जर (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				मुक्त(arg2);
				सुरूठेवा;
			} अन्यथा जर (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				जा out;
			}
			मुक्त(arg2);
			oactive = *activep;
			साठी (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				जर (r != 1 && त्रुटि_सं != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    म_त्रुटि(त्रुटि_सं));
					globfree(&gl);
					जा out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				जर (r != 1)
					मूल्य = -1;
			}
			globfree(&gl);
		}
		जर (मूल्य != 0)
			ret = मूल्य;
		थांबा;

	स्थिती oIPQoS:
		arg = argv_next(&ac, &av);
		जर ((मूल्य = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			जा out;
		}
		जर (मूल्य == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मूल्य = पूर्णांक_उच्च;
		}
		arg = argv_next(&ac, &av);
		जर (arg == रिक्त)
			value2 = मूल्य;
		अन्यथा जर ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			जा out;
		}
		जर (value2 == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = पूर्णांक_उच्च;
		}
		जर (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मूल्य;
			options->ip_qos_bulk = value2;
		}
		थांबा;

	स्थिती oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		जा parse_multistate;

	स्थिती oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		जा parse_multistate;

	स्थिती oStdinNull:
		intptr = &options->stdin_null;
		जा parse_flag;

	स्थिती oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		जा parse_flag;

	स्थिती oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		जा parse_string;

	स्थिती oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		जा parse_flag;

	स्थिती oCanonicalDomains:
		found = options->अंक_canonical_domains == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			जर (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				जा out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->canonical_domains = strs;
			options->अंक_canonical_domains = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती oCanonicalizePermittedCNAMEs:
		found = options->अंक_permitted_cnames == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			जर (strcasecmp(arg, "none") == 0) {
				जर (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
				arg2 = "";
			} अन्यथा जर (म_भेद(arg, "*") == 0) {
				arg2 = arg;
			} अन्यथा {
				lowercase(arg);
				जर ((arg2 = म_अक्षर(arg, ':')) == रिक्त ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					जा out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    आकार(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		जर (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->permitted_cnames = cnames;
			options->अंक_permitted_cnames = ncnames;
			cnames = रिक्त; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		थांबा;

	स्थिती oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		जा parse_multistate;

	स्थिती oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		जा parse_int;

	स्थिती oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		जा parse_flag;

	स्थिती oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			जा out;
		}
		/* Parse mode in octal format */
		मूल्य = म_से_दीर्घ(arg, &endofnumber, 8);
		जर (arg == endofnumber || मूल्य < 0 || मूल्य > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			जा out;
		}
		जर (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मूल्य;
		थांबा;

	स्थिती oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		जा parse_flag;

	स्थिती o_Revoked_Host_किल्ल्या:
		uintptr = &options->अंक_revoked_host_किल्ल्या;
		cppptr = &options->revoked_host_किल्ल्या;
		found = *uintptr == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर ((मूल्य = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			जा out;
		}
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		जा parse_multistate;

	स्थिती oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		जा parse_pubkey_algos;

	स्थिती oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		जा parse_pubkey_algos;

	स्थिती o_Add_किल्ल्या_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		मूल्य = parse_multistate_मूल्य(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		जर (मूल्य == 3 && arg2 != रिक्त) {
			/* allow "AddKeysToAgent confirm 5m" */
			जर ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				जा out;
			}
		} अन्यथा जर (मूल्य == -1 && arg2 == रिक्त) {
			जर ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				जा out;
			}
			मूल्य = 1; /* yes */
		} अन्यथा जर (मूल्य == -1 || arg2 != रिक्त) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			जा out;
		}
		जर (*activep && options->add_किल्ल्या_to_agent == -1) {
			options->add_किल्ल्या_to_agent = मूल्य;
			options->add_किल्ल्या_to_agent_lifespan = value2;
		}
		थांबा;

	स्थिती oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		जर ((arg2 = dollar_expand(&r, arg)) == रिक्त || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			जा out;
		}
		मुक्त(arg2);
		/* check for legacy environment format */
		जर (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			जा out;
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		जा parse_flag;

	स्थिती oRequiredRSASize:
		intptr = &options->required_rsa_size;
		जा parse_int;

	स्थिती oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		जा parse_multistate;

	स्थिती oObscureKeystrokeTiming:
		मूल्य = -1;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (मूल्य != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				जा out;
			}
			जर (म_भेद(arg, "yes") == 0 ||
			    म_भेद(arg, "true") == 0)
				मूल्य = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			अन्यथा जर (म_भेद(arg, "no") == 0 ||
			    म_भेद(arg, "false") == 0)
				मूल्य = 0;
			अन्यथा जर (म_भेदन(arg, "interval:", 9) == 0) {
				जर ((errstr = atoi_err(arg + 9,
				    &मूल्य)) != रिक्त) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					जा out;
				}
				जर (मूल्य <= 0 || मूल्य > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					जा out;
				}
			} अन्यथा {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				जा out;
			}
		}
		जर (मूल्य == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			जा out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती oChannelTimeout:
		found = options->अंक_channel_timeouts == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			} अन्यथा जर (parse_pattern_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->channel_timeouts = strs;
			options->अंक_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती oVersionAddendum:
		जर (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		जर (म_अक्षर(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		जर ((arg = म_अक्षर(ओळ, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(ओळ);
		}
		जर (*activep && options->version_addendum == रिक्त) {
			जर (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अन्यथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		थांबा;

	स्थिती oRefuseConnection:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जा out;
		}
		जर (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		थांबा;

	स्थिती oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		थांबा;

	स्थिती oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		थांबा;

	पूर्वनिर्धारित:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		जा out;
	}

	/* Check that there is no garbage at end of line. */
	जर (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		जा out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	परत ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
पूर्णांक
read_config_file(स्थिरांक अक्षर *filename, संरचना passwd *pw, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command, Options *options, पूर्णांक flags,
    पूर्णांक *want_final_pass)
{
	पूर्णांक active = 1;

	परत read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
स्थिर पूर्णांक
read_config_file_depth(स्थिरांक अक्षर *filename, संरचना passwd *pw,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *original_host, स्थिरांक अक्षर *remote_command,
    Options *options, पूर्णांक flags, पूर्णांक *activep, पूर्णांक *want_final_pass, पूर्णांक depth)
{
	खाता *f;
	अक्षर *ओळ = रिक्त;
	माप_प्रकार linesize = 0;
	पूर्णांक linenum;
	पूर्णांक bad_options = 0;

	जर (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	जर ((f = ख_खोलो(filename, "r")) == रिक्त)
		परत 0;

	जर (flags & SSHCONF_CHECKPERM) {
		संरचना stat sb;

		जर (ख_स्थिति(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, म_त्रुटि(त्रुटि_सं));
		जर (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		जर (process_config_ओळ_depth(options, pw, host, original_host,
		    remote_command, ओळ, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	मुक्त(ओळ);
	ख_बंद(f);
	जर (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	परत 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
पूर्णांक
option_clear_or_none(स्थिरांक अक्षर *o)
{
	परत o == रिक्त || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
पूर्णांक
config_has_permitted_cnames(Options *options)
{
	जर (options->अंक_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    म_भेद(options->permitted_cnames[0].target_list, "") == 0)
		परत 0;
	परत options->अंक_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

शून्य
initialize_options(Options * options)
{
	स_रखो(options, 'X', आकार(*options));
	options->host_arg = रिक्त;
	options->forward_agent = -1;
	options->forward_agent_sock_path = रिक्त;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = रिक्त;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = रिक्त;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = रिक्त;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_किल्ली_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->संख्या_of_password_prompts = -1;
	options->ciphers = रिक्त;
	options->macs = रिक्त;
	options->kex_algorithms = रिक्त;
	options->hostkeyalgorithms = रिक्त;
	options->ca_sign_algorithms = रिक्त;
	options->अंक_identity_files = 0;
	स_रखो(options->identity_किल्ल्या, 0, आकार(options->identity_किल्ल्या));
	options->अंक_certificate_files = 0;
	स_रखो(options->certificates, 0, आकार(options->certificates));
	options->hostname = रिक्त;
	options->host_किल्ली_alias = रिक्त;
	options->proxy_command = रिक्त;
	options->jump_user = रिक्त;
	options->jump_host = रिक्त;
	options->jump_port = -1;
	options->jump_extra = रिक्त;
	options->user = रिक्त;
	options->escape_char = -1;
	options->अंक_system_hostfiles = 0;
	options->अंक_user_hostfiles = 0;
	options->local_forwards = रिक्त;
	options->अंक_local_forwards = 0;
	options->remote_forwards = रिक्त;
	options->अंक_remote_forwards = 0;
	options->permitted_remote_opens = रिक्त;
	options->अंक_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->अंक_log_verbose = 0;
	options->log_verbose = रिक्त;
	options->preferred_authentications = रिक्त;
	options->bind_address = रिक्त;
	options->bind_interface = रिक्त;
	options->pkcs11_provider = रिक्त;
	options->sk_provider = रिक्त;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_किल्ली_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_मोजणी_max = -1;
	options->send_env = रिक्त;
	options->अंक_send_env = 0;
	options->setenv = रिक्त;
	options->अंक_setenv = 0;
	options->control_path = रिक्त;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = रिक्त;
	options->permit_local_command = -1;
	options->remote_command = रिक्त;
	options->add_किल्ल्या_to_agent = -1;
	options->add_किल्ल्या_to_agent_lifespan = -1;
	options->identity_agent = रिक्त;
	options->visual_host_किल्ली = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = रिक्त;
	options->अंक_canonical_domains = 0;
	options->अंक_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_किल्ल्या = रिक्त;
	options->अंक_revoked_host_किल्ल्या = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = रिक्त;
	options->pubkey_accepted_algos = रिक्त;
	options->known_hosts_command = रिक्त;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = रिक्त;
	options->channel_timeouts = रिक्त;
	options->अंक_channel_timeouts = 0;
	options->version_addendum = रिक्त;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
शून्य
fill_default_options_for_canonicalization(Options *options)
{
	जर (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	जर (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	जर (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
पूर्णांक
fill_default_options(Options * options)
{
	अक्षर *all_cipher, *all_mac, *all_kex, *all_किल्ली, *all_sig;
	अक्षर *def_cipher, *def_mac, *def_kex, *def_किल्ली, *def_sig;
	पूर्णांक ret = -1, r;

	जर (options->forward_agent == -1)
		options->forward_agent = 0;
	जर (options->forward_x11 == -1)
		options->forward_x11 = 0;
	जर (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	जर (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	जर (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	जर (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	जर (options->clear_forwardings == 1)
		clear_forwardings(options);

	जर (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	जर (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	जर (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	जर (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	जर (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	जर (options->gss_authentication == -1)
		options->gss_authentication = 0;
	जर (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	जर (options->password_authentication == -1)
		options->password_authentication = 1;
	जर (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	जर (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	जर (options->batch_mode == -1)
		options->batch_mode = 0;
	जर (options->check_host_ip == -1)
		options->check_host_ip = 0;
	जर (options->strict_host_किल्ली_checking == -1)
		options->strict_host_किल्ली_checking = SSH_STRICT_HOSTKEY_ASK;
	जर (options->compression == -1)
		options->compression = 0;
	जर (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	जर (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	जर (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	जर (options->connection_attempts == -1)
		options->connection_attempts = 1;
	जर (options->संख्या_of_password_prompts == -1)
		options->संख्या_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	जर (options->add_किल्ल्या_to_agent == -1) {
		options->add_किल्ल्या_to_agent = 0;
		options->add_किल्ल्या_to_agent_lifespan = 0;
	}
	जर (options->अंक_identity_files == 0) {
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ECDSA_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	जर (options->escape_char == -1)
		options->escape_char = '~';
	जर (options->अंक_system_hostfiles == 0) {
		options->system_hostfiles[options->अंक_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->अंक_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	जर (options->update_hostkeys == -1) {
		जर (options->verify_host_किल्ली_dns <= 0 &&
		    (options->अंक_user_hostfiles == 0 ||
		    (options->अंक_user_hostfiles == 1 && म_भेद(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		अन्यथा
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	जर (options->अंक_user_hostfiles == 0) {
		options->user_hostfiles[options->अंक_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->अंक_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	जर (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	जर (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	जर (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	जर (options->identities_only == -1)
		options->identities_only = 0;
	जर (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	जर (options->rekey_limit == -1)
		options->rekey_limit = 0;
	जर (options->rekey_interval == -1)
		options->rekey_interval = 0;
	जर (options->verify_host_किल्ली_dns == -1)
		options->verify_host_किल्ली_dns = 0;
	जर (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	जर (options->server_alive_मोजणी_max == -1)
		options->server_alive_मोजणी_max = 3;
	जर (options->control_master == -1)
		options->control_master = 0;
	जर (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	जर (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	जर (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	जर (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	जर (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	जर (options->permit_local_command == -1)
		options->permit_local_command = 0;
	जर (options->visual_host_किल्ली == -1)
		options->visual_host_किल्ली = 0;
	जर (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	जर (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	जर (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	जर (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	जर (options->stdin_null == -1)
		options->stdin_null = 0;
	जर (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	जर (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	जर (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	जर (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	जर (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	जर (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	जर (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
#अन्यथा
	जर (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	जर (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	जर (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	जर (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	जर (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_किल्ली = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_किल्ली = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_किल्ली);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	करा { \
		जर ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			जा fail; \
		} \
	} पर्यंत (0)
	options->kex_algorithms_set = options->kex_algorithms != रिक्त;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_किल्ली, all_किल्ली);
	ASSEMBLE(pubkey_accepted_algos, def_किल्ली, all_किल्ली);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	करा { \
		जर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} पर्यंत(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करा { \
		जर (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} पर्यंत (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, अंक_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_किल्ल्या, अंक_revoked_host_किल्ल्या, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	जर (options->jump_host != रिक्त &&
	    म_भेद(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == रिक्त) {
		मुक्त(options->jump_host);
		options->jump_host = रिक्त;
	}
	जर (options->अंक_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		मुक्त(options->permitted_cnames[0].source_list);
		मुक्त(options->permitted_cnames[0].target_list);
		स_रखो(options->permitted_cnames, '\0',
		    आकार(*options->permitted_cnames));
		options->अंक_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_किल्ली);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_किल्ली);
	मुक्त(def_sig);
	परत ret;
}

शून्य
free_options(Options *o)
{
	पूर्णांक i;

	जर (o == रिक्त)
		परत;

#define FREE_ARRAY(type, n, a) \
	करा { \
		type _i; \
		साठी (_i = 0; _i < (n); _i++) \
			मुक्त((a)[_i]); \
	} पर्यंत (0)

	मुक्त(o->forward_agent_sock_path);
	मुक्त(o->xauth_location);
	FREE_ARRAY(u_int, o->अंक_log_verbose, o->log_verbose);
	मुक्त(o->log_verbose);
	मुक्त(o->ciphers);
	मुक्त(o->macs);
	मुक्त(o->hostkeyalgorithms);
	मुक्त(o->kex_algorithms);
	मुक्त(o->ca_sign_algorithms);
	मुक्त(o->hostname);
	मुक्त(o->host_किल्ली_alias);
	मुक्त(o->proxy_command);
	मुक्त(o->user);
	FREE_ARRAY(u_int, o->अंक_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->अंक_user_hostfiles, o->user_hostfiles);
	मुक्त(o->preferred_authentications);
	मुक्त(o->bind_address);
	मुक्त(o->bind_interface);
	मुक्त(o->pkcs11_provider);
	मुक्त(o->sk_provider);
	साठी (i = 0; i < o->अंक_identity_files; i++) {
		मुक्त(o->identity_files[i]);
		sshkey_free(o->identity_किल्ल्या[i]);
	}
	साठी (i = 0; i < o->अंक_certificate_files; i++) {
		मुक्त(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	मुक्त(o->identity_agent);
	साठी (i = 0; i < o->अंक_local_forwards; i++) {
		मुक्त(o->local_forwards[i].listen_host);
		मुक्त(o->local_forwards[i].listen_path);
		मुक्त(o->local_forwards[i].connect_host);
		मुक्त(o->local_forwards[i].connect_path);
	}
	मुक्त(o->local_forwards);
	साठी (i = 0; i < o->अंक_remote_forwards; i++) {
		मुक्त(o->remote_forwards[i].listen_host);
		मुक्त(o->remote_forwards[i].listen_path);
		मुक्त(o->remote_forwards[i].connect_host);
		मुक्त(o->remote_forwards[i].connect_path);
	}
	मुक्त(o->remote_forwards);
	मुक्त(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->अंक_send_env, o->send_env);
	मुक्त(o->send_env);
	FREE_ARRAY(u_int, o->अंक_setenv, o->setenv);
	मुक्त(o->setenv);
	मुक्त(o->control_path);
	मुक्त(o->local_command);
	मुक्त(o->remote_command);
	FREE_ARRAY(पूर्णांक, o->अंक_canonical_domains, o->canonical_domains);
	साठी (i = 0; i < o->अंक_permitted_cnames; i++) {
		मुक्त(o->permitted_cnames[i].source_list);
		मुक्त(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->अंक_revoked_host_किल्ल्या, o->revoked_host_किल्ल्या);
	मुक्त(o->revoked_host_किल्ल्या);
	मुक्त(o->hostbased_accepted_algos);
	मुक्त(o->pubkey_accepted_algos);
	मुक्त(o->jump_user);
	मुक्त(o->jump_host);
	मुक्त(o->jump_extra);
	मुक्त(o->ignored_unknown);
	explicit_bzero(o, आकार(*o));
#undef FREE_ARRAY
}

संरचना fwdarg {
	अक्षर *arg;
	पूर्णांक ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
स्थिर पूर्णांक
parse_fwd_field(अक्षर **p, संरचना fwdarg *fwd)
{
	अक्षर *ep, *cp = *p;
	पूर्णांक ispath = 0;

	जर (*cp == '\0') {
		*p = रिक्त;
		परत -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	जर (*cp == '[') {
		/* find matching ']' */
		साठी (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			जर (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		जर (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			परत -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		जर (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		परत 0;
	}

	साठी (cp = *p; *cp != '\0'; cp++) {
		निवड (*cp) {
		स्थिती '\\':
			स_हटाओ(cp, cp + 1, म_माप(cp + 1) + 1);
			जर (*cp == '\0')
				परत -1;
			थांबा;
		स्थिती '/':
			ispath = 1;
			थांबा;
		स्थिती ':':
			*cp++ = '\0';
			जा done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	परत 0;
}

/*
 * parse_forward
 * parses a string containing a port forwarding specification of the form:
 *   dynamicfwd == 0
 *	[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
 *   dynamicfwd == 1
 *	[listenhost:]listenport
 * returns number of arguments parsed or zero on error
 */
पूर्णांक
parse_forward(संरचना Forward *fwd, स्थिरांक अक्षर *fwdspec, पूर्णांक dynamicfwd, पूर्णांक remotefwd)
{
	संरचना fwdarg fwdargs[4];
	अक्षर *p, *cp;
	पूर्णांक i, err;

	स_रखो(fwd, 0, आकार(*fwd));
	स_रखो(fwdargs, 0, आकार(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	जर (p == रिक्त || err)
		परत 0;

	/* skip leading spaces */
	पर्यंत (है_खाली((u_char)*cp))
		cp++;

	साठी (i = 0; i < 4; ++i) {
		जर (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			थांबा;
	}

	/* Check for trailing garbage */
	जर (cp != रिक्त && *cp != '\0') {
		i = 0;	/* failure */
	}

	निवड (i) {
	स्थिती 1:
		जर (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		थांबा;

	स्थिती 2:
		जर (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा जर (fwdargs[1].ispath) {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		थांबा;

	स्थिती 3:
		जर (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} अन्यथा जर (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		थांबा;

	स्थिती 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		थांबा;
	पूर्वनिर्धारित:
		i = 0; /* failure */
	}

	मुक्त(p);

	जर (dynamicfwd) {
		जर (!(i == 1 || i == 2))
			जा fail_free;
	} अन्यथा {
		जर (!(i == 3 || i == 4)) {
			जर (fwd->connect_path == रिक्त &&
			    fwd->listen_path == रिक्त)
				जा fail_free;
		}
		जर (fwd->connect_port <= 0 && fwd->connect_path == रिक्त)
			जा fail_free;
	}

	जर ((fwd->listen_port < 0 && fwd->listen_path == रिक्त) ||
	    (!remotefwd && fwd->listen_port == 0))
		जा fail_free;
	जर (fwd->connect_host != रिक्त &&
	    म_माप(fwd->connect_host) >= NI_MAXHOST)
		जा fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	जर (fwd->connect_path != रिक्त &&
	    म_माप(fwd->connect_path) >= PATH_MAX_SUN)
		जा fail_free;
	जर (fwd->listen_host != रिक्त &&
	    म_माप(fwd->listen_host) >= NI_MAXHOST)
		जा fail_free;
	जर (fwd->listen_path != रिक्त &&
	    म_माप(fwd->listen_path) >= PATH_MAX_SUN)
		जा fail_free;

	परत (i);

 fail_free:
	मुक्त(fwd->connect_host);
	fwd->connect_host = रिक्त;
	मुक्त(fwd->connect_path);
	fwd->connect_path = रिक्त;
	मुक्त(fwd->listen_host);
	fwd->listen_host = रिक्त;
	मुक्त(fwd->listen_path);
	fwd->listen_path = रिक्त;
	परत (0);
}

पूर्णांक
ssh_valid_hostname(स्थिरांक अक्षर *s)
{
	माप_प्रकार i;

	जर (*s == '-')
		परत 0;
	साठी (i = 0; s[i] != 0; i++) {
		जर (म_अक्षर("'`\"$\\;&<>|(){},", s[i]) != रिक्त ||
		    है_खाली((u_char)s[i]) || है_नियंत्रण((u_char)s[i]))
			परत 0;
	}
	परत 1;
}

पूर्णांक
ssh_valid_ruser(स्थिरांक अक्षर *s)
{
	माप_प्रकार i;

	जर (*s == '-')
		परत 0;
	साठी (i = 0; s[i] != 0; i++) {
		जर (है_नियंत्रण((u_char)s[i]))
			परत 0;
		जर (म_अक्षर("'`\";&<>|(){}$\\", s[i]) != रिक्त)
			परत 0;
		/* Disallow '-' after whitespace */
		जर (है_खाली((u_char)s[i]) && s[i + 1] == '-')
			परत 0;
	}
	परत 1;
}

पूर्णांक
parse_jump(स्थिरांक अक्षर *s, Options *o, पूर्णांक strict, पूर्णांक active)
{
	अक्षर *orig = रिक्त, *sdup = रिक्त, *cp;
	अक्षर *tmp_user = रिक्त, *tmp_host = रिक्त, *host = रिक्त, *user = रिक्त;
	पूर्णांक r, ret = -1, tmp_port = -1, port = -1, first = 1;

	जर (strcasecmp(s, "none") == 0) {
		जर (active && o->jump_host == रिक्त) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		परत 0;
	}

	orig = xstrdup(s);
	जर ((cp = म_अक्षर(orig, '#')) != रिक्त)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == रिक्त && o->jump_host == रिक्त;
	sdup = xstrdup(orig);
	करा {
		/* Work backwards through string */
		जर ((cp = म_खोजप(sdup, ',')) == रिक्त)
			cp = sdup; /* last */
		अन्यथा
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		जर (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			जा out; /* error already logged */
		जर (strict) {
			जर (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				जा out;
			}
			जर (tmp_user != रिक्त && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				जा out;
			}
		}
		जर (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = रिक्त; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		मुक्त(tmp_user);
		मुक्त(tmp_host);
		tmp_user = tmp_host = रिक्त;
		tmp_port = -1;
	} पर्यंत (cp != sdup);

	/* success */
	जर (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = रिक्त; /* transferred */
		जर (orig != रिक्त && (cp = म_खोजप(orig, ',')) != रिक्त) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	मुक्त(orig);
	मुक्त(sdup);
	मुक्त(tmp_user);
	मुक्त(tmp_host);
	मुक्त(user);
	मुक्त(host);
	परत ret;
}

पूर्णांक
parse_ssh_uri(स्थिरांक अक्षर *uri, अक्षर **userp, अक्षर **hostp, पूर्णांक *portp)
{
	अक्षर *user = रिक्त, *host = रिक्त, *path = रिक्त;
	पूर्णांक r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	जर (r == 0 && path != रिक्त)
		r = -1;		/* path not allowed */
	जर (r == 0) {
		जर (userp != रिक्त) {
			*userp = user;
			user = रिक्त;
		}
		जर (hostp != रिक्त) {
			*hostp = host;
			host = रिक्त;
		}
		जर (portp != रिक्त)
			*portp = port;
	}
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	परत r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
स्थिर स्थिरांक अक्षर *
fmt_multistate_int(पूर्णांक val, स्थिरांक संरचना multistate *m)
{
	u_int i;

	साठी (i = 0; m[i].किल्ली != रिक्त; i++) {
		जर (m[i].मूल्य == val)
			परत m[i].किल्ली;
	}
	परत "UNKNOWN";
}

स्थिर स्थिरांक अक्षर *
fmt_intarg(OpCodes code, पूर्णांक val)
{
	जर (val == -1)
		परत "unset";
	निवड (code) {
	स्थिती oAddressFamily:
		परत fmt_multistate_int(val, multistate_addressfamily);
	स्थिती oCompression:
		परत fmt_multistate_int(val, multistate_compression);
	स्थिती o_Verify_Host_किल्ली_DNS:
	स्थिती oUpdateHostkeys:
		परत fmt_multistate_int(val, multistate_yesnoask);
	स्थिती o_Strict_Host_किल्ली_Checking:
		परत fmt_multistate_int(val, multistate_strict_hostkey);
	स्थिती oControlMaster:
		परत fmt_multistate_int(val, multistate_controlmaster);
	स्थिती oTunnel:
		परत fmt_multistate_int(val, multistate_tunnel);
	स्थिती oRequestTTY:
		परत fmt_multistate_int(val, multistate_requesttty);
	स्थिती oSessionType:
		परत fmt_multistate_int(val, multistate_sessiontype);
	स्थिती oCanonicalizeHostname:
		परत fmt_multistate_int(val, multistate_canonicalizehostname);
	स्थिती o_Add_किल्ल्या_To_Agent:
		परत fmt_multistate_int(val, multistate_yesnoaskconfirm);
	स्थिती oPubkeyAuthentication:
		परत fmt_multistate_int(val, multistate_pubkey_auth);
	स्थिती oTCPKeepAlive:
		परत fmt_multistate_int(val, multistate_keepalives);
	स्थिती oFingerprintHash:
		परत ssh_digest_alg_name(val);
	पूर्वनिर्धारित:
		निवड (val) {
		स्थिती 0:
			परत "no";
		स्थिती 1:
			परत "yes";
		पूर्वनिर्धारित:
			परत "UNKNOWN";
		}
	}
}

स्थिर स्थिरांक अक्षर *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	साठी (i = 0; keywords[i].name != रिक्त; i++)
		जर (keywords[i].opcode == code)
			परत(keywords[i].name);
	परत "UNKNOWN";
}

स्थिर शून्य
dump_cfg_int(OpCodes code, पूर्णांक val)
{
	जर (code == oObscureKeystrokeTiming) {
		जर (val == 0) {
			म_लिखो("%s no\n", lookup_opcode_name(code));
			परत;
		} अन्यथा जर (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			म_लिखो("%s yes\n", lookup_opcode_name(code));
			परत;
		}
		/* FALLTHROUGH */
	}
	म_लिखो("%s %d\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_fmtint(OpCodes code, पूर्णांक val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

स्थिर शून्य
dump_cfg_string(OpCodes code, स्थिरांक अक्षर *val)
{
	जर (val == रिक्त)
		परत;
	म_लिखो("%s %s\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_strarray(OpCodes code, u_int मोजणी, अक्षर **vals)
{
	u_int i;

	साठी (i = 0; i < मोजणी; i++)
		म_लिखो("%s %s\n", lookup_opcode_name(code), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(OpCodes code, u_int मोजणी, अक्षर **vals)
{
	u_int i;

	म_लिखो("%s", lookup_opcode_name(code));
	जर (मोजणी == 0)
		म_लिखो(" none");
	साठी (i = 0; i < मोजणी; i++)
		म_लिखो(" %s",  vals[i]);
	म_लिखो("\n");
}

स्थिर शून्य
dump_cfg_forwards(OpCodes code, u_int मोजणी, स्थिरांक संरचना Forward *fwds)
{
	स्थिरांक संरचना Forward *fwd;
	u_int i;

	/* oDynamicForward */
	साठी (i = 0; i < मोजणी; i++) {
		fwd = &fwds[i];
		जर (code == oDynamicForward && fwd->connect_host != रिक्त &&
		    म_भेद(fwd->connect_host, "socks") != 0)
			सुरूठेवा;
		जर (code == oLocalForward && fwd->connect_host != रिक्त &&
		    म_भेद(fwd->connect_host, "socks") == 0)
			सुरूठेवा;
		म_लिखो("%s", lookup_opcode_name(code));
		जर (fwd->listen_port == PORT_STREAMLOCAL)
			म_लिखो(" %s", fwd->listen_path);
		अन्यथा जर (fwd->listen_host == रिक्त)
			म_लिखो(" %d", fwd->listen_port);
		अन्यथा {
			म_लिखो(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		जर (code != oDynamicForward) {
			जर (fwd->connect_port == PORT_STREAMLOCAL)
				म_लिखो(" %s", fwd->connect_path);
			अन्यथा जर (fwd->connect_host == रिक्त)
				म_लिखो(" %d", fwd->connect_port);
			अन्यथा {
				म_लिखो(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		म_लिखो("\n");
	}
}

शून्य
dump_client_config(Options *o, स्थिरांक अक्षर *host)
{
	पूर्णांक i, r;
	अक्षर buf[8], *all_किल्ली;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_किल्ली = sshkey_alg_list(0, 0, 1, ',');
	जर ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_किल्ली)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	मुक्त(all_किल्ली);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(oPort, o->port);

	/* Flag options */
	dump_cfg_fmtint(oAddressFamily, o->address_family);
	dump_cfg_fmtint(oBatchMode, o->batch_mode);
	dump_cfg_fmtint(oCanonicalizeFallbackLocal, o->canonicalize_fallback_local);
	dump_cfg_fmtint(oCanonicalizeHostname, o->canonicalize_hostname);
	dump_cfg_fmtint(oCheckHostIP, o->check_host_ip);
	dump_cfg_fmtint(oCompression, o->compression);
	dump_cfg_fmtint(oControlMaster, o->control_master);
	dump_cfg_fmtint(oEnableSSHKeysign, o->enable_ssh_keysign);
	dump_cfg_fmtint(oClearAllForwardings, o->clear_forwardings);
	dump_cfg_fmtint(oExitOnForwardFailure, o->exit_on_forward_failure);
	dump_cfg_fmtint(oFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(oForwardX11, o->forward_x11);
	dump_cfg_fmtint(oForwardX11Trusted, o->forward_x11_trusted);
	dump_cfg_fmtint(oGatewayPorts, o->fwd_opts.gateway_ports);
#ifdef GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#endif /* GSSAPI */
	dump_cfg_fmtint(oHashKnownHosts, o->hash_known_hosts);
	dump_cfg_fmtint(oHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(oIdentitiesOnly, o->identities_only);
	dump_cfg_fmtint(oKbdInteractiveAuthentication, o->kbd_interactive_authentication);
	dump_cfg_fmtint(oNoHostAuthenticationForLocalhost, o->no_host_authentication_for_localhost);
	dump_cfg_fmtint(oPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(oPermitLocalCommand, o->permit_local_command);
	dump_cfg_fmtint(oProxyUseFdpass, o->proxy_use_fdpass);
	dump_cfg_fmtint(oPubkeyAuthentication, o->pubkey_authentication);
	dump_cfg_fmtint(oRequestTTY, o->request_tty);
	dump_cfg_fmtint(oSessionType, o->session_type);
	dump_cfg_fmtint(oStdinNull, o->stdin_null);
	dump_cfg_fmtint(oForkAfterAuthentication, o->fork_after_authentication);
	dump_cfg_fmtint(oStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_किल्ली_Checking, o->strict_host_किल्ली_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_किल्ली_DNS, o->verify_host_किल्ली_dns);
	dump_cfg_fmtint(o_Visual_Host_किल्ली, o->visual_host_किल्ली);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_संख्या_Of_Password_Prompts, o->संख्या_of_password_prompts);
	dump_cfg_int(o_Server_Alive_मोजणी_Max, o->server_alive_मोजणी_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_किल्ली_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_किल्ली_Alias, o->host_किल्ली_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(oIdentityAgent, o->identity_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ifdef ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#endif
	dump_cfg_string(o_Security_किल्ली_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->अंक_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->अंक_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->अंक_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->अंक_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->अंक_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->अंक_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->अंक_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->अंक_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_किल्ल्या, o->अंक_revoked_host_किल्ल्या, o->revoked_host_किल्ल्या);
	dump_cfg_strarray(oSendEnv, o->अंक_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->अंक_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->अंक_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->अंक_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	जर (o->अंक_permitted_remote_opens == 0)
		म_लिखो("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	अन्यथा
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->अंक_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	जर (o->add_किल्ल्या_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_किल्ल्या_To_Agent, o->add_किल्ल्या_to_agent);
	अन्यथा {
		म_लिखो("addkeystoagent%s %d\n",
		    o->add_किल्ल्या_to_agent == 3 ? " confirm" : "",
		    o->add_किल्ल्या_to_agent_lifespan);
	}

	/* oForwardAgent */
	जर (o->forward_agent_sock_path == रिक्त)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	अन्यथा
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	जर (o->connection_timeout == -1)
		म_लिखो("connecttimeout none\n");
	अन्यथा
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	म_लिखो("tunneldevice");
	जर (o->tun_local == SSH_TUNID_ANY)
		म_लिखो(" any");
	अन्यथा
		म_लिखो(" %d", o->tun_local);
	जर (o->tun_remote == SSH_TUNID_ANY)
		म_लिखो(":any");
	अन्यथा
		म_लिखो(":%d", o->tun_remote);
	म_लिखो("\n");

	/* oCanonicalizePermittedCNAMEs */
	म_लिखो("canonicalizepermittedcnames");
	जर (o->अंक_permitted_cnames == 0)
		म_लिखो(" none");
	साठी (i = 0; i < o->अंक_permitted_cnames; i++) {
		म_लिखो(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	म_लिखो("\n");

	/* oControlPersist */
	जर (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	अन्यथा
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	जर (o->escape_char == SSH_ESCAPECHAR_NONE)
		म_लिखो("escapechar none\n");
	अन्यथा {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		म_लिखो("escapechar %s\n", buf);
	}

	/* oIPQoS */
	म_लिखो("ipqos %s ", iptos2str(o->ip_qos_interactive));
	म_लिखो("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	म_लिखो("rekeylimit %llu %d\n",
	    (अचिन्हित दीर्घ दीर्घ)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	म_लिखो("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	म_लिखो("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	जर (o->jump_host == रिक्त)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	अन्यथा {
		/* Check for numeric addresses */
		i = म_अक्षर(o->jump_host, ':') != रिक्त ||
		    म_अखोज(o->jump_host, "1234567890.") == म_माप(o->jump_host);
		snprintf(buf, आकार(buf), "%d", o->jump_port);
		म_लिखो("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == रिक्त ? "" : o->jump_extra,
		    o->jump_extra == रिक्त ? "" : ",",
		    /* optional user */
		    o->jump_user == रिक्त ? "" : o->jump_user,
		    o->jump_user == रिक्त ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_port <= 0 ? "" : ":",
		    o->jump_port <= 0 ? "" : buf);
	}
}
