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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/wait.h>
#ضمن <sys/un.h>

#ضمن <net/if.h>
#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#ضمن <arpa/inet.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <glob.h>
#ضمن <ifaddrs.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <util.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#د_که_پای

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "cipher.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "match.h"
#ضمن "kex.h"
#ضمن "mac.h"
#ضمن "myproposal.h"
#ضمن "digest.h"
#ضمن "version.h"

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

ساكن صحيح read_config_file_ژوروالی(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح ژوروالی);
ساكن صحيح process_config_کرښه_ژوروالی(Options *options, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    حرف *کرښه, ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح ژوروالی);

/* Keyword tokens. */

تعريفنوع تعداد {
	oBadOption,
	oHost, o_سمون, oInclude, o_نښان,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_بې_اغېزه_عنصر_File, oHostname, o_پورټ, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_جمع_کړه_کلیګانې_منزل_Agent, o_بې_اغېزه_عنصر_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_معلوم_Hosts_File, o_User_معلوم_Hosts_File, oConnectionAttempts,
	o_Batch_ډېرپېښ, oCheckHostIP, o_Strict_Host_کلی_Checking, oCompression,
	oTCPKeepAlive, o_شمېره_د_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_کلی_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_کلی_Algorithms, o_Bind_پته, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_حد, o_Verify_Host_کلی_DNS, oConnectTimeout,
	o_پته_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_شمېر_Max, oIdentitiesOnly,
	oSendEnv, o_سېټ_Env, o_Control_لار, oControlMaster, oControlPersist,
	o_Hash_معلوم_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_کلی,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_بهیر_Local_Bind_ماسک, o_بهیر_Local_Bind_Unlink, o_Revoked_Host_کلیګانې,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_کلی_Provider, o_معلوم_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_نسخه_Addendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ساكن بنية {
	ثابت حرف *name;
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
#إذا defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# وإلا
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#د_که_پای
#که_تعریف_شوی ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# وإلا
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#د_که_پای

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
	{ "identityfile", o_بې_اغېزه_عنصر_File },
	{ "identityfile2", o_بې_اغېزه_عنصر_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_جمع_کړه_کلیګانې_منزل_Agent },
	{ "identityagent", o_بې_اغېزه_عنصر_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_کلی_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_پورټ },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_سمون },
	{ "tag", o_نښان },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_معلوم_Hosts_File },
	{ "userknownhostsfile", o_User_معلوم_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_ډېرپېښ },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_کلی_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_شمېره_د_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_کلی_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_پته },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_کلی_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_حد },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_پته_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_شمېر_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_سېټ_Env },
	{ "controlpath", o_Control_لار },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_معلوم_Hosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_کلی },
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
	{ "streamlocalbindmask", o_بهیر_Local_Bind_ماسک },
	{ "streamlocalbindunlink", o_بهیر_Local_Bind_Unlink },
	{ "revokedhostkeys", o_Revoked_Host_کلیګانې },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_کلی_Provider },
	{ "knownhostscommand", o_معلوم_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_نسخه_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ عدم, oBadOption }
};

ساكن ثابت حرف *lookup_opcode_name(OpCodes کوډ);

ثابت حرف *
kex_default_pk_alg(فراغ)
{
	ساكن حرف *pkalgs;

	إذا (pkalgs == عدم) {
		حرف *all_کلی;

		all_کلی = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = سمون_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلی);
		حرر(all_کلی);
	}
	أرجع pkalgs;
}

حرف *
ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host, ثابت حرف *portstr,
    ثابت حرف *user, ثابت حرف *jumphost)
{
	بنية ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_اوږدتیا];

	إذا ((md = ssh_digest_پیل(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_digest_update(md, thishost, مزي_اوږدوالی(thishost)) < 0 ||
	    ssh_digest_update(md, host, مزي_اوږدوالی(host)) < 0 ||
	    ssh_digest_update(md, portstr, مزي_اوږدوالی(portstr)) < 0 ||
	    ssh_digest_update(md, user, مزي_اوږدوالی(user)) < 0 ||
	    ssh_digest_update(md, jumphost, مزي_اوږدوالی(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, حجم(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	أرجع tohex(conn_hash, ssh_digest_بایټونه(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

فراغ
جمع_کړه_local_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->عدد_local_forwards; i++) {
		إذا (forward_equals(newfwd, options->local_forwards + i))
			أرجع;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->عدد_local_forwards + 1,
	    حجم(*options->local_forwards));
	fwd = &options->local_forwards[options->عدد_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورټ = newfwd->listen_پورټ;
	fwd->listen_لار = newfwd->listen_لار;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورټ = newfwd->connect_پورټ;
	fwd->connect_لار = newfwd->connect_لار;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

فراغ
جمع_کړه_remote_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->عدد_remote_forwards; i++) {
		إذا (forward_equals(newfwd, options->remote_forwards + i))
			أرجع;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->عدد_remote_forwards + 1,
	    حجم(*options->remote_forwards));
	fwd = &options->remote_forwards[options->عدد_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورټ = newfwd->listen_پورټ;
	fwd->listen_لار = newfwd->listen_لار;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورټ = newfwd->connect_پورټ;
	fwd->connect_لار = newfwd->connect_لار;
	fwd->handle = newfwd->handle;
	fwd->allocated_پورټ = 0;
}

ساكن فراغ
clear_forwardings(Options *options)
{
	صحيح i;

	لكل (i = 0; i < options->عدد_local_forwards; i++) {
		حرر(options->local_forwards[i].listen_host);
		حرر(options->local_forwards[i].listen_لار);
		حرر(options->local_forwards[i].connect_host);
		حرر(options->local_forwards[i].connect_لار);
	}
	إذا (options->عدد_local_forwards > 0) {
		حرر(options->local_forwards);
		options->local_forwards = عدم;
	}
	options->عدد_local_forwards = 0;
	لكل (i = 0; i < options->عدد_remote_forwards; i++) {
		حرر(options->remote_forwards[i].listen_host);
		حرر(options->remote_forwards[i].listen_لار);
		حرر(options->remote_forwards[i].connect_host);
		حرر(options->remote_forwards[i].connect_لار);
	}
	إذا (options->عدد_remote_forwards > 0) {
		حرر(options->remote_forwards);
		options->remote_forwards = عدم;
	}
	options->عدد_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

فراغ
جمع_کړه_certificate_file(Options *options, ثابت حرف *لار, صحيح userprovided)
{
	صحيح i;

	إذا (options->عدد_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->عدد_certificate_files; i++) {
		إذا (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], لار) == 0) {
			debug2_f("ignoring duplicate key %s", لار);
			أرجع;
		}
	}

	options->certificate_file_userprovided[options->عدد_certificate_files] =
	    userprovided;
	options->certificate_files[options->عدد_certificate_files++] =
	    xstrdup(لار);
}

فراغ
جمع_کړه_بې_اغېزه_عنصر_file(Options *options, ثابت حرف *dir, ثابت حرف *filename,
    صحيح userprovided)
{
	حرف *لار;
	صحيح i;

	إذا (options->عدد_بې_اغېزه_عنصر_files >= SSH_MAX_بې_اغېزه_عنصر_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_بې_اغېزه_عنصر_FILES);

	إذا (dir == عدم) /* no dir, filename is absolute */
		لار = xstrdup(filename);
	وإلا إذا (xasprintf(&لار, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", لار);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->عدد_بې_اغېزه_عنصر_files; i++) {
		إذا (options->بې_اغېزه_عنصر_file_userprovided[i] == userprovided &&
		    strcmp(options->بې_اغېزه_عنصر_files[i], لار) == 0) {
			debug2_f("ignoring duplicate key %s", لار);
			حرر(لار);
			أرجع;
		}
	}

	options->بې_اغېزه_عنصر_file_userprovided[options->عدد_بې_اغېزه_عنصر_files] =
	    userprovided;
	options->بې_اغېزه_عنصر_files[options->عدد_بې_اغېزه_عنصر_files++] = لار;
}

صحيح
default_ssh_پورټ(فراغ)
{
	ساكن صحيح پورټ;
	بنية servent *sp;

	إذا (پورټ == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		پورټ = sp ? ntohs(sp->s_port) : SSH_DEFAULT_پورټ;
	}
	أرجع پورټ;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ساكن صحيح
execute_دننه_shell(ثابت حرف *cmd)
{
	حرف *shell;
	pid_t pid;
	صحيح حالت;

	إذا ((shell = getenv("SHELL")) == عدم)
		shell = _PATH_BSHELL;

	إذا (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	إذا ((pid = fork()) == 0) {
		حرف *argv[4];

		إذا (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = عدم;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	إذا (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	طالما (waitpid(pid, &حالت, 0) == -1) {
		إذا (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	إذا (!WIFEXITED(حالت)) {
		error("command '%.100s' exited abnormally", cmd);
		أرجع -1;
	}
	debug3("command returned status %d", WEXITSTATUS(حالت));
	أرجع WEXITSTATUS(حالت);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ساكن صحيح
check_سمون_ifaddrs(ثابت حرف *addrlist)
{
#که_تعریف_شوی HAVE_IFADDRS_H
	بنية ifaddrs *ifa, *ifaddrs = عدم;
	صحيح r, وموندل = 0;
	حرف addr[NI_MAXHOST];
	socklen_t salen;

	إذا (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		أرجع 0;
	}
	لكل (ifa = ifaddrs; ifa != عدم; ifa = ifa->ifa_بل) {
		إذا (ifa->ifa_addr == عدم || ifa->ifa_name == عدم ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			استمر;
		بدل (ifa->ifa_addr->sa_family) {
		حالة AF_INET:
			salen = حجم(بنية sockaddr_in);
			اكسر;
		حالة AF_INET6:
			salen = حجم(بنية sockaddr_in6);
			اكسر;
#که_تعریف_شوی AF_LINK
		حالة AF_LINK:
			/* ignore */
			استمر;
#د_که_پای /* AF_LINK */
		افتراضي:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			استمر;
		}
		إذا ((r = getnameinfo(ifa->ifa_addr, salen, addr, حجم(addr),
		    عدم, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			استمر;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		إذا (addr_سمون_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			وموندل = 1;
			اكسر;
		}
	}
	freeifaddrs(ifaddrs);
	أرجع وموندل;
#وإلا /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	أرجع 0;
#د_که_پای /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ساكن حرف *
expand_سمون_exec_or_include_لار(ثابت حرف *لار, Options *options,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    صحيح final_pass, صحيح is_include_لار)
{
	حرف thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	حرف uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	حرف *host, *ret;
	صحيح پورټ;

	پورټ = options->پورټ <= 0 ? default_ssh_پورټ() : options->پورټ;
	ruser = options->user == عدم ? pw->pw_name : options->user;
	إذا (final_pass) {
		host = xstrdup(options->hostname);
	} وإلا إذا (options->hostname != عدم) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)عدم);
	} وإلا {
		host = xstrdup(host_arg);
	}
	إذا (gethostname(thishost, حجم(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, حجم(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, حجم(portstr), "%d", پورټ);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بینښه اوږد اوږد)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_کلی_alias ?  options->host_کلی_alias : host;

	ret = (is_include_لار ? percent_dollar_expand : percent_expand)(لار,
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
	    (حرف *)عدم);
	حرر(host);
	حرر(conn_hash_hex);
	أرجع ret;
}

/*
 * Parse and execute a Match directive.
 */
ساكن صحيح
سمون_cfg_کرښه(Options *options, ثابت حرف *ډک_کرښه, صحيح *acp, حرف ***avp,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    ثابت حرف *remote_command, صحيح final_pass, صحيح *want_final_pass,
    ثابت حرف *filename, صحيح linenum)
{
	حرف *arg, *oattrib = عدم, *attrib = عدم, *cmd, *host, *criteria;
	ثابت حرف *ruser;
	صحيح r, this_پایله, پایله = 1, ځانګړتیاوې = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == عدم ? pw->pw_name : options->user;
	إذا (final_pass) {
		host = xstrdup(options->hostname);
	} وإلا إذا (options->hostname != عدم) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)عدم);
	} وإلا {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    ډک_کرښه, host, original_host);
	طالما ((attrib = argv_بل(acp, avp)) != عدم) {
		/* Terminate on comment */
		إذا (*attrib == '#') {
			argv_consume(acp);
			اكسر;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = عدم;
		this_پایله = 1;
		إذا ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		إذا (strcasecmp(attrib, "all") == 0) {
			إذا (ځانګړتیاوې > 1 ||
			    ((arg = argv_بل(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				پایله = -1;
				اذهب بهر;
			}
			إذا (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			إذا (پایله)
				پایله = negate ? 0 : 1;
			اذهب بهر;
		}
		ځانګړتیاوې++;
		/* criteria "final" and "canonical" have no argument */
		إذا (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			إذا (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != عدم)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_پایله ? "" : "not ", oattrib);
			اذهب بل;
		}

		/* Keep this list in sync with below */
		إذا (strprefix(attrib, "host=", 1)  != عدم ||
		    strprefix(attrib, "originalhost=", 1) != عدم ||
		    strprefix(attrib, "user=", 1) != عدم ||
		    strprefix(attrib, "localuser=", 1) != عدم ||
		    strprefix(attrib, "localnetwork=", 1) != عدم ||
		    strprefix(attrib, "version=", 1) != عدم ||
		    strprefix(attrib, "tagged=", 1) != عدم ||
		    strprefix(attrib, "command=", 1) != عدم ||
		    strprefix(attrib, "exec=", 1) != عدم) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وإلا إذا ((arg = argv_بل(acp, avp)) == عدم) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			پایله = -1;
			اذهب بهر;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		إذا (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = عدم;
		إذا (arg == عدم || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			پایله = -1;
			اذهب بهر;
		}
		إذا (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = سمون_hostname(host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = سمون_hostname(original_host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = سمون_نمونه_list(ruser, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = سمون_نمونه_list(pw->pw_name, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "localnetwork") == 0) {
			إذا (addr_سمون_cidr_list(عدم, arg) == -1) {
				/* Error already printed */
				پایله = -1;
				اذهب بهر;
			}
			r = check_سمون_ifaddrs(arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = سمون_نمونه_list(SSH_RELEASE, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->نښان == عدم ? "" :
			    options->نښان);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    سمون_نمونه_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == عدم ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    سمون_نمونه_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "sessiontype") == 0) {
			إذا (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			وإلا إذا (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			وإلا إذا (remote_command != عدم &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			وإلا
				criteria = xstrdup("shell");
			r = سمون_نمونه_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا إذا (strcasecmp(attrib, "exec") == 0) {
			إذا ((cmd = expand_سمون_exec_or_include_لار(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == عدم) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			إذا (پایله != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				حرر(cmd);
				اذهب بل;
			}
			r = execute_دننه_shell(cmd);
			إذا (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			حرر(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			إذا (r == (negate ? 1 : 0))
				this_پایله = پایله = 0;
		} وإلا {
			error("Unsupported Match attribute %s", attrib);
			پایله = -1;
			اذهب بهر;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_پایله ? "": "not ", oattrib,
		    criteria == عدم ? "" : " \"",
		    criteria == عدم ? "" : criteria,
		    criteria == عدم ? "" : "\"");
 بل:
		حرر(criteria);
		حرر(oattrib);
		oattrib = attrib = عدم;
	}
	إذا (ځانګړتیاوې == 0) {
		error("One or more attributes required for Match");
		پایله = -1;
		اذهب بهر;
	}
 بهر:
	إذا (پایله != -1)
		debug2("match %sfound", پایله ? "" : "not ");
	حرر(oattrib);
	حرر(host);
	أرجع پایله;
}

/* Remove environment variable by pattern */
ساكن فراغ
rm_env(Options *options, ثابت حرف *arg, ثابت حرف *filename, صحيح linenum)
{
	u_int i, j, onum_send_env = options->عدد_send_env;

	/* Remove an environment variable */
	لكل (i = 0; i < options->عدد_send_env; ) {
		إذا (!سمون_نمونه(options->send_env[i], arg + 1)) {
			i++;
			استمر;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		حرر(options->send_env[i]);
		options->send_env[i] = عدم;
		لكل (j = i; j < options->عدد_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = عدم;
		}
		options->عدد_send_env--;
		/* NB. don't increment i */
	}
	إذا (onum_send_env != options->عدد_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->عدد_send_env,
		    حجم(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ساكن OpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename, صحيح linenum,
    ثابت حرف *ignored_unknown)
{
	صحيح i;

	لكل (i = 0; keywords[i].name; i++)
		إذا (strcmp(cp, keywords[i].name) == 0)
			أرجع keywords[i].opcode;
	إذا (ignored_unknown != عدم &&
	    سمون_نمونه_list(cp, ignored_unknown, 1) == 1)
		أرجع oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	أرجع oBadOption;
}

ساكن فراغ
free_canon_cnames(بنية allowed_cname *cnames, u_int n)
{
	u_int i;

	إذا (cnames == عدم || n == 0)
		أرجع;
	لكل (i = 0; i < n; i++) {
		حرر(cnames[i].سرچینه_list);
		حرر(cnames[i].موخه_list);
	}
	حرر(cnames);
}

/* Multistate option parsing */
بنية multistate {
	حرف *کلی;
	صحيح ارزښت;
};
ساكن ثابت بنية multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_compression[] = {
#که_تعریف_شوی WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#د_که_پای
	{ "no",				COMP_NONE },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ عدم, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ساكن ثابت بنية multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ عدم, -1 }
};

ساكن صحيح
parse_multistate_ارزښت(ثابت حرف *arg, ثابت حرف *filename, صحيح linenum,
    ثابت بنية multistate *multistate_ptr)
{
	صحيح i;

	إذا (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		أرجع -1;
	}
	لكل (i = 0; multistate_ptr[i].کلی != عدم; i++) {
		إذا (strcasecmp(arg, multistate_ptr[i].کلی) == 0)
			أرجع multistate_ptr[i].ارزښت;
	}
	أرجع -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
صحيح
process_config_کرښه(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *کرښه,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags)
{
	أرجع process_config_کرښه_ژوروالی(options, pw, host, original_host,
	    remote_command, کرښه, filename, linenum, activep, flags, عدم, 0);
}

#تعریف_کړه WHITESPACE " \t\r\n"
ساكن صحيح
process_config_کرښه_ژوروالی(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *کرښه,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح ژوروالی)
{
	حرف *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	حرف **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	صحيح r, oactive, negated, opcode, *intptr, ارزښت, value2, cmdline = 0;
	صحيح remotefwd, dynamicfwd, ca_only = 0, وموندل = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	اوږد اوږد val64;
	اندازه_t len;
	بنية Forward fwd;
	ثابت بنية multistate *multistate_ptr;
	glob_t gl;
	ثابت حرف *errstr;
	حرف **oav = عدم, **av;
	صحيح oac = 0, ac;
	صحيح ret = -1;
	بنية allowed_cname *cnames = عدم;
	u_int ncnames = 0;
	حرف **strs = عدم; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	إذا (activep == عدم) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	إذا ((len = مزي_اوږدوالی(کرښه)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		إذا (strchr(WHITESPACE "\f", کرښه[len]) == عدم)
			اكسر;
		کرښه[len] = '\0';
	}

	str = کرښه;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	إذا ((keyword = strdelim(&str)) == عدم)
		أرجع 0;
	/* Ignore leading whitespace. */
	إذا (*keyword == '\0')
		keyword = strdelim(&str);
	إذا (keyword == عدم || !*keyword || *keyword == '\n' || *keyword == '#')
		أرجع 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	إذا (str != عدم)
		str += strspn(str, WHITESPACE);
	إذا (str == عدم || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		أرجع -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	إذا (argv_وېشل(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	بدل (opcode) {
	حالة oBadOption:
		/* don't panic, but count bad options */
		اذهب بهر;
	حالة oIgnore:
		argv_consume(&ac);
		اكسر;
	حالة oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;
	حالة oConnectTimeout:
		intptr = &options->connection_timeout;
parse_وخت:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (strcmp(arg, "none") == 0)
			ارزښت = -1;
		وإلا إذا ((ارزښت = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			اذهب بهر;
		}

		ارزښت = -1;
		multistate_ptr = multistate_flag;
		لكل (i = 0; multistate_ptr[i].کلی != عدم; i++) {
			إذا (strcasecmp(arg, multistate_ptr[i].کلی) == 0) {
				ارزښت = multistate_ptr[i].ارزښت;
				اكسر;
			}
		}
		إذا (ارزښت != -1) {
			إذا (*activep && *intptr == -1)
				*intptr = ارزښت;
			اكسر;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		إذا (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_لار;
		اذهب parse_agent_لار;

	حالة oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_بل(&ac, &av);
		إذا ((ارزښت = parse_multistate_ارزښت(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		اذهب parse_flag;

	حالة oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		اذهب parse_وخت;

	حالة oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		اذهب parse_flag;

	حالة oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		اذهب parse_flag;

	حالة oPasswordAuthentication:
		intptr = &options->password_authentication;
		اذهب parse_flag;

	حالة oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		اذهب parse_flag;

	حالة oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		اذهب parse_string;

	حالة oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		اذهب parse_multistate;

	حالة oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		اذهب parse_flag;

	حالة oGssAuthentication:
		intptr = &options->gss_authentication;
		اذهب parse_flag;

	حالة oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		اذهب parse_flag;

	حالة o_Batch_ډېرپېښ:
		intptr = &options->batch_ډېرپېښ;
		اذهب parse_flag;

	حالة oCheckHostIP:
		intptr = &options->check_host_ip;
		اذهب parse_flag;

	حالة o_Verify_Host_کلی_DNS:
		intptr = &options->verify_host_کلی_dns;
		multistate_ptr = multistate_yesnoask;
		اذهب parse_multistate;

	حالة o_Strict_Host_کلی_Checking:
		intptr = &options->strict_host_کلی_checking;
		multistate_ptr = multistate_strict_hostkey;
		اذهب parse_multistate;

	حالة oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		اذهب parse_multistate;

	حالة oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		اذهب parse_multistate;

	حالة oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		اذهب parse_flag;

	حالة o_شمېره_د_Password_Prompts:
		intptr = &options->شمېره_د_password_prompts;
		اذهب parse_int;

	حالة o_Rekey_حد:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			اذهب بهر;
		}
		إذا (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			إذا (لټون_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				اذهب بهر;
			}
			إذا (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				اذهب بهر;
			}
		}
		إذا (*activep && options->rekey_حد == -1)
			options->rekey_حد = val64;
		إذا (ac != 0) { /* optional rekey interval present */
			إذا (strcmp(av[0], "none") == 0) {
				(فراغ)argv_بل(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_وخت;
		}
		اكسر;

	حالة o_بې_اغېزه_عنصر_File:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep) {
			intptr = &options->عدد_بې_اغېزه_عنصر_files;
			إذا (*intptr >= SSH_MAX_بې_اغېزه_عنصر_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_بې_اغېزه_عنصر_FILES);
				اذهب بهر;
			}
			جمع_کړه_بې_اغېزه_عنصر_file(options, عدم,
			    arg, flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oCertificateFile:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep) {
			intptr = &options->عدد_certificate_files;
			إذا (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				اذهب بهر;
			}
			جمع_کړه_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oXAuthLocation:
		charptr=&options->xauth_location;
		اذهب parse_string;

	حالة oUser:
		charptr = &options->user;
parse_string:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة o_Global_معلوم_Hosts_File:
		cpptr = (حرف **)&options->system_hostfiles;
		uintptr = &options->عدد_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		ارزښت = *uintptr == 0; /* was array empty when we started? */
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بهر;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
			}
			i++;
			إذا (*activep && ارزښت) {
				إذا ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					اذهب بهر;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		اكسر;

	حالة o_User_معلوم_Hosts_File:
		cpptr = (حرف **)&options->user_hostfiles;
		uintptr = &options->عدد_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		اذهب parse_char_array;

	حالة oHostname:
		charptr = &options->hostname;
		اذهب parse_string;

	حالة o_نښان:
		charptr = &options->نښان;
		اذهب parse_string;

	حالة o_Host_کلی_Alias:
		charptr = &options->host_کلی_alias;
		اذهب parse_string;

	حالة oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		اذهب parse_string;

	حالة o_Bind_پته:
		charptr = &options->bind_پته;
		اذهب parse_string;

	حالة oBindInterface:
		charptr = &options->bind_interface;
		اذهب parse_string;

	حالة oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		اذهب parse_string;

	حالة o_Security_کلی_Provider:
		charptr = &options->sk_provider;
		اذهب parse_string;

	حالة o_معلوم_Hosts_Command:
		charptr = &options->معلوم_hosts_command;
		اذهب parse_command;

	حالة oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		إذا (str == عدم) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		len = strspn(str, WHITESPACE "=");
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة oProxyJump:
		إذا (str == عدم) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		إذا (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			اذهب بهر;
		}
		argv_consume(&ac);
		اكسر;

	حالة o_پورټ:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		ارزښت = a2port(arg);
		إذا (ارزښت <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (*activep && options->پورټ == -1)
			options->پورټ = ارزښت;
		اكسر;

	حالة oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_بل(&ac, &av);
		إذا ((errstr = atoi_err(arg, &ارزښت)) != عدم) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة oCiphers:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*activep && options->ciphers == عدم)
			options->ciphers = xstrdup(arg);
		اكسر;

	حالة oMacs:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*activep && options->macs == عدم)
			options->macs = xstrdup(arg);
		اكسر;

	حالة oKexAlgorithms:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*arg != '-' &&
		    !kex_نومونه_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*activep && options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة o_Host_کلی_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*arg != '-' &&
		    !sshkey_نومونه_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		اذهب parse_pubkey_algos;

	حالة oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_بل(&ac, &av);
		ارزښت = log_level_شمېره(arg);
		إذا (ارزښت == SYSLOG_LEVEL_NOT_سېټ) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_سېټ)
			*log_level_ptr = (LogLevel) ارزښت;
		اكسر;

	حالة oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_بل(&ac, &av);
		ارزښت = log_facility_شمېره(arg);
		إذا (ارزښت == SYSLOG_FACILITY_NOT_سېټ) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب بهر;
		}
		إذا (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ارزښت;
		اكسر;

	حالة oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->عدد_log_verbose;
		i = 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بهر;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
			}
			i++;
			إذا (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, حجم(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		اكسر;

	حالة oLocalForward:
	حالة oRemoteForward:
	حالة oDynamicForward:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		إذا (!dynamicfwd) {
			arg2 = argv_بل(&ac, &av);
			إذا (arg2 == عدم || *arg2 == '\0') {
				إذا (remotefwd)
					dynamicfwd = 1;
				وإلا {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					اذهب بهر;
				}
			} وإلا {
				/* construct a string for parse_forward */
				snprintf(fwdarg, حجم(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		إذا (dynamicfwd)
			strlcpy(fwdarg, arg, حجم(fwdarg));

		إذا (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			اذهب بهر;
		}

		إذا (*activep) {
			إذا (remotefwd) {
				جمع_کړه_remote_forward(options, &fwd);
			} وإلا {
				جمع_کړه_local_forward(options, &fwd);
			}
		}
		اكسر;

	حالة oPermitRemoteOpen:
		uintptr = &options->عدد_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		وموندل = *uintptr == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			إذا (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					حرر(arg2);
					اذهب بهر;
				}
			} وإلا {
				p = hpdelim(&arg);
				إذا (p == عدم) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				إذا (arg == عدم || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		إذا (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		إذا (وموندل && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oClearAllForwardings:
		intptr = &options->clear_forwardings;
		اذهب parse_flag;

	حالة oHost:
		إذا (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			اذهب بهر;
		}
		*activep = 0;
		arg2 = عدم;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بهر;
			}
			إذا ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				اكسر;
			}
			negated = *arg == '!';
			إذا (negated)
				arg++;
			إذا (سمون_نمونه(host, arg)) {
				إذا (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					اكسر;
				}
				إذا (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		إذا (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		اكسر;

	حالة o_سمون:
		إذا (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			اذهب بهر;
		}
		ارزښت = سمون_cfg_کرښه(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		إذا (ارزښت < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			اذهب بهر;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : ارزښت;
		اكسر;

	حالة oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (strcmp(arg, "none") == 0)
			ارزښت = SSH_ESCAPECHAR_NONE;
		وإلا إذا (arg[1] == '\0')
			ارزښت = (u_char) arg[0];
		وإلا إذا (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			ارزښت = (u_char) arg[1] & 31;
		وإلا {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة o_پته_Family:
		intptr = &options->پته_family;
		multistate_ptr = multistate_addressfamily;
		اذهب parse_multistate;

	حالة oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		اذهب parse_flag;

	حالة oIdentitiesOnly:
		intptr = &options->identities_only;
		اذهب parse_flag;

	حالة oServerAliveInterval:
		intptr = &options->server_alive_interval;
		اذهب parse_وخت;

	حالة o_Server_Alive_شمېر_Max:
		intptr = &options->server_alive_شمېر_max;
		اذهب parse_int;

	حالة oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') != عدم) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				اذهب بهر;
			}
			وموندل = 1;
			إذا (!*activep)
				استمر;
			إذا (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				استمر;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->عدد_send_env, arg);
		}
		إذا (!وموندل) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة o_سېټ_Env:
		وموندل = options->عدد_setenv == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (strchr(arg, '=') == عدم) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				اذهب بهر;
			}
			إذا (lookup_setenv_دننه_list(arg, strs, nstrs) != عدم) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				استمر;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (وموندل && *activep) {
			options->setenv = strs;
			options->عدد_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة o_Control_لار:
		charptr = &options->control_لار;
		اذهب parse_string;

	حالة oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		اذهب parse_multistate;

	حالة oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			اذهب بهر;
		}
		ارزښت = 0;
		value2 = 0;	/* timeout */
		إذا (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			ارزښت = 0;
		وإلا إذا (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			ارزښت = 1;
		وإلا إذا ((value2 = convtime(arg)) >= 0)
			ارزښت = 1;
		وإلا {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1) {
			*intptr = ارزښت;
			options->control_persist_timeout = value2;
		}
		اكسر;

	حالة o_Hash_معلوم_Hosts:
		intptr = &options->hash_معلوم_hosts;
		اذهب parse_flag;

	حالة oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		اذهب parse_multistate;

	حالة oTunnelDevice:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		ارزښت = a2tun(arg, &value2);
		إذا (ارزښت == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && options->tun_local == -1) {
			options->tun_local = ارزښت;
			options->tun_remote = value2;
		}
		اكسر;

	حالة oLocalCommand:
		charptr = &options->local_command;
		اذهب parse_command;

	حالة oPermitLocalCommand:
		intptr = &options->permit_local_command;
		اذهب parse_flag;

	حالة oRemoteCommand:
		charptr = &options->remote_command;
		اذهب parse_command;

	حالة o_Visual_Host_کلی:
		intptr = &options->visual_host_کلی;
		اذهب parse_flag;

	حالة oInclude:
		إذا (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			اذهب بهر;
		}
		ارزښت = 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بهر;
			}
			/* Expand %tokens and environment variables */
			إذا ((p = expand_سمون_exec_or_include_لار(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == عدم) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				استمر;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			إذا (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				اذهب بهر;
			}
			إذا (!لار_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" لار_SSH_USER_DIR : SSHDIR, p);
			} وإلا {
				arg2 = xstrdup(p);
			}
			حرر(p);
			memset(&gl, 0, حجم(gl));
			r = glob(arg2, GLOB_TILDE, عدم, &gl);
			إذا (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				حرر(arg2);
				استمر;
			} وإلا إذا (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				اذهب بهر;
			}
			حرر(arg2);
			oactive = *activep;
			لكل (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], ژوروالی,
				    oactive ? "" : " (parse only)");
				r = read_config_file_ژوروالی(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, ژوروالی + 1);
				إذا (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					اذهب بهر;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				إذا (r != 1)
					ارزښت = -1;
			}
			globfree(&gl);
		}
		إذا (ارزښت != 0)
			ret = ارزښت;
		اكسر;

	حالة oIPQoS:
		arg = argv_بل(&ac, &av);
		إذا ((ارزښت = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (ارزښت == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ارزښت = لوی_عدد;
		}
		arg = argv_بل(&ac, &av);
		إذا (arg == عدم)
			value2 = ارزښت;
		وإلا إذا ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = لوی_عدد;
		}
		إذا (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ارزښت;
			options->ip_qos_bulk = value2;
		}
		اكسر;

	حالة oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		اذهب parse_multistate;

	حالة oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		اذهب parse_multistate;

	حالة oStdinNull:
		intptr = &options->stdin_null;
		اذهب parse_flag;

	حالة oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		اذهب parse_flag;

	حالة oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		اذهب parse_string;

	حالة oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		اذهب parse_flag;

	حالة oCanonicalDomains:
		وموندل = options->عدد_canonical_domains == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
			}
			إذا (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				اذهب بهر;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (وموندل && *activep) {
			options->canonical_domains = strs;
			options->عدد_canonical_domains = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oCanonicalizePermittedCNAMEs:
		وموندل = options->عدد_permitted_cnames == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
				arg2 = "";
			} وإلا إذا (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} وإلا {
				lowercase(arg);
				إذا ((arg2 = strchr(arg, ':')) == عدم ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					اذهب بهر;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    حجم(*cnames));
			cnames[ncnames].سرچینه_list = xstrdup(arg);
			cnames[ncnames].موخه_list = xstrdup(arg2);
			ncnames++;
		}
		إذا (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (وموندل && *activep) {
			options->permitted_cnames = cnames;
			options->عدد_permitted_cnames = ncnames;
			cnames = عدم; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		اكسر;

	حالة oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		اذهب parse_multistate;

	حالة oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		اذهب parse_int;

	حالة oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		اذهب parse_flag;

	حالة o_بهیر_Local_Bind_ماسک:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			اذهب بهر;
		}
		/* Parse mode in octal format */
		ارزښت = strtol(arg, &endofnumber, 8);
		إذا (arg == endofnumber || ارزښت < 0 || ارزښت > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			اذهب بهر;
		}
		إذا (*activep &&
		    options->fwd_opts.streamlocal_bind_ماسک == (ډېرپېښ_t)-1)
			options->fwd_opts.streamlocal_bind_ماسک = (ډېرپېښ_t)ارزښت;
		اكسر;

	حالة o_بهیر_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة o_Revoked_Host_کلیګانې:
		uintptr = &options->عدد_revoked_host_کلیګانې;
		cppptr = &options->revoked_host_کلیګانې;
		وموندل = *uintptr == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بهر;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (وموندل && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا ((ارزښت = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		اذهب parse_multistate;

	حالة oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة o_جمع_کړه_کلیګانې_منزل_Agent:
		arg = argv_بل(&ac, &av);
		arg2 = argv_بل(&ac, &av);
		ارزښت = parse_multistate_ارزښت(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		إذا (ارزښت == 3 && arg2 != عدم) {
			/* allow "AddKeysToAgent confirm 5m" */
			إذا ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				اذهب بهر;
			}
		} وإلا إذا (ارزښت == -1 && arg2 == عدم) {
			إذا ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				اذهب بهر;
			}
			ارزښت = 1; /* yes */
		} وإلا إذا (ارزښت == -1 || arg2 != عدم) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep && options->جمع_کړه_کلیګانې_منزل_agent == -1) {
			options->جمع_کړه_کلیګانې_منزل_agent = ارزښت;
			options->جمع_کړه_کلیګانې_منزل_agent_lifespan = value2;
		}
		اكسر;

	حالة o_بې_اغېزه_عنصر_Agent:
		charptr = &options->بې_اغېزه_عنصر_agent;
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
  parse_agent_لار:
		/* Extra validation if the string represents an env var. */
		إذا ((arg2 = dollar_expand(&r, arg)) == عدم || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			اذهب بهر;
		}
		حرر(arg2);
		/* check for legacy environment format */
		إذا (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			اذهب بهر;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		اذهب parse_flag;

	حالة oRequiredRSASize:
		intptr = &options->required_rsa_اندازه;
		اذهب parse_int;

	حالة oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		اذهب parse_multistate;

	حالة oObscureKeystrokeTiming:
		ارزښت = -1;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			إذا (ارزښت != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				اذهب بهر;
			}
			إذا (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				ارزښت = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			وإلا إذا (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				ارزښت = 0;
			وإلا إذا (مزي_پرتله(arg, "interval:", 9) == 0) {
				إذا ((errstr = atoi_err(arg + 9,
				    &ارزښت)) != عدم) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					اذهب بهر;
				}
				إذا (ارزښت <= 0 || ارزښت > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					اذهب بهر;
				}
			} وإلا {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				اذهب بهر;
			}
		}
		إذا (ارزښت == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			اذهب بهر;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		إذا (*activep && *intptr == -1)
			*intptr = ارزښت;
		اكسر;

	حالة oChannelTimeout:
		وموندل = options->عدد_channel_timeouts == 0;
		طالما ((arg = argv_بل(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بهر;
				}
			} وإلا إذا (parse_نمونه_interval(arg,
			    عدم, عدم) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (وموندل && *activep) {
			options->channel_timeouts = strs;
			options->عدد_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة o_نسخه_Addendum:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		إذا ((arg = strchr(کرښه, '#')) != عدم) {
			*arg = '\0';
			rtrim(کرښه);
		}
		إذا (*activep && options->نسخه_addendum == عدم) {
			إذا (strcasecmp(str + len, "none") == 0)
				options->نسخه_addendum = xstrdup("");
			وإلا
				options->نسخه_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة oRefuseConnection:
		arg = argv_بل(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب بهر;
		}
		إذا (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		اكسر;

	حالة oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;

	حالة oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;

	افتراضي:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		اذهب بهر;
	}

	/* Check that there is no garbage at end of line. */
	إذا (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		اذهب بهر;
	}

	/* success */
	ret = 0;
 بهر:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, عدم, nstrs);
	argv_free(oav, oac);
	أرجع ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
صحيح
read_config_file(ثابت حرف *filename, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, Options *options, صحيح flags,
    صحيح *want_final_pass)
{
	صحيح فعال = 1;

	أرجع read_config_file_ژوروالی(filename, pw, host, original_host,
	    remote_command, options, flags, &فعال, want_final_pass, 0);
}

#تعریف_کړه READCONF_MAX_ژوروالی	16
ساكن صحيح
read_config_file_ژوروالی(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح ژوروالی)
{
	FILE *f;
	حرف *کرښه = عدم;
	اندازه_t linesize = 0;
	صحيح linenum;
	صحيح bad_options = 0;

	إذا (ژوروالی < 0 || ژوروالی > READCONF_MAX_ژوروالی)
		fatal("Too many recursive configuration includes");

	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع 0;

	إذا (flags & SSHCONF_CHECKPERM) {
		بنية stat sb;

		إذا (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		إذا (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	طالما (getline(&کرښه, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		إذا (process_config_کرښه_ژوروالی(options, pw, host, original_host,
		    remote_command, کرښه, filename, linenum, activep, flags,
		    want_final_pass, ژوروالی) != 0)
			bad_options++;
	}
	حرر(کرښه);
	fclose(f);
	إذا (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	أرجع 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
صحيح
option_clear_or_none(ثابت حرف *o)
{
	أرجع o == عدم || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
صحيح
config_has_permitted_cnames(Options *options)
{
	إذا (options->عدد_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].سرچینه_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].موخه_list, "") == 0)
		أرجع 0;
	أرجع options->عدد_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

فراغ
initialize_options(Options * options)
{
	memset(options, 'X', حجم(*options));
	options->host_arg = عدم;
	options->forward_agent = -1;
	options->forward_agent_sock_لار = عدم;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = عدم;
	options->stdio_forward_پورټ = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = عدم;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_ماسک = (ډېرپېښ_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = عدم;
	options->hostbased_authentication = -1;
	options->batch_ډېرپېښ = -1;
	options->check_host_ip = -1;
	options->strict_host_کلی_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->پورټ = -1;
	options->پته_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->شمېره_د_password_prompts = -1;
	options->ciphers = عدم;
	options->macs = عدم;
	options->kex_algorithms = عدم;
	options->hostkeyalgorithms = عدم;
	options->ca_sign_algorithms = عدم;
	options->عدد_بې_اغېزه_عنصر_files = 0;
	memset(options->بې_اغېزه_عنصر_کلیګانې, 0, حجم(options->بې_اغېزه_عنصر_کلیګانې));
	options->عدد_certificate_files = 0;
	memset(options->certificates, 0, حجم(options->certificates));
	options->hostname = عدم;
	options->host_کلی_alias = عدم;
	options->proxy_command = عدم;
	options->jump_user = عدم;
	options->jump_host = عدم;
	options->jump_پورټ = -1;
	options->jump_extra = عدم;
	options->user = عدم;
	options->escape_char = -1;
	options->عدد_system_hostfiles = 0;
	options->عدد_user_hostfiles = 0;
	options->local_forwards = عدم;
	options->عدد_local_forwards = 0;
	options->remote_forwards = عدم;
	options->عدد_remote_forwards = 0;
	options->permitted_remote_opens = عدم;
	options->عدد_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_سېټ;
	options->log_level = SYSLOG_LEVEL_NOT_سېټ;
	options->عدد_log_verbose = 0;
	options->log_verbose = عدم;
	options->preferred_authentications = عدم;
	options->bind_پته = عدم;
	options->bind_interface = عدم;
	options->pkcs11_provider = عدم;
	options->sk_provider = عدم;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_حد = -1;
	options->rekey_interval = -1;
	options->verify_host_کلی_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_شمېر_max = -1;
	options->send_env = عدم;
	options->عدد_send_env = 0;
	options->setenv = عدم;
	options->عدد_setenv = 0;
	options->control_لار = عدم;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_معلوم_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = عدم;
	options->permit_local_command = -1;
	options->remote_command = عدم;
	options->جمع_کړه_کلیګانې_منزل_agent = -1;
	options->جمع_کړه_کلیګانې_منزل_agent_lifespan = -1;
	options->بې_اغېزه_عنصر_agent = عدم;
	options->visual_host_کلی = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = عدم;
	options->عدد_canonical_domains = 0;
	options->عدد_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_کلیګانې = عدم;
	options->عدد_revoked_host_کلیګانې = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = عدم;
	options->pubkey_accepted_algos = عدم;
	options->معلوم_hosts_command = عدم;
	options->required_rsa_اندازه = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->نښان = عدم;
	options->channel_timeouts = عدم;
	options->عدد_channel_timeouts = 0;
	options->نسخه_addendum = عدم;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
فراغ
fill_default_options_for_canonicalization(Options *options)
{
	إذا (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	إذا (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	إذا (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
صحيح
fill_default_options(Options * options)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_کلی, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_کلی, *def_sig;
	صحيح ret = -1, r;

	إذا (options->forward_agent == -1)
		options->forward_agent = 0;
	إذا (options->forward_x11 == -1)
		options->forward_x11 = 0;
	إذا (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	إذا (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	إذا (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != عدم ? 1 : 0;
	إذا (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != عدم ? 1 : 0;
	إذا (options->clear_forwardings == 1)
		clear_forwardings(options);

	إذا (options->xauth_location == عدم)
		options->xauth_location = xstrdup(لار_XAUTH);
	إذا (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	إذا (options->fwd_opts.streamlocal_bind_ماسک == (ډېرپېښ_t)-1)
		options->fwd_opts.streamlocal_bind_ماسک = 0177;
	إذا (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	إذا (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	إذا (options->gss_authentication == -1)
		options->gss_authentication = 0;
	إذا (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	إذا (options->password_authentication == -1)
		options->password_authentication = 1;
	إذا (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	إذا (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	إذا (options->batch_ډېرپېښ == -1)
		options->batch_ډېرپېښ = 0;
	إذا (options->check_host_ip == -1)
		options->check_host_ip = 0;
	إذا (options->strict_host_کلی_checking == -1)
		options->strict_host_کلی_checking = SSH_STRICT_HOSTKEY_ASK;
	إذا (options->compression == -1)
		options->compression = 0;
	إذا (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	إذا (options->پورټ == -1)
		options->پورټ = 0;	/* Filled in ssh_connect. */
	إذا (options->پته_family == -1)
		options->پته_family = AF_UNSPEC;
	إذا (options->connection_attempts == -1)
		options->connection_attempts = 1;
	إذا (options->شمېره_د_password_prompts == -1)
		options->شمېره_د_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	إذا (options->جمع_کړه_کلیګانې_منزل_agent == -1) {
		options->جمع_کړه_کلیګانې_منزل_agent = 0;
		options->جمع_کړه_کلیګانې_منزل_agent_lifespan = 0;
	}
	إذا (options->عدد_بې_اغېزه_عنصر_files == 0) {
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/", لار_SSH_CLIENT_ID_RSA, 0);
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/", لار_SSH_CLIENT_ID_ECDSA, 0);
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/",
		    لار_SSH_CLIENT_ID_ECDSA_SK, 0);
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/",
		    لار_SSH_CLIENT_ID_ED25519, 0);
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/",
		    لار_SSH_CLIENT_ID_ED25519_SK, 0);
		جمع_کړه_بې_اغېزه_عنصر_file(options, "~/",
		    لار_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	إذا (options->escape_char == -1)
		options->escape_char = '~';
	إذا (options->عدد_system_hostfiles == 0) {
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(لار_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(لار_SSH_SYSTEM_HOSTFILE2);
	}
	إذا (options->update_hostkeys == -1) {
		إذا (options->verify_host_کلی_dns <= 0 &&
		    (options->عدد_user_hostfiles == 0 ||
		    (options->عدد_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], لار_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		وإلا
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	إذا (options->عدد_user_hostfiles == 0) {
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(لار_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(لار_SSH_USER_HOSTFILE2);
	}
	إذا (options->log_level == SYSLOG_LEVEL_NOT_سېټ)
		options->log_level = SYSLOG_LEVEL_INFO;
	إذا (options->log_facility == SYSLOG_FACILITY_NOT_سېټ)
		options->log_facility = SYSLOG_FACILITY_USER;
	إذا (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	إذا (options->identities_only == -1)
		options->identities_only = 0;
	إذا (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	إذا (options->rekey_حد == -1)
		options->rekey_حد = 0;
	إذا (options->rekey_interval == -1)
		options->rekey_interval = 0;
	إذا (options->verify_host_کلی_dns == -1)
		options->verify_host_کلی_dns = 0;
	إذا (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	إذا (options->server_alive_شمېر_max == -1)
		options->server_alive_شمېر_max = 3;
	إذا (options->control_master == -1)
		options->control_master = 0;
	إذا (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	إذا (options->hash_معلوم_hosts == -1)
		options->hash_معلوم_hosts = 0;
	إذا (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	إذا (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	إذا (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	إذا (options->permit_local_command == -1)
		options->permit_local_command = 0;
	إذا (options->visual_host_کلی == -1)
		options->visual_host_کلی = 0;
	إذا (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	إذا (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	إذا (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	إذا (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	إذا (options->stdin_null == -1)
		options->stdin_null = 0;
	إذا (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	إذا (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	إذا (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	إذا (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	إذا (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	إذا (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#که_تعریف_شوی ENABLE_SK_دننی
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
#وإلا
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#د_که_پای
	إذا (options->required_rsa_اندازه == -1)
		options->required_rsa_اندازه = SSH_RSA_MINIMUM_MODULUS_اندازه;
	إذا (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	إذا (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	إذا (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_کلی = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = سمون_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = سمون_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = سمون_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_کلی = سمون_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلی);
	def_sig = سمون_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#تعریف_کړه ASSEMBLE(what, defaults, all) \
	افعل { \
		إذا ((r = kex_assemble_نومونه(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			اذهب fail; \
		} \
	} طالما (0)
	options->kex_algorithms_سېټ = options->kex_algorithms != عدم;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_کلی, all_کلی);
	ASSEMBLE(pubkey_accepted_algos, def_کلی, all_کلی);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#تعریف_لغوه ASSEMBLE

#تعریف_کړه CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#تعریف_کړه CLEAR_ON_NONE_ARRAY(v, nv, none) \
	افعل { \
		إذا (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			حرر(options->v[0]); \
			حرر(options->v); \
			options->v = عدم; \
			options->nv = 0; \
		} \
	} طالما (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_لار);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->معلوم_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, عدد_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_کلیګانې, عدد_revoked_host_کلیګانې, "none");
#تعریف_لغوه CLEAR_ON_NONE
#تعریف_لغوه CLEAR_ON_NONE_ARRAY
	إذا (options->jump_host != عدم &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_پورټ == 0 && options->jump_user == عدم) {
		حرر(options->jump_host);
		options->jump_host = عدم;
	}
	إذا (options->عدد_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		حرر(options->permitted_cnames[0].سرچینه_list);
		حرر(options->permitted_cnames[0].موخه_list);
		memset(options->permitted_cnames, '\0',
		    حجم(*options->permitted_cnames));
		options->عدد_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	حرر(all_cipher);
	حرر(all_mac);
	حرر(all_kex);
	حرر(all_کلی);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_کلی);
	حرر(def_sig);
	أرجع ret;
}

فراغ
free_options(Options *o)
{
	صحيح i;

	إذا (o == عدم)
		أرجع;

#تعریف_کړه FREE_ARRAY(type, n, a) \
	افعل { \
		type _i; \
		لكل (_i = 0; _i < (n); _i++) \
			حرر((a)[_i]); \
	} طالما (0)

	حرر(o->forward_agent_sock_لار);
	حرر(o->xauth_location);
	FREE_ARRAY(u_int, o->عدد_log_verbose, o->log_verbose);
	حرر(o->log_verbose);
	حرر(o->ciphers);
	حرر(o->macs);
	حرر(o->hostkeyalgorithms);
	حرر(o->kex_algorithms);
	حرر(o->ca_sign_algorithms);
	حرر(o->hostname);
	حرر(o->host_کلی_alias);
	حرر(o->proxy_command);
	حرر(o->user);
	FREE_ARRAY(u_int, o->عدد_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->عدد_user_hostfiles, o->user_hostfiles);
	حرر(o->preferred_authentications);
	حرر(o->bind_پته);
	حرر(o->bind_interface);
	حرر(o->pkcs11_provider);
	حرر(o->sk_provider);
	لكل (i = 0; i < o->عدد_بې_اغېزه_عنصر_files; i++) {
		حرر(o->بې_اغېزه_عنصر_files[i]);
		sshkey_free(o->بې_اغېزه_عنصر_کلیګانې[i]);
	}
	لكل (i = 0; i < o->عدد_certificate_files; i++) {
		حرر(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	حرر(o->بې_اغېزه_عنصر_agent);
	لكل (i = 0; i < o->عدد_local_forwards; i++) {
		حرر(o->local_forwards[i].listen_host);
		حرر(o->local_forwards[i].listen_لار);
		حرر(o->local_forwards[i].connect_host);
		حرر(o->local_forwards[i].connect_لار);
	}
	حرر(o->local_forwards);
	لكل (i = 0; i < o->عدد_remote_forwards; i++) {
		حرر(o->remote_forwards[i].listen_host);
		حرر(o->remote_forwards[i].listen_لار);
		حرر(o->remote_forwards[i].connect_host);
		حرر(o->remote_forwards[i].connect_لار);
	}
	حرر(o->remote_forwards);
	حرر(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->عدد_send_env, o->send_env);
	حرر(o->send_env);
	FREE_ARRAY(u_int, o->عدد_setenv, o->setenv);
	حرر(o->setenv);
	حرر(o->control_لار);
	حرر(o->local_command);
	حرر(o->remote_command);
	FREE_ARRAY(صحيح, o->عدد_canonical_domains, o->canonical_domains);
	لكل (i = 0; i < o->عدد_permitted_cnames; i++) {
		حرر(o->permitted_cnames[i].سرچینه_list);
		حرر(o->permitted_cnames[i].موخه_list);
	}
	FREE_ARRAY(u_int, o->عدد_revoked_host_کلیګانې, o->revoked_host_کلیګانې);
	حرر(o->revoked_host_کلیګانې);
	حرر(o->hostbased_accepted_algos);
	حرر(o->pubkey_accepted_algos);
	حرر(o->jump_user);
	حرر(o->jump_host);
	حرر(o->jump_extra);
	حرر(o->ignored_unknown);
	explicit_bzero(o, حجم(*o));
#تعریف_لغوه FREE_ARRAY
}

بنية fwdarg {
	حرف *arg;
	صحيح ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ساكن صحيح
parse_fwd_ډګر(حرف **p, بنية fwdarg *fwd)
{
	حرف *ep, *cp = *p;
	صحيح ispath = 0;

	إذا (*cp == '\0') {
		*p = عدم;
		أرجع -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	إذا (*cp == '[') {
		/* find matching ']' */
		لكل (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			إذا (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		إذا (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			أرجع -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		إذا (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		أرجع 0;
	}

	لكل (cp = *p; *cp != '\0'; cp++) {
		بدل (*cp) {
		حالة '\\':
			memmove(cp, cp + 1, مزي_اوږدوالی(cp + 1) + 1);
			إذا (*cp == '\0')
				أرجع -1;
			اكسر;
		حالة '/':
			ispath = 1;
			اكسر;
		حالة ':':
			*cp++ = '\0';
			اذهب بشپړ;
		}
	}
بشپړ:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	أرجع 0;
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
صحيح
parse_forward(بنية Forward *fwd, ثابت حرف *fwdspec, صحيح dynamicfwd, صحيح remotefwd)
{
	بنية fwdarg fwdargs[4];
	حرف *p, *cp;
	صحيح i, err;

	memset(fwd, 0, حجم(*fwd));
	memset(fwdargs, 0, حجم(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	إذا (p == عدم || err)
		أرجع 0;

	/* skip leading spaces */
	طالما (که_تشه((u_char)*cp))
		cp++;

	لكل (i = 0; i < 4; ++i) {
		إذا (parse_fwd_ډګر(&cp, &fwdargs[i]) != 0)
			اكسر;
	}

	/* Check for trailing garbage */
	إذا (cp != عدم && *cp != '\0') {
		i = 0;	/* failure */
	}

	بدل (i) {
	حالة 1:
		إذا (fwdargs[0].ispath) {
			fwd->listen_لار = xstrdup(fwdargs[0].arg);
			fwd->listen_پورټ = پورټ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_پورټ = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		اكسر;

	حالة 2:
		إذا (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_لار = xstrdup(fwdargs[0].arg);
			fwd->listen_پورټ = پورټ_STREAMLOCAL;
			fwd->connect_لار = xstrdup(fwdargs[1].arg);
			fwd->connect_پورټ = پورټ_STREAMLOCAL;
		} وإلا إذا (fwdargs[1].ispath) {
			fwd->listen_host = عدم;
			fwd->listen_پورټ = a2port(fwdargs[0].arg);
			fwd->connect_لار = xstrdup(fwdargs[1].arg);
			fwd->connect_پورټ = پورټ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورټ = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		اكسر;

	حالة 3:
		إذا (fwdargs[0].ispath) {
			fwd->listen_لار = xstrdup(fwdargs[0].arg);
			fwd->listen_پورټ = پورټ_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورټ = a2port(fwdargs[2].arg);
		} وإلا إذا (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورټ = a2port(fwdargs[1].arg);
			fwd->connect_لار = xstrdup(fwdargs[2].arg);
			fwd->connect_پورټ = پورټ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_پورټ = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورټ = a2port(fwdargs[2].arg);
		}
		اكسر;

	حالة 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_پورټ = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_پورټ = a2port(fwdargs[3].arg);
		اكسر;
	افتراضي:
		i = 0; /* failure */
	}

	حرر(p);

	إذا (dynamicfwd) {
		إذا (!(i == 1 || i == 2))
			اذهب fail_free;
	} وإلا {
		إذا (!(i == 3 || i == 4)) {
			إذا (fwd->connect_لار == عدم &&
			    fwd->listen_لار == عدم)
				اذهب fail_free;
		}
		إذا (fwd->connect_پورټ <= 0 && fwd->connect_لار == عدم)
			اذهب fail_free;
	}

	إذا ((fwd->listen_پورټ < 0 && fwd->listen_لار == عدم) ||
	    (!remotefwd && fwd->listen_پورټ == 0))
		اذهب fail_free;
	إذا (fwd->connect_host != عدم &&
	    مزي_اوږدوالی(fwd->connect_host) >= NI_MAXHOST)
		اذهب fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	إذا (fwd->connect_لار != عدم &&
	    مزي_اوږدوالی(fwd->connect_لار) >= لار_MAX_SUN)
		اذهب fail_free;
	إذا (fwd->listen_host != عدم &&
	    مزي_اوږدوالی(fwd->listen_host) >= NI_MAXHOST)
		اذهب fail_free;
	إذا (fwd->listen_لار != عدم &&
	    مزي_اوږدوالی(fwd->listen_لار) >= لار_MAX_SUN)
		اذهب fail_free;

	أرجع (i);

 fail_free:
	حرر(fwd->connect_host);
	fwd->connect_host = عدم;
	حرر(fwd->connect_لار);
	fwd->connect_لار = عدم;
	حرر(fwd->listen_host);
	fwd->listen_host = عدم;
	حرر(fwd->listen_لار);
	fwd->listen_لار = عدم;
	أرجع (0);
}

صحيح
ssh_valid_hostname(ثابت حرف *s)
{
	اندازه_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (strchr("'`\"$\\;&<>|(){},", s[i]) != عدم ||
		    که_تشه((u_char)s[i]) || iscntrl((u_char)s[i]))
			أرجع 0;
	}
	أرجع 1;
}

صحيح
ssh_valid_ruser(ثابت حرف *s)
{
	اندازه_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (iscntrl((u_char)s[i]))
			أرجع 0;
		إذا (strchr("'`\";&<>|(){}$\\", s[i]) != عدم)
			أرجع 0;
		/* Disallow '-' after whitespace */
		إذا (که_تشه((u_char)s[i]) && s[i + 1] == '-')
			أرجع 0;
	}
	أرجع 1;
}

صحيح
parse_jump(ثابت حرف *s, Options *o, صحيح strict, صحيح فعال)
{
	حرف *orig = عدم, *sdup = عدم, *cp;
	حرف *tmp_user = عدم, *tmp_host = عدم, *host = عدم, *user = عدم;
	صحيح r, ret = -1, tmp_پورټ = -1, پورټ = -1, لومړی = 1;

	إذا (strcasecmp(s, "none") == 0) {
		إذا (فعال && o->jump_host == عدم) {
			o->jump_host = xstrdup("none");
			o->jump_پورټ = 0;
		}
		أرجع 0;
	}

	orig = xstrdup(s);
	إذا ((cp = strchr(orig, '#')) != عدم)
		*cp = '\0';
	rtrim(orig);

	فعال &= o->proxy_command == عدم && o->jump_host == عدم;
	sdup = xstrdup(orig);
	افعل {
		/* Work backwards through string */
		إذا ((cp = strrchr(sdup, ',')) == عدم)
			cp = sdup; /*وروستی*/
		وإلا
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_پورټ);
		إذا (r == -1 || (r == 1 && parse_user_host_پورټ(cp,
		    &tmp_user, &tmp_host, &tmp_پورټ) != 0))
			اذهب بهر; /* error already logged */
		إذا (strict) {
			إذا (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				اذهب بهر;
			}
			إذا (tmp_user != عدم && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				اذهب بهر;
			}
		}
		إذا (لومړی) {
			user = tmp_user;
			host = tmp_host;
			پورټ = tmp_پورټ;
			tmp_user = tmp_host = عدم; /* transferred */
		}
		لومړی = 0; /* only check syntax for subsequent hosts */
		حرر(tmp_user);
		حرر(tmp_host);
		tmp_user = tmp_host = عدم;
		tmp_پورټ = -1;
	} طالما (cp != sdup);

	/* success */
	إذا (فعال) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_پورټ = پورټ;
		o->proxy_command = xstrdup("none");
		user = host = عدم; /* transferred */
		إذا (orig != عدم && (cp = strrchr(orig, ',')) != عدم) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 بهر:
	حرر(orig);
	حرر(sdup);
	حرر(tmp_user);
	حرر(tmp_host);
	حرر(user);
	حرر(host);
	أرجع ret;
}

صحيح
parse_ssh_uri(ثابت حرف *uri, حرف **userp, حرف **hostp, صحيح *portp)
{
	حرف *user = عدم, *host = عدم, *لار = عدم;
	صحيح r, پورټ;

	r = parse_uri("ssh", uri, &user, &host, &پورټ, &لار);
	إذا (r == 0 && لار != عدم)
		r = -1;		/* path not allowed */
	إذا (r == 0) {
		إذا (userp != عدم) {
			*userp = user;
			user = عدم;
		}
		إذا (hostp != عدم) {
			*hostp = host;
			host = عدم;
		}
		إذا (portp != عدم)
			*portp = پورټ;
	}
	حرر(user);
	حرر(host);
	حرر(لار);
	أرجع r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].کلی != عدم; i++) {
		إذا (m[i].ارزښت == val)
			أرجع m[i].کلی;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(OpCodes کوډ, صحيح val)
{
	إذا (val == -1)
		أرجع "unset";
	بدل (کوډ) {
	حالة o_پته_Family:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة oCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة o_Verify_Host_کلی_DNS:
	حالة oUpdateHostkeys:
		أرجع fmt_multistate_int(val, multistate_yesnoask);
	حالة o_Strict_Host_کلی_Checking:
		أرجع fmt_multistate_int(val, multistate_strict_hostkey);
	حالة oControlMaster:
		أرجع fmt_multistate_int(val, multistate_controlmaster);
	حالة oTunnel:
		أرجع fmt_multistate_int(val, multistate_tunnel);
	حالة oRequestTTY:
		أرجع fmt_multistate_int(val, multistate_requesttty);
	حالة oSessionType:
		أرجع fmt_multistate_int(val, multistate_sessiontype);
	حالة oCanonicalizeHostname:
		أرجع fmt_multistate_int(val, multistate_canonicalizehostname);
	حالة o_جمع_کړه_کلیګانې_منزل_Agent:
		أرجع fmt_multistate_int(val, multistate_yesnoaskconfirm);
	حالة oPubkeyAuthentication:
		أرجع fmt_multistate_int(val, multistate_pubkey_auth);
	حالة oTCPKeepAlive:
		أرجع fmt_multistate_int(val, multistate_keepalives);
	حالة oFingerprintHash:
		أرجع ssh_digest_alg_name(val);
	افتراضي:
		بدل (val) {
		حالة 0:
			أرجع "no";
		حالة 1:
			أرجع "yes";
		افتراضي:
			أرجع "UNKNOWN";
		}
	}
}

ساكن ثابت حرف *
lookup_opcode_name(OpCodes کوډ)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		إذا (keywords[i].opcode == کوډ)
			أرجع(keywords[i].name);
	أرجع "UNKNOWN";
}

ساكن فراغ
dump_cfg_int(OpCodes کوډ, صحيح val)
{
	إذا (کوډ == oObscureKeystrokeTiming) {
		إذا (val == 0) {
			چاپ_کړه("%s no\n", lookup_opcode_name(کوډ));
			أرجع;
		} وإلا إذا (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			چاپ_کړه("%s yes\n", lookup_opcode_name(کوډ));
			أرجع;
		}
		/* FALLTHROUGH */
	}
	چاپ_کړه("%s %d\n", lookup_opcode_name(کوډ), val);
}

ساكن فراغ
dump_cfg_fmtint(OpCodes کوډ, صحيح val)
{
	چاپ_کړه("%s %s\n", lookup_opcode_name(کوډ), fmt_intarg(کوډ, val));
}

ساكن فراغ
dump_cfg_string(OpCodes کوډ, ثابت حرف *val)
{
	إذا (val == عدم)
		أرجع;
	چاپ_کړه("%s %s\n", lookup_opcode_name(کوډ), val);
}

ساكن فراغ
dump_cfg_strarray(OpCodes کوډ, u_int شمېر, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < شمېر; i++)
		چاپ_کړه("%s %s\n", lookup_opcode_name(کوډ), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(OpCodes کوډ, u_int شمېر, حرف **vals)
{
	u_int i;

	چاپ_کړه("%s", lookup_opcode_name(کوډ));
	إذا (شمېر == 0)
		چاپ_کړه(" none");
	لكل (i = 0; i < شمېر; i++)
		چاپ_کړه(" %s",  vals[i]);
	چاپ_کړه("\n");
}

ساكن فراغ
dump_cfg_forwards(OpCodes کوډ, u_int شمېر, ثابت بنية Forward *fwds)
{
	ثابت بنية Forward *fwd;
	u_int i;

	/* oDynamicForward */
	لكل (i = 0; i < شمېر; i++) {
		fwd = &fwds[i];
		إذا (کوډ == oDynamicForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") != 0)
			استمر;
		إذا (کوډ == oLocalForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") == 0)
			استمر;
		چاپ_کړه("%s", lookup_opcode_name(کوډ));
		إذا (fwd->listen_پورټ == پورټ_STREAMLOCAL)
			چاپ_کړه(" %s", fwd->listen_لار);
		وإلا إذا (fwd->listen_host == عدم)
			چاپ_کړه(" %d", fwd->listen_پورټ);
		وإلا {
			چاپ_کړه(" [%s]:%d",
			    fwd->listen_host, fwd->listen_پورټ);
		}
		إذا (کوډ != oDynamicForward) {
			إذا (fwd->connect_پورټ == پورټ_STREAMLOCAL)
				چاپ_کړه(" %s", fwd->connect_لار);
			وإلا إذا (fwd->connect_host == عدم)
				چاپ_کړه(" %d", fwd->connect_پورټ);
			وإلا {
				چاپ_کړه(" [%s]:%d",
				    fwd->connect_host, fwd->connect_پورټ);
			}
		}
		چاپ_کړه("\n");
	}
}

فراغ
dump_client_config(Options *o, ثابت حرف *host)
{
	صحيح i, r;
	حرف buf[8], *all_کلی;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_کلی = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_نومونه(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_کلی)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	حرر(all_کلی);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_پورټ, o->پورټ);

	/* Flag options */
	dump_cfg_fmtint(o_پته_Family, o->پته_family);
	dump_cfg_fmtint(o_Batch_ډېرپېښ, o->batch_ډېرپېښ);
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
#که_تعریف_شوی GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#د_که_پای /* GSSAPI */
	dump_cfg_fmtint(o_Hash_معلوم_Hosts, o->hash_معلوم_hosts);
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
	dump_cfg_fmtint(o_بهیر_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_کلی_Checking, o->strict_host_کلی_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_کلی_DNS, o->verify_host_کلی_dns);
	dump_cfg_fmtint(o_Visual_Host_کلی, o->visual_host_کلی);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_شمېره_د_Password_Prompts, o->شمېره_د_password_prompts);
	dump_cfg_int(o_Server_Alive_شمېر_Max, o->server_alive_شمېر_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_اندازه);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_پته, o->bind_پته);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_لار, o->control_لار);
	dump_cfg_string(o_Host_کلی_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_کلی_Alias, o->host_کلی_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_بې_اغېزه_عنصر_Agent, o->بې_اغېزه_عنصر_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#که_تعریف_شوی ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#د_که_پای
	dump_cfg_string(o_Security_کلی_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_معلوم_Hosts_Command, o->معلوم_hosts_command);
	dump_cfg_string(o_نښان, o->نښان);
	dump_cfg_string(o_نسخه_Addendum, o->نسخه_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->عدد_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_بې_اغېزه_عنصر_File, o->عدد_بې_اغېزه_عنصر_files, o->بې_اغېزه_عنصر_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->عدد_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->عدد_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_معلوم_Hosts_File, o->عدد_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_معلوم_Hosts_File, o->عدد_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_کلیګانې, o->عدد_revoked_host_کلیګانې, o->revoked_host_کلیګانې);
	dump_cfg_strarray(oSendEnv, o->عدد_send_env, o->send_env);
	dump_cfg_strarray(o_سېټ_Env, o->عدد_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->عدد_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->عدد_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	إذا (o->عدد_permitted_remote_opens == 0)
		چاپ_کړه("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	وإلا
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->عدد_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	إذا (o->جمع_کړه_کلیګانې_منزل_agent_lifespan <= 0)
		dump_cfg_fmtint(o_جمع_کړه_کلیګانې_منزل_Agent, o->جمع_کړه_کلیګانې_منزل_agent);
	وإلا {
		چاپ_کړه("addkeystoagent%s %d\n",
		    o->جمع_کړه_کلیګانې_منزل_agent == 3 ? " confirm" : "",
		    o->جمع_کړه_کلیګانې_منزل_agent_lifespan);
	}

	/* oForwardAgent */
	إذا (o->forward_agent_sock_لار == عدم)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	وإلا
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_لار);

	/* oConnectTimeout */
	إذا (o->connection_timeout == -1)
		چاپ_کړه("connecttimeout none\n");
	وإلا
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	چاپ_کړه("tunneldevice");
	إذا (o->tun_local == SSH_TUNID_ANY)
		چاپ_کړه(" any");
	وإلا
		چاپ_کړه(" %d", o->tun_local);
	إذا (o->tun_remote == SSH_TUNID_ANY)
		چاپ_کړه(":any");
	وإلا
		چاپ_کړه(":%d", o->tun_remote);
	چاپ_کړه("\n");

	/* oCanonicalizePermittedCNAMEs */
	چاپ_کړه("canonicalizepermittedcnames");
	إذا (o->عدد_permitted_cnames == 0)
		چاپ_کړه(" none");
	لكل (i = 0; i < o->عدد_permitted_cnames; i++) {
		چاپ_کړه(" %s:%s", o->permitted_cnames[i].سرچینه_list,
		    o->permitted_cnames[i].موخه_list);
	}
	چاپ_کړه("\n");

	/* oControlPersist */
	إذا (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	وإلا
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	إذا (o->escape_char == SSH_ESCAPECHAR_NONE)
		چاپ_کړه("escapechar none\n");
	وإلا {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		چاپ_کړه("escapechar %s\n", buf);
	}

	/* oIPQoS */
	چاپ_کړه("ipqos %s ", iptos2str(o->ip_qos_interactive));
	چاپ_کړه("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	چاپ_کړه("rekeylimit %llu %d\n",
	    (بینښه اوږد اوږد)o->rekey_حد, o->rekey_interval);

	/* oStreamLocalBindMask */
	چاپ_کړه("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_ماسک);

	/* oLogFacility */
	چاپ_کړه("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	إذا (o->jump_host == عدم)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	وإلا {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != عدم ||
		    strspn(o->jump_host, "1234567890.") == مزي_اوږدوالی(o->jump_host);
		snprintf(buf, حجم(buf), "%d", o->jump_پورټ);
		چاپ_کړه("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == عدم ? "" : o->jump_extra,
		    o->jump_extra == عدم ? "" : ",",
		    /* optional user */
		    o->jump_user == عدم ? "" : o->jump_user,
		    o->jump_user == عدم ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_پورټ <= 0 ? "" : ":",
		    o->jump_پورټ <= 0 ? "" : buf);
	}
}
