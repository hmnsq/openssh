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
#यदि defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#यदि_अन्तः

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

स्थिर पूर्णाङ्क read_config_file_गभीरता(ध्रुव वर्ण *filename, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    Options *options, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क *want_final_pass, पूर्णाङ्क गभीरता);
स्थिर पूर्णाङ्क process_config_पङ्क्तिः_गभीरता(Options *options, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    वर्ण *पङ्क्तिः, ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass, पूर्णाङ्क गभीरता);

/* Keyword tokens. */

प्रकारनिर्देश गणना {
	oBadOption,
	oHost, o_मेलनम्, oInclude, o_चिह्नकम्,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_तटस्थः_File, oHostname, o_पत्तनम्, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_सङ्कलय_कुञ्चिकाः_गन्तव्यम्_Agent, o_तटस्थः_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_ज्ञातम्_Hosts_File, o_User_ज्ञातम्_Hosts_File, oConnectionAttempts,
	o_Batch_बहुलकम्, oCheckHostIP, o_Strict_Host_कुञ्चिका_Checking, oCompression,
	oTCPKeepAlive, o_सङ्ख्या_सम्बन्धि_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_कुञ्चिका_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_कुञ्चिका_Algorithms, o_Bind_स्थानाङ्कः, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_सीमा, o_Verify_Host_कुञ्चिका_DNS, oConnectTimeout,
	o_स्थानाङ्कः_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_गणनम्_Max, oIdentitiesOnly,
	oSendEnv, o_समुच्चयः_Env, o_Control_मार्गः, oControlMaster, oControlPersist,
	o_Hash_ज्ञातम्_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_कुञ्चिका,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_प्रवाहः_Local_Bind_आवरणम्, o_प्रवाहः_Local_Bind_Unlink, o_Revoked_Host_कुञ्चिकाः,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_कुञ्चिका_Provider, o_ज्ञातम्_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_संस्करणम्_Addendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

स्थिर संरचना {
	ध्रुव वर्ण *name;
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
#यदि defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# अन्यथा
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#यदि_अन्तः
#यदि_परिभाषितम् ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# अन्यथा
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#यदि_अन्तः

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
	{ "identityfile", o_तटस्थः_File },
	{ "identityfile2", o_तटस्थः_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_सङ्कलय_कुञ्चिकाः_गन्तव्यम्_Agent },
	{ "identityagent", o_तटस्थः_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_कुञ्चिका_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_पत्तनम् },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_मेलनम् },
	{ "tag", o_चिह्नकम् },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_ज्ञातम्_Hosts_File },
	{ "userknownhostsfile", o_User_ज्ञातम्_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_बहुलकम् },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_कुञ्चिका_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_सङ्ख्या_सम्बन्धि_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_कुञ्चिका_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_स्थानाङ्कः },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_कुञ्चिका_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_सीमा },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_स्थानाङ्कः_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_गणनम्_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_समुच्चयः_Env },
	{ "controlpath", o_Control_मार्गः },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_ज्ञातम्_Hosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_कुञ्चिका },
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
	{ "streamlocalbindmask", o_प्रवाहः_Local_Bind_आवरणम् },
	{ "streamlocalbindunlink", o_प्रवाहः_Local_Bind_Unlink },
	{ "revokedhostkeys", o_Revoked_Host_कुञ्चिकाः },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_कुञ्चिका_Provider },
	{ "knownhostscommand", o_ज्ञातम्_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_संस्करणम्_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ रिक्त, oBadOption }
};

स्थिर ध्रुव वर्ण *lookup_opcode_name(OpCodes संहिता);

ध्रुव वर्ण *
kex_default_pk_alg(शून्य)
{
	स्थिर वर्ण *pkalgs;

	यदि (pkalgs == रिक्त) {
		वर्ण *all_कुञ्चिका;

		all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = मेलनम्_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
		मुक्त(all_कुञ्चिका);
	}
	प्रत्यागम pkalgs;
}

वर्ण *
ssh_connection_hash(ध्रुव वर्ण *thishost, ध्रुव वर्ण *host, ध्रुव वर्ण *portstr,
    ध्रुव वर्ण *user, ध्रुव वर्ण *jumphost)
{
	संरचना ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_दीर्घता];

	यदि ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == रिक्त ||
	    ssh_digest_update(md, thishost, वाक्यदैर्घ्यम्(thishost)) < 0 ||
	    ssh_digest_update(md, host, वाक्यदैर्घ्यम्(host)) < 0 ||
	    ssh_digest_update(md, portstr, वाक्यदैर्घ्यम्(portstr)) < 0 ||
	    ssh_digest_update(md, user, वाक्यदैर्घ्यम्(user)) < 0 ||
	    ssh_digest_update(md, jumphost, वाक्यदैर्घ्यम्(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, परिमाण(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	प्रत्यागम tohex(conn_hash, ssh_digest_अष्टकानि(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

शून्य
सङ्कलय_local_forward(Options *options, ध्रुव संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णाङ्क i;

	/* Don't add duplicates */
	प्रति (i = 0; i < options->अङ्कः_local_forwards; i++) {
		यदि (forward_equals(newfwd, options->local_forwards + i))
			प्रत्यागम;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->अङ्कः_local_forwards + 1,
	    परिमाण(*options->local_forwards));
	fwd = &options->local_forwards[options->अङ्कः_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_पत्तनम् = newfwd->listen_पत्तनम्;
	fwd->listen_मार्गः = newfwd->listen_मार्गः;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_पत्तनम् = newfwd->connect_पत्तनम्;
	fwd->connect_मार्गः = newfwd->connect_मार्गः;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

शून्य
सङ्कलय_remote_forward(Options *options, ध्रुव संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णाङ्क i;

	/* Don't add duplicates */
	प्रति (i = 0; i < options->अङ्कः_remote_forwards; i++) {
		यदि (forward_equals(newfwd, options->remote_forwards + i))
			प्रत्यागम;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->अङ्कः_remote_forwards + 1,
	    परिमाण(*options->remote_forwards));
	fwd = &options->remote_forwards[options->अङ्कः_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_पत्तनम् = newfwd->listen_पत्तनम्;
	fwd->listen_मार्गः = newfwd->listen_मार्गः;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_पत्तनम् = newfwd->connect_पत्तनम्;
	fwd->connect_मार्गः = newfwd->connect_मार्गः;
	fwd->handle = newfwd->handle;
	fwd->allocated_पत्तनम् = 0;
}

स्थिर शून्य
clear_forwardings(Options *options)
{
	पूर्णाङ्क i;

	प्रति (i = 0; i < options->अङ्कः_local_forwards; i++) {
		मुक्त(options->local_forwards[i].listen_host);
		मुक्त(options->local_forwards[i].listen_मार्गः);
		मुक्त(options->local_forwards[i].connect_host);
		मुक्त(options->local_forwards[i].connect_मार्गः);
	}
	यदि (options->अङ्कः_local_forwards > 0) {
		मुक्त(options->local_forwards);
		options->local_forwards = रिक्त;
	}
	options->अङ्कः_local_forwards = 0;
	प्रति (i = 0; i < options->अङ्कः_remote_forwards; i++) {
		मुक्त(options->remote_forwards[i].listen_host);
		मुक्त(options->remote_forwards[i].listen_मार्गः);
		मुक्त(options->remote_forwards[i].connect_host);
		मुक्त(options->remote_forwards[i].connect_मार्गः);
	}
	यदि (options->अङ्कः_remote_forwards > 0) {
		मुक्त(options->remote_forwards);
		options->remote_forwards = रिक्त;
	}
	options->अङ्कः_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

शून्य
सङ्कलय_certificate_file(Options *options, ध्रुव वर्ण *मार्गः, पूर्णाङ्क userprovided)
{
	पूर्णाङ्क i;

	यदि (options->अङ्कः_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	प्रति (i = 0; i < options->अङ्कः_certificate_files; i++) {
		यदि (options->certificate_file_userprovided[i] == userprovided &&
		    वाक्यं_तुलय(options->certificate_files[i], मार्गः) == 0) {
			debug2_f("ignoring duplicate key %s", मार्गः);
			प्रत्यागम;
		}
	}

	options->certificate_file_userprovided[options->अङ्कः_certificate_files] =
	    userprovided;
	options->certificate_files[options->अङ्कः_certificate_files++] =
	    xstrdup(मार्गः);
}

शून्य
सङ्कलय_तटस्थः_file(Options *options, ध्रुव वर्ण *dir, ध्रुव वर्ण *filename,
    पूर्णाङ्क userprovided)
{
	वर्ण *मार्गः;
	पूर्णाङ्क i;

	यदि (options->अङ्कः_तटस्थः_files >= SSH_MAX_तटस्थः_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_तटस्थः_FILES);

	यदि (dir == रिक्त) /* no dir, filename is absolute */
		मार्गः = xstrdup(filename);
	अन्यथा यदि (xasprintf(&मार्गः, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", मार्गः);

	/* Avoid registering duplicates */
	प्रति (i = 0; i < options->अङ्कः_तटस्थः_files; i++) {
		यदि (options->तटस्थः_file_userprovided[i] == userprovided &&
		    वाक्यं_तुलय(options->तटस्थः_files[i], मार्गः) == 0) {
			debug2_f("ignoring duplicate key %s", मार्गः);
			मुक्त(मार्गः);
			प्रत्यागम;
		}
	}

	options->तटस्थः_file_userprovided[options->अङ्कः_तटस्थः_files] =
	    userprovided;
	options->तटस्थः_files[options->अङ्कः_तटस्थः_files++] = मार्गः;
}

पूर्णाङ्क
default_ssh_पत्तनम्(शून्य)
{
	स्थिर पूर्णाङ्क पत्तनम्;
	संरचना servent *sp;

	यदि (पत्तनम् == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		पत्तनम् = sp ? ntohs(sp->s_port) : SSH_DEFAULT_पत्तनम्;
	}
	प्रत्यागम पत्तनम्;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
स्थिर पूर्णाङ्क
execute_अन्तर्_shell(ध्रुव वर्ण *cmd)
{
	वर्ण *shell;
	pid_t pid;
	पूर्णाङ्क स्थितिः;

	यदि ((shell = getenv("SHELL")) == रिक्त)
		shell = _PATH_BSHELL;

	यदि (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	यदि ((pid = fork()) == 0) {
		वर्ण *argv[4];

		यदि (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = रिक्त;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	यदि (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	यावत् (waitpid(pid, &स्थितिः, 0) == -1) {
		यदि (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	यदि (!WIFEXITED(स्थितिः)) {
		error("command '%.100s' exited abnormally", cmd);
		प्रत्यागम -1;
	}
	debug3("command returned status %d", WEXITSTATUS(स्थितिः));
	प्रत्यागम WEXITSTATUS(स्थितिः);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
स्थिर पूर्णाङ्क
check_मेलनम्_ifaddrs(ध्रुव वर्ण *addrlist)
{
#यदि_परिभाषितम् HAVE_IFADDRS_H
	संरचना ifaddrs *ifa, *ifaddrs = रिक्त;
	पूर्णाङ्क r, प्राप्तम् = 0;
	वर्ण addr[NI_MAXHOST];
	socklen_t salen;

	यदि (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		प्रत्यागम 0;
	}
	प्रति (ifa = ifaddrs; ifa != रिक्त; ifa = ifa->ifa_अग्र) {
		यदि (ifa->ifa_addr == रिक्त || ifa->ifa_name == रिक्त ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			अनुवर्त;
		विकल्प (ifa->ifa_addr->sa_family) {
		पक्ष AF_INET:
			salen = परिमाण(संरचना sockaddr_in);
			भङ्ग;
		पक्ष AF_INET6:
			salen = परिमाण(संरचना sockaddr_in6);
			भङ्ग;
#यदि_परिभाषितम् AF_LINK
		पक्ष AF_LINK:
			/* ignore */
			अनुवर्त;
#यदि_अन्तः /* AF_LINK */
		स्वभाव:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			अनुवर्त;
		}
		यदि ((r = getnameinfo(ifa->ifa_addr, salen, addr, परिमाण(addr),
		    रिक्त, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			अनुवर्त;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		यदि (addr_मेलनम्_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			प्राप्तम् = 1;
			भङ्ग;
		}
	}
	freeifaddrs(ifaddrs);
	प्रत्यागम प्राप्तम्;
#अन्यथा /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	प्रत्यागम 0;
#यदि_अन्तः /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
स्थिर वर्ण *
expand_मेलनम्_exec_or_include_मार्गः(ध्रुव वर्ण *मार्गः, Options *options,
    संरचना passwd *pw, ध्रुव वर्ण *host_arg, ध्रुव वर्ण *original_host,
    पूर्णाङ्क final_pass, पूर्णाङ्क is_include_मार्गः)
{
	वर्ण thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	वर्ण uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	वर्ण *host, *ret;
	पूर्णाङ्क पत्तनम्;

	पत्तनम् = options->पत्तनम् <= 0 ? default_ssh_पत्तनम्() : options->पत्तनम्;
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	यदि (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा यदि (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (वर्ण *)रिक्त);
	} अन्यथा {
		host = xstrdup(host_arg);
	}
	यदि (gethostname(thishost, परिमाण(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, परिमाण(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, परिमाण(portstr), "%d", पत्तनम्);
	snprintf(uidstr, परिमाण(uidstr), "%llu",
	    (अचिह्नित दीर्घ दीर्घ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_कुञ्चिका_alias ?  options->host_कुञ्चिका_alias : host;

	ret = (is_include_मार्गः ? percent_dollar_expand : percent_expand)(मार्गः,
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
	    (वर्ण *)रिक्त);
	मुक्त(host);
	मुक्त(conn_hash_hex);
	प्रत्यागम ret;
}

/*
 * Parse and execute a Match directive.
 */
स्थिर पूर्णाङ्क
मेलनम्_cfg_पङ्क्तिः(Options *options, ध्रुव वर्ण *पूर्णम्_पङ्क्तिः, पूर्णाङ्क *acp, वर्ण ***avp,
    संरचना passwd *pw, ध्रुव वर्ण *host_arg, ध्रुव वर्ण *original_host,
    ध्रुव वर्ण *remote_command, पूर्णाङ्क final_pass, पूर्णाङ्क *want_final_pass,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum)
{
	वर्ण *arg, *oattrib = रिक्त, *attrib = रिक्त, *cmd, *host, *criteria;
	ध्रुव वर्ण *ruser;
	पूर्णाङ्क r, this_परिणाम, परिणाम = 1, गुणाः = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	यदि (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा यदि (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (वर्ण *)रिक्त);
	} अन्यथा {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    पूर्णम्_पङ्क्तिः, host, original_host);
	यावत् ((attrib = argv_अग्र(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		यदि (*attrib == '#') {
			argv_consume(acp);
			भङ्ग;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = रिक्त;
		this_परिणाम = 1;
		यदि ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		यदि (strcasecmp(attrib, "all") == 0) {
			यदि (गुणाः > 1 ||
			    ((arg = argv_अग्र(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
			यदि (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			यदि (परिणाम)
				परिणाम = negate ? 0 : 1;
			गच्छ बहिर्गमनम्;
		}
		गुणाः++;
		/* criteria "final" and "canonical" have no argument */
		यदि (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			यदि (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != रिक्त)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_परिणाम ? "" : "not ", oattrib);
			गच्छ अग्र;
		}

		/* Keep this list in sync with below */
		यदि (strprefix(attrib, "host=", 1)  != रिक्त ||
		    strprefix(attrib, "originalhost=", 1) != रिक्त ||
		    strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "localuser=", 1) != रिक्त ||
		    strprefix(attrib, "localnetwork=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त ||
		    strprefix(attrib, "tagged=", 1) != रिक्त ||
		    strprefix(attrib, "command=", 1) != रिक्त ||
		    strprefix(attrib, "exec=", 1) != रिक्त) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा यदि ((arg = argv_अग्र(acp, avp)) == रिक्त) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			परिणाम = -1;
			गच्छ बहिर्गमनम्;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		यदि (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = रिक्त;
		यदि (arg == रिक्त || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			परिणाम = -1;
			गच्छ बहिर्गमनम्;
		}
		यदि (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = मेलनम्_hostname(host, arg) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = मेलनम्_hostname(original_host, arg) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = मेलनम्_आदर्शः_list(ruser, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = मेलनम्_आदर्शः_list(pw->pw_name, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "localnetwork") == 0) {
			यदि (addr_मेलनम्_cidr_list(रिक्त, arg) == -1) {
				/* Error already printed */
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
			r = check_मेलनम्_ifaddrs(arg) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = मेलनम्_आदर्शः_list(SSH_RELEASE, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->चिह्नकम् == रिक्त ? "" :
			    options->चिह्नकम्);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    मेलनम्_आदर्शः_list(criteria, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == रिक्त ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    मेलनम्_आदर्शः_list(criteria, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "sessiontype") == 0) {
			यदि (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			अन्यथा यदि (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			अन्यथा यदि (remote_command != रिक्त &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			अन्यथा
				criteria = xstrdup("shell");
			r = मेलनम्_आदर्शः_list(criteria, arg, 0) == 1;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "exec") == 0) {
			यदि ((cmd = expand_मेलनम्_exec_or_include_मार्गः(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == रिक्त) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			यदि (परिणाम != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				मुक्त(cmd);
				गच्छ अग्र;
			}
			r = execute_अन्तर्_shell(cmd);
			यदि (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			मुक्त(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			यदि (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा {
			error("Unsupported Match attribute %s", attrib);
			परिणाम = -1;
			गच्छ बहिर्गमनम्;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_परिणाम ? "": "not ", oattrib,
		    criteria == रिक्त ? "" : " \"",
		    criteria == रिक्त ? "" : criteria,
		    criteria == रिक्त ? "" : "\"");
 अग्र:
		मुक्त(criteria);
		मुक्त(oattrib);
		oattrib = attrib = रिक्त;
	}
	यदि (गुणाः == 0) {
		error("One or more attributes required for Match");
		परिणाम = -1;
		गच्छ बहिर्गमनम्;
	}
 बहिर्गमनम्:
	यदि (परिणाम != -1)
		debug2("match %sfound", परिणाम ? "" : "not ");
	मुक्त(oattrib);
	मुक्त(host);
	प्रत्यागम परिणाम;
}

/* Remove environment variable by pattern */
स्थिर शून्य
rm_env(Options *options, ध्रुव वर्ण *arg, ध्रुव वर्ण *filename, पूर्णाङ्क linenum)
{
	u_int i, j, onum_send_env = options->अङ्कः_send_env;

	/* Remove an environment variable */
	प्रति (i = 0; i < options->अङ्कः_send_env; ) {
		यदि (!मेलनम्_आदर्शः(options->send_env[i], arg + 1)) {
			i++;
			अनुवर्त;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		मुक्त(options->send_env[i]);
		options->send_env[i] = रिक्त;
		प्रति (j = i; j < options->अङ्कः_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = रिक्त;
		}
		options->अङ्कः_send_env--;
		/* NB. don't increment i */
	}
	यदि (onum_send_env != options->अङ्कः_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->अङ्कः_send_env,
		    परिमाण(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
स्थिर OpCodes
parse_token(ध्रुव वर्ण *cp, ध्रुव वर्ण *filename, पूर्णाङ्क linenum,
    ध्रुव वर्ण *ignored_unknown)
{
	पूर्णाङ्क i;

	प्रति (i = 0; keywords[i].name; i++)
		यदि (वाक्यं_तुलय(cp, keywords[i].name) == 0)
			प्रत्यागम keywords[i].opcode;
	यदि (ignored_unknown != रिक्त &&
	    मेलनम्_आदर्शः_list(cp, ignored_unknown, 1) == 1)
		प्रत्यागम oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	प्रत्यागम oBadOption;
}

स्थिर शून्य
free_canon_cnames(संरचना allowed_cname *cnames, u_int n)
{
	u_int i;

	यदि (cnames == रिक्त || n == 0)
		प्रत्यागम;
	प्रति (i = 0; i < n; i++) {
		मुक्त(cnames[i].source_list);
		मुक्त(cnames[i].target_list);
	}
	मुक्त(cnames);
}

/* Multistate option parsing */
संरचना multistate {
	वर्ण *कुञ्चिका;
	पूर्णाङ्क मानम्;
};
स्थिर ध्रुव संरचना multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_compression[] = {
#यदि_परिभाषितम् WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#यदि_अन्तः
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
स्थिर ध्रुव संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णाङ्क
parse_multistate_मानम्(ध्रुव वर्ण *arg, ध्रुव वर्ण *filename, पूर्णाङ्क linenum,
    ध्रुव संरचना multistate *multistate_ptr)
{
	पूर्णाङ्क i;

	यदि (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		प्रत्यागम -1;
	}
	प्रति (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
		यदि (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0)
			प्रत्यागम multistate_ptr[i].मानम्;
	}
	प्रत्यागम -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
पूर्णाङ्क
process_config_पङ्क्तिः(Options *options, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags)
{
	प्रत्यागम process_config_पङ्क्तिः_गभीरता(options, pw, host, original_host,
	    remote_command, पङ्क्तिः, filename, linenum, activep, flags, रिक्त, 0);
}

#परिभाषय WHITESPACE " \t\r\n"
स्थिर पूर्णाङ्क
process_config_पङ्क्तिः_गभीरता(Options *options, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass, पूर्णाङ्क गभीरता)
{
	वर्ण *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	वर्ण **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	पूर्णाङ्क r, oactive, negated, opcode, *intptr, मानम्, value2, cmdline = 0;
	पूर्णाङ्क remotefwd, dynamicfwd, ca_only = 0, प्राप्तम् = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	दीर्घ दीर्घ val64;
	आकार_t len;
	संरचना Forward fwd;
	ध्रुव संरचना multistate *multistate_ptr;
	glob_t gl;
	ध्रुव वर्ण *errstr;
	वर्ण **oav = रिक्त, **av;
	पूर्णाङ्क oac = 0, ac;
	पूर्णाङ्क ret = -1;
	संरचना allowed_cname *cnames = रिक्त;
	u_int ncnames = 0;
	वर्ण **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	यदि (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	यदि ((len = वाक्यदैर्घ्यम्(पङ्क्तिः)) == 0)
		प्रत्यागम 0;
	प्रति (len--; len > 0; len--) {
		यदि (strchr(WHITESPACE "\f", पङ्क्तिः[len]) == रिक्त)
			भङ्ग;
		पङ्क्तिः[len] = '\0';
	}

	str = पङ्क्तिः;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	यदि ((keyword = strdelim(&str)) == रिक्त)
		प्रत्यागम 0;
	/* Ignore leading whitespace. */
	यदि (*keyword == '\0')
		keyword = strdelim(&str);
	यदि (keyword == रिक्त || !*keyword || *keyword == '\n' || *keyword == '#')
		प्रत्यागम 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	यदि (str != रिक्त)
		str += strspn(str, WHITESPACE);
	यदि (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		प्रत्यागम -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	यदि (argv_विभज(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		प्रत्यागम -1;
	}
	ac = oac;
	av = oav;

	विकल्प (opcode) {
	पक्ष oBadOption:
		/* don't panic, but count bad options */
		गच्छ बहिर्गमनम्;
	पक्ष oIgnore:
		argv_consume(&ac);
		भङ्ग;
	पक्ष oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;
	पक्ष oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (वाक्यं_तुलय(arg, "none") == 0)
			मानम् = -1;
		अन्यथा यदि ((मानम् = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}

		मानम् = -1;
		multistate_ptr = multistate_flag;
		प्रति (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
			यदि (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0) {
				मानम् = multistate_ptr[i].मानम्;
				भङ्ग;
			}
		}
		यदि (मानम् != -1) {
			यदि (*activep && *intptr == -1)
				*intptr = मानम्;
			भङ्ग;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		यदि (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_मार्गः;
		गच्छ parse_agent_मार्गः;

	पक्ष oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_अग्र(&ac, &av);
		यदि ((मानम् = parse_multistate_मानम्(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		गच्छ parse_flag;

	पक्ष oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		गच्छ parse_time;

	पक्ष oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		गच्छ parse_flag;

	पक्ष oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		गच्छ parse_flag;

	पक्ष oPasswordAuthentication:
		intptr = &options->password_authentication;
		गच्छ parse_flag;

	पक्ष oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		गच्छ parse_flag;

	पक्ष oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		गच्छ parse_string;

	पक्ष oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		गच्छ parse_multistate;

	पक्ष oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		गच्छ parse_flag;

	पक्ष oGssAuthentication:
		intptr = &options->gss_authentication;
		गच्छ parse_flag;

	पक्ष oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		गच्छ parse_flag;

	पक्ष o_Batch_बहुलकम्:
		intptr = &options->batch_बहुलकम्;
		गच्छ parse_flag;

	पक्ष oCheckHostIP:
		intptr = &options->check_host_ip;
		गच्छ parse_flag;

	पक्ष o_Verify_Host_कुञ्चिका_DNS:
		intptr = &options->verify_host_कुञ्चिका_dns;
		multistate_ptr = multistate_yesnoask;
		गच्छ parse_multistate;

	पक्ष o_Strict_Host_कुञ्चिका_Checking:
		intptr = &options->strict_host_कुञ्चिका_checking;
		multistate_ptr = multistate_strict_hostkey;
		गच्छ parse_multistate;

	पक्ष oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		गच्छ parse_multistate;

	पक्ष oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		गच्छ parse_multistate;

	पक्ष oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		गच्छ parse_flag;

	पक्ष o_सङ्ख्या_सम्बन्धि_Password_Prompts:
		intptr = &options->सङ्ख्या_सम्बन्धि_password_prompts;
		गच्छ parse_int;

	पक्ष o_Rekey_सीमा:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (वाक्यं_तुलय(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			यदि (अवलोकनम्_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				गच्छ बहिर्गमनम्;
			}
			यदि (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
		}
		यदि (*activep && options->rekey_सीमा == -1)
			options->rekey_सीमा = val64;
		यदि (ac != 0) { /* optional rekey interval present */
			यदि (वाक्यं_तुलय(av[0], "none") == 0) {
				(शून्य)argv_अग्र(&ac, &av);	/* discard */
				भङ्ग;
			}
			intptr = &options->rekey_interval;
			गच्छ parse_time;
		}
		भङ्ग;

	पक्ष o_तटस्थः_File:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep) {
			intptr = &options->अङ्कः_तटस्थः_files;
			यदि (*intptr >= SSH_MAX_तटस्थः_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_तटस्थः_FILES);
				गच्छ बहिर्गमनम्;
			}
			सङ्कलय_तटस्थः_file(options, रिक्त,
			    arg, flags & SSHCONF_USERCONF);
		}
		भङ्ग;

	पक्ष oCertificateFile:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep) {
			intptr = &options->अङ्कः_certificate_files;
			यदि (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				गच्छ बहिर्गमनम्;
			}
			सङ्कलय_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		भङ्ग;

	पक्ष oXAuthLocation:
		charptr=&options->xauth_location;
		गच्छ parse_string;

	पक्ष oUser:
		charptr = &options->user;
parse_string:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष o_Global_ज्ञातम्_Hosts_File:
		cpptr = (वर्ण **)&options->system_hostfiles;
		uintptr = &options->अङ्कः_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		मानम् = *uintptr == 0; /* was array empty when we started? */
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			}
			i++;
			यदि (*activep && मानम्) {
				यदि ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					गच्छ बहिर्गमनम्;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		भङ्ग;

	पक्ष o_User_ज्ञातम्_Hosts_File:
		cpptr = (वर्ण **)&options->user_hostfiles;
		uintptr = &options->अङ्कः_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		गच्छ parse_char_array;

	पक्ष oHostname:
		charptr = &options->hostname;
		गच्छ parse_string;

	पक्ष o_चिह्नकम्:
		charptr = &options->चिह्नकम्;
		गच्छ parse_string;

	पक्ष o_Host_कुञ्चिका_Alias:
		charptr = &options->host_कुञ्चिका_alias;
		गच्छ parse_string;

	पक्ष oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		गच्छ parse_string;

	पक्ष o_Bind_स्थानाङ्कः:
		charptr = &options->bind_स्थानाङ्कः;
		गच्छ parse_string;

	पक्ष oBindInterface:
		charptr = &options->bind_interface;
		गच्छ parse_string;

	पक्ष oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		गच्छ parse_string;

	पक्ष o_Security_कुञ्चिका_Provider:
		charptr = &options->sk_provider;
		गच्छ parse_string;

	पक्ष o_ज्ञातम्_Hosts_Command:
		charptr = &options->ज्ञातम्_hosts_command;
		गच्छ parse_command;

	पक्ष oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		यदि (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		len = strspn(str, WHITESPACE "=");
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष oProxyJump:
		यदि (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		यदि (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			गच्छ बहिर्गमनम्;
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष o_पत्तनम्:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		मानम् = a2port(arg);
		यदि (मानम् <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->पत्तनम् == -1)
			options->पत्तनम् = मानम्;
		भङ्ग;

	पक्ष oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_अग्र(&ac, &av);
		यदि ((errstr = atoi_err(arg, &मानम्)) != रिक्त) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oCiphers:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		भङ्ग;

	पक्ष oMacs:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->macs == रिक्त)
			options->macs = xstrdup(arg);
		भङ्ग;

	पक्ष oKexAlgorithms:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*arg != '-' &&
		    !kex_नामानि_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		भङ्ग;

	पक्ष o_Host_कुञ्चिका_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*arg != '-' &&
		    !sshkey_नामानि_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		गच्छ parse_pubkey_algos;

	पक्ष oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_अग्र(&ac, &av);
		मानम् = log_level_सङ्ख्या(arg);
		यदि (मानम् == SYSLOG_LEVEL_NOT_समुच्चयः) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_समुच्चयः)
			*log_level_ptr = (LogLevel) मानम्;
		भङ्ग;

	पक्ष oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_अग्र(&ac, &av);
		मानम् = log_facility_सङ्ख्या(arg);
		यदि (मानम् == SYSLOG_FACILITY_NOT_समुच्चयः) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ बहिर्गमनम्;
		}
		यदि (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मानम्;
		भङ्ग;

	पक्ष oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->अङ्कः_log_verbose;
		i = 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			}
			i++;
			यदि (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, परिमाण(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		भङ्ग;

	पक्ष oLocalForward:
	पक्ष oRemoteForward:
	पक्ष oDynamicForward:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		यदि (!dynamicfwd) {
			arg2 = argv_अग्र(&ac, &av);
			यदि (arg2 == रिक्त || *arg2 == '\0') {
				यदि (remotefwd)
					dynamicfwd = 1;
				अन्यथा {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा {
				/* construct a string for parse_forward */
				snprintf(fwdarg, परिमाण(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		यदि (dynamicfwd)
			strlcpy(fwdarg, arg, परिमाण(fwdarg));

		यदि (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}

		यदि (*activep) {
			यदि (remotefwd) {
				सङ्कलय_remote_forward(options, &fwd);
			} अन्यथा {
				सङ्कलय_local_forward(options, &fwd);
			}
		}
		भङ्ग;

	पक्ष oPermitRemoteOpen:
		uintptr = &options->अङ्कः_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		प्राप्तम् = *uintptr == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			यदि (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					मुक्त(arg2);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा {
				p = hpdelim(&arg);
				यदि (p == रिक्त) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				यदि (arg == रिक्त || (वाक्यं_तुलय(arg, "*") != 0 &&
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
		यदि (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		यदि (प्राप्तम् && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oClearAllForwardings:
		intptr = &options->clear_forwardings;
		गच्छ parse_flag;

	पक्ष oHost:
		यदि (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			गच्छ बहिर्गमनम्;
		}
		*activep = 0;
		arg2 = रिक्त;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			यदि ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				भङ्ग;
			}
			negated = *arg == '!';
			यदि (negated)
				arg++;
			यदि (मेलनम्_आदर्शः(host, arg)) {
				यदि (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					भङ्ग;
				}
				यदि (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		यदि (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		भङ्ग;

	पक्ष o_मेलनम्:
		यदि (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			गच्छ बहिर्गमनम्;
		}
		मानम् = मेलनम्_cfg_पङ्क्तिः(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		यदि (मानम् < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			गच्छ बहिर्गमनम्;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : मानम्;
		भङ्ग;

	पक्ष oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (वाक्यं_तुलय(arg, "none") == 0)
			मानम् = SSH_ESCAPECHAR_NONE;
		अन्यथा यदि (arg[1] == '\0')
			मानम् = (u_char) arg[0];
		अन्यथा यदि (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			मानम् = (u_char) arg[1] & 31;
		अन्यथा {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष o_स्थानाङ्कः_Family:
		intptr = &options->स्थानाङ्कः_family;
		multistate_ptr = multistate_addressfamily;
		गच्छ parse_multistate;

	पक्ष oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		गच्छ parse_flag;

	पक्ष oIdentitiesOnly:
		intptr = &options->identities_only;
		गच्छ parse_flag;

	पक्ष oServerAliveInterval:
		intptr = &options->server_alive_interval;
		गच्छ parse_time;

	पक्ष o_Server_Alive_गणनम्_Max:
		intptr = &options->server_alive_गणनम्_max;
		गच्छ parse_int;

	पक्ष oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' || strchr(arg, '=') != रिक्त) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
			प्राप्तम् = 1;
			यदि (!*activep)
				अनुवर्त;
			यदि (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				अनुवर्त;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->अङ्कः_send_env, arg);
		}
		यदि (!प्राप्तम्) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष o_समुच्चयः_Env:
		प्राप्तम् = options->अङ्कः_setenv == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (strchr(arg, '=') == रिक्त) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
			यदि (lookup_setenv_अन्तर्_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				अनुवर्त;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->setenv = strs;
			options->अङ्कः_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष o_Control_मार्गः:
		charptr = &options->control_मार्गः;
		गच्छ parse_string;

	पक्ष oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		गच्छ parse_multistate;

	पक्ष oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		मानम् = 0;
		value2 = 0;	/* timeout */
		यदि (वाक्यं_तुलय(arg, "no") == 0 || वाक्यं_तुलय(arg, "false") == 0)
			मानम् = 0;
		अन्यथा यदि (वाक्यं_तुलय(arg, "yes") == 0 || वाक्यं_तुलय(arg, "true") == 0)
			मानम् = 1;
		अन्यथा यदि ((value2 = convtime(arg)) >= 0)
			मानम् = 1;
		अन्यथा {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1) {
			*intptr = मानम्;
			options->control_persist_timeout = value2;
		}
		भङ्ग;

	पक्ष o_Hash_ज्ञातम्_Hosts:
		intptr = &options->hash_ज्ञातम्_hosts;
		गच्छ parse_flag;

	पक्ष oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		गच्छ parse_multistate;

	पक्ष oTunnelDevice:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		मानम् = a2tun(arg, &value2);
		यदि (मानम् == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->tun_local == -1) {
			options->tun_local = मानम्;
			options->tun_remote = value2;
		}
		भङ्ग;

	पक्ष oLocalCommand:
		charptr = &options->local_command;
		गच्छ parse_command;

	पक्ष oPermitLocalCommand:
		intptr = &options->permit_local_command;
		गच्छ parse_flag;

	पक्ष oRemoteCommand:
		charptr = &options->remote_command;
		गच्छ parse_command;

	पक्ष o_Visual_Host_कुञ्चिका:
		intptr = &options->visual_host_कुञ्चिका;
		गच्छ parse_flag;

	पक्ष oInclude:
		यदि (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			गच्छ बहिर्गमनम्;
		}
		मानम् = 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Expand %tokens and environment variables */
			यदि ((p = expand_मेलनम्_exec_or_include_मार्गः(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == रिक्त) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				अनुवर्त;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			यदि (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				गच्छ बहिर्गमनम्;
			}
			यदि (!मार्गः_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" मार्गः_SSH_USER_DIR : SSHDIR, p);
			} अन्यथा {
				arg2 = xstrdup(p);
			}
			मुक्त(p);
			स्मृतिं_पूरय(&gl, 0, परिमाण(gl));
			r = glob(arg2, GLOB_TILDE, रिक्त, &gl);
			यदि (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				मुक्त(arg2);
				अनुवर्त;
			} अन्यथा यदि (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				गच्छ बहिर्गमनम्;
			}
			मुक्त(arg2);
			oactive = *activep;
			प्रति (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], गभीरता,
				    oactive ? "" : " (parse only)");
				r = read_config_file_गभीरता(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, गभीरता + 1);
				यदि (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					गच्छ बहिर्गमनम्;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				यदि (r != 1)
					मानम् = -1;
			}
			globfree(&gl);
		}
		यदि (मानम् != 0)
			ret = मानम्;
		भङ्ग;

	पक्ष oIPQoS:
		arg = argv_अग्र(&ac, &av);
		यदि ((मानम् = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (मानम् == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मानम् = अधिकतम_पूर्णाङ्कः;
		}
		arg = argv_अग्र(&ac, &av);
		यदि (arg == रिक्त)
			value2 = मानम्;
		अन्यथा यदि ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = अधिकतम_पूर्णाङ्कः;
		}
		यदि (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मानम्;
			options->ip_qos_bulk = value2;
		}
		भङ्ग;

	पक्ष oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		गच्छ parse_multistate;

	पक्ष oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		गच्छ parse_multistate;

	पक्ष oStdinNull:
		intptr = &options->stdin_null;
		गच्छ parse_flag;

	पक्ष oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		गच्छ parse_flag;

	पक्ष oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		गच्छ parse_string;

	पक्ष oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		गच्छ parse_flag;

	पक्ष oCanonicalDomains:
		प्राप्तम् = options->अङ्कः_canonical_domains == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			}
			यदि (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				गच्छ बहिर्गमनम्;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->canonical_domains = strs;
			options->अङ्कः_canonical_domains = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oCanonicalizePermittedCNAMEs:
		प्राप्तम् = options->अङ्कः_permitted_cnames == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
				arg2 = "";
			} अन्यथा यदि (वाक्यं_तुलय(arg, "*") == 0) {
				arg2 = arg;
			} अन्यथा {
				lowercase(arg);
				यदि ((arg2 = strchr(arg, ':')) == रिक्त ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					गच्छ बहिर्गमनम्;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    परिमाण(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		यदि (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->permitted_cnames = cnames;
			options->अङ्कः_permitted_cnames = ncnames;
			cnames = रिक्त; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		भङ्ग;

	पक्ष oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		गच्छ parse_multistate;

	पक्ष oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		गच्छ parse_int;

	पक्ष oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		गच्छ parse_flag;

	पक्ष o_प्रवाहः_Local_Bind_आवरणम्:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		/* Parse mode in octal format */
		मानम् = strtol(arg, &endofnumber, 8);
		यदि (arg == endofnumber || मानम् < 0 || मानम् > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep &&
		    options->fwd_opts.streamlocal_bind_आवरणम् == (बहुलकम्_t)-1)
			options->fwd_opts.streamlocal_bind_आवरणम् = (बहुलकम्_t)मानम्;
		भङ्ग;

	पक्ष o_प्रवाहः_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		गच्छ parse_flag;

	पक्ष o_Revoked_Host_कुञ्चिकाः:
		uintptr = &options->अङ्कः_revoked_host_कुञ्चिकाः;
		cppptr = &options->revoked_host_कुञ्चिकाः;
		प्राप्तम् = *uintptr == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि ((मानम् = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		गच्छ parse_multistate;

	पक्ष oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष o_सङ्कलय_कुञ्चिकाः_गन्तव्यम्_Agent:
		arg = argv_अग्र(&ac, &av);
		arg2 = argv_अग्र(&ac, &av);
		मानम् = parse_multistate_मानम्(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		यदि (मानम् == 3 && arg2 != रिक्त) {
			/* allow "AddKeysToAgent confirm 5m" */
			यदि ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
		} अन्यथा यदि (मानम् == -1 && arg2 == रिक्त) {
			यदि ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
			मानम् = 1; /* yes */
		} अन्यथा यदि (मानम् == -1 || arg2 != रिक्त) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent == -1) {
			options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent = मानम्;
			options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent_lifespan = value2;
		}
		भङ्ग;

	पक्ष o_तटस्थः_Agent:
		charptr = &options->तटस्थः_agent;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
  parse_agent_मार्गः:
		/* Extra validation if the string represents an env var. */
		यदि ((arg2 = dollar_expand(&r, arg)) == रिक्त || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		मुक्त(arg2);
		/* check for legacy environment format */
		यदि (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		गच्छ parse_flag;

	पक्ष oRequiredRSASize:
		intptr = &options->required_rsa_आकार;
		गच्छ parse_int;

	पक्ष oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		गच्छ parse_multistate;

	पक्ष oObscureKeystrokeTiming:
		मानम् = -1;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (मानम् != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				गच्छ बहिर्गमनम्;
			}
			यदि (वाक्यं_तुलय(arg, "yes") == 0 ||
			    वाक्यं_तुलय(arg, "true") == 0)
				मानम् = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			अन्यथा यदि (वाक्यं_तुलय(arg, "no") == 0 ||
			    वाक्यं_तुलय(arg, "false") == 0)
				मानम् = 0;
			अन्यथा यदि (वाक्ये_तुलय(arg, "interval:", 9) == 0) {
				यदि ((errstr = atoi_err(arg + 9,
				    &मानम्)) != रिक्त) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					गच्छ बहिर्गमनम्;
				}
				यदि (मानम् <= 0 || मानम् > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				गच्छ बहिर्गमनम्;
			}
		}
		यदि (मानम् == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oChannelTimeout:
		प्राप्तम् = options->अङ्कः_channel_timeouts == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा यदि (parse_आदर्शः_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->channel_timeouts = strs;
			options->अङ्कः_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष o_संस्करणम्_Addendum:
		यदि (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		यदि (strchr(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		यदि ((arg = strchr(पङ्क्तिः, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(पङ्क्तिः);
		}
		यदि (*activep && options->संस्करणम्_addendum == रिक्त) {
			यदि (strcasecmp(str + len, "none") == 0)
				options->संस्करणम्_addendum = xstrdup("");
			अन्यथा
				options->संस्करणम्_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष oRefuseConnection:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ बहिर्गमनम्;
		}
		यदि (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		भङ्ग;

	पक्ष oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;

	पक्ष oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;

	स्वभाव:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		गच्छ बहिर्गमनम्;
	}

	/* Check that there is no garbage at end of line. */
	यदि (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		गच्छ बहिर्गमनम्;
	}

	/* success */
	ret = 0;
 बहिर्गमनम्:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	प्रत्यागम ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
पूर्णाङ्क
read_config_file(ध्रुव वर्ण *filename, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, Options *options, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass)
{
	पूर्णाङ्क सक्रिय = 1;

	प्रत्यागम read_config_file_गभीरता(filename, pw, host, original_host,
	    remote_command, options, flags, &सक्रिय, want_final_pass, 0);
}

#परिभाषय READCONF_MAX_गभीरता	16
स्थिर पूर्णाङ्क
read_config_file_गभीरता(ध्रुव वर्ण *filename, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    Options *options, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क *want_final_pass, पूर्णाङ्क गभीरता)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त;
	आकार_t linesize = 0;
	पूर्णाङ्क linenum;
	पूर्णाङ्क bad_options = 0;

	यदि (गभीरता < 0 || गभीरता > READCONF_MAX_गभीरता)
		fatal("Too many recursive configuration includes");

	यदि ((f = fopen(filename, "r")) == रिक्त)
		प्रत्यागम 0;

	यदि (flags & SSHCONF_CHECKPERM) {
		संरचना stat sb;

		यदि (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		यदि (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		यदि (process_config_पङ्क्तिः_गभीरता(options, pw, host, original_host,
		    remote_command, पङ्क्तिः, filename, linenum, activep, flags,
		    want_final_pass, गभीरता) != 0)
			bad_options++;
	}
	मुक्त(पङ्क्तिः);
	fclose(f);
	यदि (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	प्रत्यागम 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
पूर्णाङ्क
option_clear_or_none(ध्रुव वर्ण *o)
{
	प्रत्यागम o == रिक्त || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
पूर्णाङ्क
config_has_permitted_cnames(Options *options)
{
	यदि (options->अङ्कः_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    वाक्यं_तुलय(options->permitted_cnames[0].target_list, "") == 0)
		प्रत्यागम 0;
	प्रत्यागम options->अङ्कः_permitted_cnames > 0;
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
	स्मृतिं_पूरय(options, 'X', परिमाण(*options));
	options->host_arg = रिक्त;
	options->forward_agent = -1;
	options->forward_agent_sock_मार्गः = रिक्त;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = रिक्त;
	options->stdio_forward_पत्तनम् = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = रिक्त;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_आवरणम् = (बहुलकम्_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = रिक्त;
	options->hostbased_authentication = -1;
	options->batch_बहुलकम् = -1;
	options->check_host_ip = -1;
	options->strict_host_कुञ्चिका_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->पत्तनम् = -1;
	options->स्थानाङ्कः_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->सङ्ख्या_सम्बन्धि_password_prompts = -1;
	options->ciphers = रिक्त;
	options->macs = रिक्त;
	options->kex_algorithms = रिक्त;
	options->hostkeyalgorithms = रिक्त;
	options->ca_sign_algorithms = रिक्त;
	options->अङ्कः_तटस्थः_files = 0;
	स्मृतिं_पूरय(options->तटस्थः_कुञ्चिकाः, 0, परिमाण(options->तटस्थः_कुञ्चिकाः));
	options->अङ्कः_certificate_files = 0;
	स्मृतिं_पूरय(options->certificates, 0, परिमाण(options->certificates));
	options->hostname = रिक्त;
	options->host_कुञ्चिका_alias = रिक्त;
	options->proxy_command = रिक्त;
	options->jump_user = रिक्त;
	options->jump_host = रिक्त;
	options->jump_पत्तनम् = -1;
	options->jump_extra = रिक्त;
	options->user = रिक्त;
	options->escape_char = -1;
	options->अङ्कः_system_hostfiles = 0;
	options->अङ्कः_user_hostfiles = 0;
	options->local_forwards = रिक्त;
	options->अङ्कः_local_forwards = 0;
	options->remote_forwards = रिक्त;
	options->अङ्कः_remote_forwards = 0;
	options->permitted_remote_opens = रिक्त;
	options->अङ्कः_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_समुच्चयः;
	options->log_level = SYSLOG_LEVEL_NOT_समुच्चयः;
	options->अङ्कः_log_verbose = 0;
	options->log_verbose = रिक्त;
	options->preferred_authentications = रिक्त;
	options->bind_स्थानाङ्कः = रिक्त;
	options->bind_interface = रिक्त;
	options->pkcs11_provider = रिक्त;
	options->sk_provider = रिक्त;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_सीमा = -1;
	options->rekey_interval = -1;
	options->verify_host_कुञ्चिका_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_गणनम्_max = -1;
	options->send_env = रिक्त;
	options->अङ्कः_send_env = 0;
	options->setenv = रिक्त;
	options->अङ्कः_setenv = 0;
	options->control_मार्गः = रिक्त;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_ज्ञातम्_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = रिक्त;
	options->permit_local_command = -1;
	options->remote_command = रिक्त;
	options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent = -1;
	options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent_lifespan = -1;
	options->तटस्थः_agent = रिक्त;
	options->visual_host_कुञ्चिका = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = रिक्त;
	options->अङ्कः_canonical_domains = 0;
	options->अङ्कः_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_कुञ्चिकाः = रिक्त;
	options->अङ्कः_revoked_host_कुञ्चिकाः = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = रिक्त;
	options->pubkey_accepted_algos = रिक्त;
	options->ज्ञातम्_hosts_command = रिक्त;
	options->required_rsa_आकार = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->चिह्नकम् = रिक्त;
	options->channel_timeouts = रिक्त;
	options->अङ्कः_channel_timeouts = 0;
	options->संस्करणम्_addendum = रिक्त;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
शून्य
fill_default_options_for_canonicalization(Options *options)
{
	यदि (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	यदि (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	यदि (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
पूर्णाङ्क
fill_default_options(Options * options)
{
	वर्ण *all_cipher, *all_mac, *all_kex, *all_कुञ्चिका, *all_sig;
	वर्ण *def_cipher, *def_mac, *def_kex, *def_कुञ्चिका, *def_sig;
	पूर्णाङ्क ret = -1, r;

	यदि (options->forward_agent == -1)
		options->forward_agent = 0;
	यदि (options->forward_x11 == -1)
		options->forward_x11 = 0;
	यदि (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	यदि (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	यदि (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	यदि (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	यदि (options->clear_forwardings == 1)
		clear_forwardings(options);

	यदि (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(मार्गः_XAUTH);
	यदि (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	यदि (options->fwd_opts.streamlocal_bind_आवरणम् == (बहुलकम्_t)-1)
		options->fwd_opts.streamlocal_bind_आवरणम् = 0177;
	यदि (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	यदि (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	यदि (options->gss_authentication == -1)
		options->gss_authentication = 0;
	यदि (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	यदि (options->password_authentication == -1)
		options->password_authentication = 1;
	यदि (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	यदि (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	यदि (options->batch_बहुलकम् == -1)
		options->batch_बहुलकम् = 0;
	यदि (options->check_host_ip == -1)
		options->check_host_ip = 0;
	यदि (options->strict_host_कुञ्चिका_checking == -1)
		options->strict_host_कुञ्चिका_checking = SSH_STRICT_HOSTKEY_ASK;
	यदि (options->compression == -1)
		options->compression = 0;
	यदि (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	यदि (options->पत्तनम् == -1)
		options->पत्तनम् = 0;	/* Filled in ssh_connect. */
	यदि (options->स्थानाङ्कः_family == -1)
		options->स्थानाङ्कः_family = AF_UNSPEC;
	यदि (options->connection_attempts == -1)
		options->connection_attempts = 1;
	यदि (options->सङ्ख्या_सम्बन्धि_password_prompts == -1)
		options->सङ्ख्या_सम्बन्धि_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	यदि (options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent == -1) {
		options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent = 0;
		options->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent_lifespan = 0;
	}
	यदि (options->अङ्कः_तटस्थः_files == 0) {
		सङ्कलय_तटस्थः_file(options, "~/", मार्गः_SSH_CLIENT_ID_RSA, 0);
		सङ्कलय_तटस्थः_file(options, "~/", मार्गः_SSH_CLIENT_ID_ECDSA, 0);
		सङ्कलय_तटस्थः_file(options, "~/",
		    मार्गः_SSH_CLIENT_ID_ECDSA_SK, 0);
		सङ्कलय_तटस्थः_file(options, "~/",
		    मार्गः_SSH_CLIENT_ID_ED25519, 0);
		सङ्कलय_तटस्थः_file(options, "~/",
		    मार्गः_SSH_CLIENT_ID_ED25519_SK, 0);
		सङ्कलय_तटस्थः_file(options, "~/",
		    मार्गः_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	यदि (options->escape_char == -1)
		options->escape_char = '~';
	यदि (options->अङ्कः_system_hostfiles == 0) {
		options->system_hostfiles[options->अङ्कः_system_hostfiles++] =
		    xstrdup(मार्गः_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->अङ्कः_system_hostfiles++] =
		    xstrdup(मार्गः_SSH_SYSTEM_HOSTFILE2);
	}
	यदि (options->update_hostkeys == -1) {
		यदि (options->verify_host_कुञ्चिका_dns <= 0 &&
		    (options->अङ्कः_user_hostfiles == 0 ||
		    (options->अङ्कः_user_hostfiles == 1 && वाक्यं_तुलय(options->
		    user_hostfiles[0], मार्गः_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		अन्यथा
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	यदि (options->अङ्कः_user_hostfiles == 0) {
		options->user_hostfiles[options->अङ्कः_user_hostfiles++] =
		    xstrdup(मार्गः_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->अङ्कः_user_hostfiles++] =
		    xstrdup(मार्गः_SSH_USER_HOSTFILE2);
	}
	यदि (options->log_level == SYSLOG_LEVEL_NOT_समुच्चयः)
		options->log_level = SYSLOG_LEVEL_INFO;
	यदि (options->log_facility == SYSLOG_FACILITY_NOT_समुच्चयः)
		options->log_facility = SYSLOG_FACILITY_USER;
	यदि (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	यदि (options->identities_only == -1)
		options->identities_only = 0;
	यदि (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	यदि (options->rekey_सीमा == -1)
		options->rekey_सीमा = 0;
	यदि (options->rekey_interval == -1)
		options->rekey_interval = 0;
	यदि (options->verify_host_कुञ्चिका_dns == -1)
		options->verify_host_कुञ्चिका_dns = 0;
	यदि (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	यदि (options->server_alive_गणनम्_max == -1)
		options->server_alive_गणनम्_max = 3;
	यदि (options->control_master == -1)
		options->control_master = 0;
	यदि (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	यदि (options->hash_ज्ञातम्_hosts == -1)
		options->hash_ज्ञातम्_hosts = 0;
	यदि (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	यदि (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	यदि (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	यदि (options->permit_local_command == -1)
		options->permit_local_command = 0;
	यदि (options->visual_host_कुञ्चिका == -1)
		options->visual_host_कुञ्चिका = 0;
	यदि (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	यदि (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	यदि (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	यदि (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	यदि (options->stdin_null == -1)
		options->stdin_null = 0;
	यदि (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	यदि (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	यदि (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	यदि (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	यदि (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	यदि (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#यदि_परिभाषितम् ENABLE_SK_आन्तरिकम्
	यदि (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
#अन्यथा
	यदि (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#यदि_अन्तः
	यदि (options->required_rsa_आकार == -1)
		options->required_rsa_आकार = SSH_RSA_MINIMUM_MODULUS_आकार;
	यदि (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	यदि (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	यदि (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = मेलनम्_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = मेलनम्_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = मेलनम्_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_कुञ्चिका = मेलनम्_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
	def_sig = मेलनम्_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#परिभाषय ASSEMBLE(what, defaults, all) \
	कुरु { \
		यदि ((r = kex_assemble_नामानि(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			गच्छ fail; \
		} \
	} यावत् (0)
	options->kex_algorithms_समुच्चयः = options->kex_algorithms != रिक्त;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(pubkey_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#अपरिभाषय ASSEMBLE

#परिभाषय CLEAR_ON_NONE(v) \
	कुरु { \
		यदि (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} यावत्(0)
#परिभाषय CLEAR_ON_NONE_ARRAY(v, nv, none) \
	कुरु { \
		यदि (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} यावत् (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_मार्गः);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->ज्ञातम्_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, अङ्कः_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_कुञ्चिकाः, अङ्कः_revoked_host_कुञ्चिकाः, "none");
#अपरिभाषय CLEAR_ON_NONE
#अपरिभाषय CLEAR_ON_NONE_ARRAY
	यदि (options->jump_host != रिक्त &&
	    वाक्यं_तुलय(options->jump_host, "none") == 0 &&
	    options->jump_पत्तनम् == 0 && options->jump_user == रिक्त) {
		मुक्त(options->jump_host);
		options->jump_host = रिक्त;
	}
	यदि (options->अङ्कः_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		मुक्त(options->permitted_cnames[0].source_list);
		मुक्त(options->permitted_cnames[0].target_list);
		स्मृतिं_पूरय(options->permitted_cnames, '\0',
		    परिमाण(*options->permitted_cnames));
		options->अङ्कः_permitted_cnames = 0;
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
	मुक्त(all_कुञ्चिका);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुञ्चिका);
	मुक्त(def_sig);
	प्रत्यागम ret;
}

शून्य
free_options(Options *o)
{
	पूर्णाङ्क i;

	यदि (o == रिक्त)
		प्रत्यागम;

#परिभाषय FREE_ARRAY(type, n, a) \
	कुरु { \
		type _i; \
		प्रति (_i = 0; _i < (n); _i++) \
			मुक्त((a)[_i]); \
	} यावत् (0)

	मुक्त(o->forward_agent_sock_मार्गः);
	मुक्त(o->xauth_location);
	FREE_ARRAY(u_int, o->अङ्कः_log_verbose, o->log_verbose);
	मुक्त(o->log_verbose);
	मुक्त(o->ciphers);
	मुक्त(o->macs);
	मुक्त(o->hostkeyalgorithms);
	मुक्त(o->kex_algorithms);
	मुक्त(o->ca_sign_algorithms);
	मुक्त(o->hostname);
	मुक्त(o->host_कुञ्चिका_alias);
	मुक्त(o->proxy_command);
	मुक्त(o->user);
	FREE_ARRAY(u_int, o->अङ्कः_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->अङ्कः_user_hostfiles, o->user_hostfiles);
	मुक्त(o->preferred_authentications);
	मुक्त(o->bind_स्थानाङ्कः);
	मुक्त(o->bind_interface);
	मुक्त(o->pkcs11_provider);
	मुक्त(o->sk_provider);
	प्रति (i = 0; i < o->अङ्कः_तटस्थः_files; i++) {
		मुक्त(o->तटस्थः_files[i]);
		sshkey_free(o->तटस्थः_कुञ्चिकाः[i]);
	}
	प्रति (i = 0; i < o->अङ्कः_certificate_files; i++) {
		मुक्त(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	मुक्त(o->तटस्थः_agent);
	प्रति (i = 0; i < o->अङ्कः_local_forwards; i++) {
		मुक्त(o->local_forwards[i].listen_host);
		मुक्त(o->local_forwards[i].listen_मार्गः);
		मुक्त(o->local_forwards[i].connect_host);
		मुक्त(o->local_forwards[i].connect_मार्गः);
	}
	मुक्त(o->local_forwards);
	प्रति (i = 0; i < o->अङ्कः_remote_forwards; i++) {
		मुक्त(o->remote_forwards[i].listen_host);
		मुक्त(o->remote_forwards[i].listen_मार्गः);
		मुक्त(o->remote_forwards[i].connect_host);
		मुक्त(o->remote_forwards[i].connect_मार्गः);
	}
	मुक्त(o->remote_forwards);
	मुक्त(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->अङ्कः_send_env, o->send_env);
	मुक्त(o->send_env);
	FREE_ARRAY(u_int, o->अङ्कः_setenv, o->setenv);
	मुक्त(o->setenv);
	मुक्त(o->control_मार्गः);
	मुक्त(o->local_command);
	मुक्त(o->remote_command);
	FREE_ARRAY(पूर्णाङ्क, o->अङ्कः_canonical_domains, o->canonical_domains);
	प्रति (i = 0; i < o->अङ्कः_permitted_cnames; i++) {
		मुक्त(o->permitted_cnames[i].source_list);
		मुक्त(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->अङ्कः_revoked_host_कुञ्चिकाः, o->revoked_host_कुञ्चिकाः);
	मुक्त(o->revoked_host_कुञ्चिकाः);
	मुक्त(o->hostbased_accepted_algos);
	मुक्त(o->pubkey_accepted_algos);
	मुक्त(o->jump_user);
	मुक्त(o->jump_host);
	मुक्त(o->jump_extra);
	मुक्त(o->ignored_unknown);
	explicit_bzero(o, परिमाण(*o));
#अपरिभाषय FREE_ARRAY
}

संरचना fwdarg {
	वर्ण *arg;
	पूर्णाङ्क ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
स्थिर पूर्णाङ्क
parse_fwd_क्षेत्रम्(वर्ण **p, संरचना fwdarg *fwd)
{
	वर्ण *ep, *cp = *p;
	पूर्णाङ्क ispath = 0;

	यदि (*cp == '\0') {
		*p = रिक्त;
		प्रत्यागम -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	यदि (*cp == '[') {
		/* find matching ']' */
		प्रति (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			यदि (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		यदि (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			प्रत्यागम -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		यदि (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		प्रत्यागम 0;
	}

	प्रति (cp = *p; *cp != '\0'; cp++) {
		विकल्प (*cp) {
		पक्ष '\\':
			memmove(cp, cp + 1, वाक्यदैर्घ्यम्(cp + 1) + 1);
			यदि (*cp == '\0')
				प्रत्यागम -1;
			भङ्ग;
		पक्ष '/':
			ispath = 1;
			भङ्ग;
		पक्ष ':':
			*cp++ = '\0';
			गच्छ समाप्तम्;
		}
	}
समाप्तम्:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	प्रत्यागम 0;
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
पूर्णाङ्क
parse_forward(संरचना Forward *fwd, ध्रुव वर्ण *fwdspec, पूर्णाङ्क dynamicfwd, पूर्णाङ्क remotefwd)
{
	संरचना fwdarg fwdargs[4];
	वर्ण *p, *cp;
	पूर्णाङ्क i, err;

	स्मृतिं_पूरय(fwd, 0, परिमाण(*fwd));
	स्मृतिं_पूरय(fwdargs, 0, परिमाण(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	यदि (p == रिक्त || err)
		प्रत्यागम 0;

	/* skip leading spaces */
	यावत् (रिक्तम्_वा((u_char)*cp))
		cp++;

	प्रति (i = 0; i < 4; ++i) {
		यदि (parse_fwd_क्षेत्रम्(&cp, &fwdargs[i]) != 0)
			भङ्ग;
	}

	/* Check for trailing garbage */
	यदि (cp != रिक्त && *cp != '\0') {
		i = 0;	/* failure */
	}

	विकल्प (i) {
	पक्ष 1:
		यदि (fwdargs[0].ispath) {
			fwd->listen_मार्गः = xstrdup(fwdargs[0].arg);
			fwd->listen_पत्तनम् = पत्तनम्_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = रिक्त;
			fwd->listen_पत्तनम् = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		भङ्ग;

	पक्ष 2:
		यदि (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_मार्गः = xstrdup(fwdargs[0].arg);
			fwd->listen_पत्तनम् = पत्तनम्_STREAMLOCAL;
			fwd->connect_मार्गः = xstrdup(fwdargs[1].arg);
			fwd->connect_पत्तनम् = पत्तनम्_STREAMLOCAL;
		} अन्यथा यदि (fwdargs[1].ispath) {
			fwd->listen_host = रिक्त;
			fwd->listen_पत्तनम् = a2port(fwdargs[0].arg);
			fwd->connect_मार्गः = xstrdup(fwdargs[1].arg);
			fwd->connect_पत्तनम् = पत्तनम्_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_पत्तनम् = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		भङ्ग;

	पक्ष 3:
		यदि (fwdargs[0].ispath) {
			fwd->listen_मार्गः = xstrdup(fwdargs[0].arg);
			fwd->listen_पत्तनम् = पत्तनम्_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_पत्तनम् = a2port(fwdargs[2].arg);
		} अन्यथा यदि (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_पत्तनम् = a2port(fwdargs[1].arg);
			fwd->connect_मार्गः = xstrdup(fwdargs[2].arg);
			fwd->connect_पत्तनम् = पत्तनम्_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = रिक्त;
			fwd->listen_पत्तनम् = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_पत्तनम् = a2port(fwdargs[2].arg);
		}
		भङ्ग;

	पक्ष 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_पत्तनम् = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_पत्तनम् = a2port(fwdargs[3].arg);
		भङ्ग;
	स्वभाव:
		i = 0; /* failure */
	}

	मुक्त(p);

	यदि (dynamicfwd) {
		यदि (!(i == 1 || i == 2))
			गच्छ fail_free;
	} अन्यथा {
		यदि (!(i == 3 || i == 4)) {
			यदि (fwd->connect_मार्गः == रिक्त &&
			    fwd->listen_मार्गः == रिक्त)
				गच्छ fail_free;
		}
		यदि (fwd->connect_पत्तनम् <= 0 && fwd->connect_मार्गः == रिक्त)
			गच्छ fail_free;
	}

	यदि ((fwd->listen_पत्तनम् < 0 && fwd->listen_मार्गः == रिक्त) ||
	    (!remotefwd && fwd->listen_पत्तनम् == 0))
		गच्छ fail_free;
	यदि (fwd->connect_host != रिक्त &&
	    वाक्यदैर्घ्यम्(fwd->connect_host) >= NI_MAXHOST)
		गच्छ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	यदि (fwd->connect_मार्गः != रिक्त &&
	    वाक्यदैर्घ्यम्(fwd->connect_मार्गः) >= मार्गः_MAX_SUN)
		गच्छ fail_free;
	यदि (fwd->listen_host != रिक्त &&
	    वाक्यदैर्घ्यम्(fwd->listen_host) >= NI_MAXHOST)
		गच्छ fail_free;
	यदि (fwd->listen_मार्गः != रिक्त &&
	    वाक्यदैर्घ्यम्(fwd->listen_मार्गः) >= मार्गः_MAX_SUN)
		गच्छ fail_free;

	प्रत्यागम (i);

 fail_free:
	मुक्त(fwd->connect_host);
	fwd->connect_host = रिक्त;
	मुक्त(fwd->connect_मार्गः);
	fwd->connect_मार्गः = रिक्त;
	मुक्त(fwd->listen_host);
	fwd->listen_host = रिक्त;
	मुक्त(fwd->listen_मार्गः);
	fwd->listen_मार्गः = रिक्त;
	प्रत्यागम (0);
}

पूर्णाङ्क
ssh_valid_hostname(ध्रुव वर्ण *s)
{
	आकार_t i;

	यदि (*s == '-')
		प्रत्यागम 0;
	प्रति (i = 0; s[i] != 0; i++) {
		यदि (strchr("'`\"$\\;&<>|(){},", s[i]) != रिक्त ||
		    रिक्तम्_वा((u_char)s[i]) || iscntrl((u_char)s[i]))
			प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

पूर्णाङ्क
ssh_valid_ruser(ध्रुव वर्ण *s)
{
	आकार_t i;

	यदि (*s == '-')
		प्रत्यागम 0;
	प्रति (i = 0; s[i] != 0; i++) {
		यदि (iscntrl((u_char)s[i]))
			प्रत्यागम 0;
		यदि (strchr("'`\";&<>|(){}$\\", s[i]) != रिक्त)
			प्रत्यागम 0;
		/* Disallow '-' after whitespace */
		यदि (रिक्तम्_वा((u_char)s[i]) && s[i + 1] == '-')
			प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

पूर्णाङ्क
parse_jump(ध्रुव वर्ण *s, Options *o, पूर्णाङ्क strict, पूर्णाङ्क सक्रिय)
{
	वर्ण *orig = रिक्त, *sdup = रिक्त, *cp;
	वर्ण *tmp_user = रिक्त, *tmp_host = रिक्त, *host = रिक्त, *user = रिक्त;
	पूर्णाङ्क r, ret = -1, tmp_पत्तनम् = -1, पत्तनम् = -1, first = 1;

	यदि (strcasecmp(s, "none") == 0) {
		यदि (सक्रिय && o->jump_host == रिक्त) {
			o->jump_host = xstrdup("none");
			o->jump_पत्तनम् = 0;
		}
		प्रत्यागम 0;
	}

	orig = xstrdup(s);
	यदि ((cp = strchr(orig, '#')) != रिक्त)
		*cp = '\0';
	rtrim(orig);

	सक्रिय &= o->proxy_command == रिक्त && o->jump_host == रिक्त;
	sdup = xstrdup(orig);
	कुरु {
		/* Work backwards through string */
		यदि ((cp = strrchr(sdup, ',')) == रिक्त)
			cp = sdup; /*चरमः*/
		अन्यथा
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_पत्तनम्);
		यदि (r == -1 || (r == 1 && parse_user_host_पत्तनम्(cp,
		    &tmp_user, &tmp_host, &tmp_पत्तनम्) != 0))
			गच्छ बहिर्गमनम्; /* error already logged */
		यदि (strict) {
			यदि (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				गच्छ बहिर्गमनम्;
			}
			यदि (tmp_user != रिक्त && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				गच्छ बहिर्गमनम्;
			}
		}
		यदि (first) {
			user = tmp_user;
			host = tmp_host;
			पत्तनम् = tmp_पत्तनम्;
			tmp_user = tmp_host = रिक्त; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		मुक्त(tmp_user);
		मुक्त(tmp_host);
		tmp_user = tmp_host = रिक्त;
		tmp_पत्तनम् = -1;
	} यावत् (cp != sdup);

	/* success */
	यदि (सक्रिय) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_पत्तनम् = पत्तनम्;
		o->proxy_command = xstrdup("none");
		user = host = रिक्त; /* transferred */
		यदि (orig != रिक्त && (cp = strrchr(orig, ',')) != रिक्त) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 बहिर्गमनम्:
	मुक्त(orig);
	मुक्त(sdup);
	मुक्त(tmp_user);
	मुक्त(tmp_host);
	मुक्त(user);
	मुक्त(host);
	प्रत्यागम ret;
}

पूर्णाङ्क
parse_ssh_uri(ध्रुव वर्ण *uri, वर्ण **userp, वर्ण **hostp, पूर्णाङ्क *portp)
{
	वर्ण *user = रिक्त, *host = रिक्त, *मार्गः = रिक्त;
	पूर्णाङ्क r, पत्तनम्;

	r = parse_uri("ssh", uri, &user, &host, &पत्तनम्, &मार्गः);
	यदि (r == 0 && मार्गः != रिक्त)
		r = -1;		/* path not allowed */
	यदि (r == 0) {
		यदि (userp != रिक्त) {
			*userp = user;
			user = रिक्त;
		}
		यदि (hostp != रिक्त) {
			*hostp = host;
			host = रिक्त;
		}
		यदि (portp != रिक्त)
			*portp = पत्तनम्;
	}
	मुक्त(user);
	मुक्त(host);
	मुक्त(मार्गः);
	प्रत्यागम r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
स्थिर ध्रुव वर्ण *
fmt_multistate_int(पूर्णाङ्क val, ध्रुव संरचना multistate *m)
{
	u_int i;

	प्रति (i = 0; m[i].कुञ्चिका != रिक्त; i++) {
		यदि (m[i].मानम् == val)
			प्रत्यागम m[i].कुञ्चिका;
	}
	प्रत्यागम "UNKNOWN";
}

स्थिर ध्रुव वर्ण *
fmt_intarg(OpCodes संहिता, पूर्णाङ्क val)
{
	यदि (val == -1)
		प्रत्यागम "unset";
	विकल्प (संहिता) {
	पक्ष o_स्थानाङ्कः_Family:
		प्रत्यागम fmt_multistate_int(val, multistate_addressfamily);
	पक्ष oCompression:
		प्रत्यागम fmt_multistate_int(val, multistate_compression);
	पक्ष o_Verify_Host_कुञ्चिका_DNS:
	पक्ष oUpdateHostkeys:
		प्रत्यागम fmt_multistate_int(val, multistate_yesnoask);
	पक्ष o_Strict_Host_कुञ्चिका_Checking:
		प्रत्यागम fmt_multistate_int(val, multistate_strict_hostkey);
	पक्ष oControlMaster:
		प्रत्यागम fmt_multistate_int(val, multistate_controlmaster);
	पक्ष oTunnel:
		प्रत्यागम fmt_multistate_int(val, multistate_tunnel);
	पक्ष oRequestTTY:
		प्रत्यागम fmt_multistate_int(val, multistate_requesttty);
	पक्ष oSessionType:
		प्रत्यागम fmt_multistate_int(val, multistate_sessiontype);
	पक्ष oCanonicalizeHostname:
		प्रत्यागम fmt_multistate_int(val, multistate_canonicalizehostname);
	पक्ष o_सङ्कलय_कुञ्चिकाः_गन्तव्यम्_Agent:
		प्रत्यागम fmt_multistate_int(val, multistate_yesnoaskconfirm);
	पक्ष oPubkeyAuthentication:
		प्रत्यागम fmt_multistate_int(val, multistate_pubkey_auth);
	पक्ष oTCPKeepAlive:
		प्रत्यागम fmt_multistate_int(val, multistate_keepalives);
	पक्ष oFingerprintHash:
		प्रत्यागम ssh_digest_alg_name(val);
	स्वभाव:
		विकल्प (val) {
		पक्ष 0:
			प्रत्यागम "no";
		पक्ष 1:
			प्रत्यागम "yes";
		स्वभाव:
			प्रत्यागम "UNKNOWN";
		}
	}
}

स्थिर ध्रुव वर्ण *
lookup_opcode_name(OpCodes संहिता)
{
	u_int i;

	प्रति (i = 0; keywords[i].name != रिक्त; i++)
		यदि (keywords[i].opcode == संहिता)
			प्रत्यागम(keywords[i].name);
	प्रत्यागम "UNKNOWN";
}

स्थिर शून्य
dump_cfg_int(OpCodes संहिता, पूर्णाङ्क val)
{
	यदि (संहिता == oObscureKeystrokeTiming) {
		यदि (val == 0) {
			प्रारूप_लिख("%s no\n", lookup_opcode_name(संहिता));
			प्रत्यागम;
		} अन्यथा यदि (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			प्रारूप_लिख("%s yes\n", lookup_opcode_name(संहिता));
			प्रत्यागम;
		}
		/* FALLTHROUGH */
	}
	प्रारूप_लिख("%s %d\n", lookup_opcode_name(संहिता), val);
}

स्थिर शून्य
dump_cfg_fmtint(OpCodes संहिता, पूर्णाङ्क val)
{
	प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता), fmt_intarg(संहिता, val));
}

स्थिर शून्य
dump_cfg_string(OpCodes संहिता, ध्रुव वर्ण *val)
{
	यदि (val == रिक्त)
		प्रत्यागम;
	प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता), val);
}

स्थिर शून्य
dump_cfg_strarray(OpCodes संहिता, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	प्रति (i = 0; i < गणनम्; i++)
		प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(OpCodes संहिता, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	प्रारूप_लिख("%s", lookup_opcode_name(संहिता));
	यदि (गणनम् == 0)
		प्रारूप_लिख(" none");
	प्रति (i = 0; i < गणनम्; i++)
		प्रारूप_लिख(" %s",  vals[i]);
	प्रारूप_लिख("\n");
}

स्थिर शून्य
dump_cfg_forwards(OpCodes संहिता, u_int गणनम्, ध्रुव संरचना Forward *fwds)
{
	ध्रुव संरचना Forward *fwd;
	u_int i;

	/* oDynamicForward */
	प्रति (i = 0; i < गणनम्; i++) {
		fwd = &fwds[i];
		यदि (संहिता == oDynamicForward && fwd->connect_host != रिक्त &&
		    वाक्यं_तुलय(fwd->connect_host, "socks") != 0)
			अनुवर्त;
		यदि (संहिता == oLocalForward && fwd->connect_host != रिक्त &&
		    वाक्यं_तुलय(fwd->connect_host, "socks") == 0)
			अनुवर्त;
		प्रारूप_लिख("%s", lookup_opcode_name(संहिता));
		यदि (fwd->listen_पत्तनम् == पत्तनम्_STREAMLOCAL)
			प्रारूप_लिख(" %s", fwd->listen_मार्गः);
		अन्यथा यदि (fwd->listen_host == रिक्त)
			प्रारूप_लिख(" %d", fwd->listen_पत्तनम्);
		अन्यथा {
			प्रारूप_लिख(" [%s]:%d",
			    fwd->listen_host, fwd->listen_पत्तनम्);
		}
		यदि (संहिता != oDynamicForward) {
			यदि (fwd->connect_पत्तनम् == पत्तनम्_STREAMLOCAL)
				प्रारूप_लिख(" %s", fwd->connect_मार्गः);
			अन्यथा यदि (fwd->connect_host == रिक्त)
				प्रारूप_लिख(" %d", fwd->connect_पत्तनम्);
			अन्यथा {
				प्रारूप_लिख(" [%s]:%d",
				    fwd->connect_host, fwd->connect_पत्तनम्);
			}
		}
		प्रारूप_लिख("\n");
	}
}

शून्य
dump_client_config(Options *o, ध्रुव वर्ण *host)
{
	पूर्णाङ्क i, r;
	वर्ण buf[8], *all_कुञ्चिका;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	यदि ((r = kex_assemble_नामानि(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_कुञ्चिका)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	मुक्त(all_कुञ्चिका);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_पत्तनम्, o->पत्तनम्);

	/* Flag options */
	dump_cfg_fmtint(o_स्थानाङ्कः_Family, o->स्थानाङ्कः_family);
	dump_cfg_fmtint(o_Batch_बहुलकम्, o->batch_बहुलकम्);
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
#यदि_परिभाषितम् GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#यदि_अन्तः /* GSSAPI */
	dump_cfg_fmtint(o_Hash_ज्ञातम्_Hosts, o->hash_ज्ञातम्_hosts);
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
	dump_cfg_fmtint(o_प्रवाहः_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_कुञ्चिका_Checking, o->strict_host_कुञ्चिका_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_कुञ्चिका_DNS, o->verify_host_कुञ्चिका_dns);
	dump_cfg_fmtint(o_Visual_Host_कुञ्चिका, o->visual_host_कुञ्चिका);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_सङ्ख्या_सम्बन्धि_Password_Prompts, o->सङ्ख्या_सम्बन्धि_password_prompts);
	dump_cfg_int(o_Server_Alive_गणनम्_Max, o->server_alive_गणनम्_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_आकार);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_स्थानाङ्कः, o->bind_स्थानाङ्कः);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_मार्गः, o->control_मार्गः);
	dump_cfg_string(o_Host_कुञ्चिका_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_कुञ्चिका_Alias, o->host_कुञ्चिका_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_तटस्थः_Agent, o->तटस्थः_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#यदि_परिभाषितम् ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#यदि_अन्तः
	dump_cfg_string(o_Security_कुञ्चिका_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_ज्ञातम्_Hosts_Command, o->ज्ञातम्_hosts_command);
	dump_cfg_string(o_चिह्नकम्, o->चिह्नकम्);
	dump_cfg_string(o_संस्करणम्_Addendum, o->संस्करणम्_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->अङ्कः_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->अङ्कः_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->अङ्कः_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_तटस्थः_File, o->अङ्कः_तटस्थः_files, o->तटस्थः_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->अङ्कः_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->अङ्कः_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_ज्ञातम्_Hosts_File, o->अङ्कः_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_ज्ञातम्_Hosts_File, o->अङ्कः_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_कुञ्चिकाः, o->अङ्कः_revoked_host_कुञ्चिकाः, o->revoked_host_कुञ्चिकाः);
	dump_cfg_strarray(oSendEnv, o->अङ्कः_send_env, o->send_env);
	dump_cfg_strarray(o_समुच्चयः_Env, o->अङ्कः_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->अङ्कः_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->अङ्कः_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	यदि (o->अङ्कः_permitted_remote_opens == 0)
		प्रारूप_लिख("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	अन्यथा
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->अङ्कः_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	यदि (o->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent_lifespan <= 0)
		dump_cfg_fmtint(o_सङ्कलय_कुञ्चिकाः_गन्तव्यम्_Agent, o->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent);
	अन्यथा {
		प्रारूप_लिख("addkeystoagent%s %d\n",
		    o->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent == 3 ? " confirm" : "",
		    o->सङ्कलय_कुञ्चिकाः_गन्तव्यम्_agent_lifespan);
	}

	/* oForwardAgent */
	यदि (o->forward_agent_sock_मार्गः == रिक्त)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	अन्यथा
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_मार्गः);

	/* oConnectTimeout */
	यदि (o->connection_timeout == -1)
		प्रारूप_लिख("connecttimeout none\n");
	अन्यथा
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	प्रारूप_लिख("tunneldevice");
	यदि (o->tun_local == SSH_TUNID_ANY)
		प्रारूप_लिख(" any");
	अन्यथा
		प्रारूप_लिख(" %d", o->tun_local);
	यदि (o->tun_remote == SSH_TUNID_ANY)
		प्रारूप_लिख(":any");
	अन्यथा
		प्रारूप_लिख(":%d", o->tun_remote);
	प्रारूप_लिख("\n");

	/* oCanonicalizePermittedCNAMEs */
	प्रारूप_लिख("canonicalizepermittedcnames");
	यदि (o->अङ्कः_permitted_cnames == 0)
		प्रारूप_लिख(" none");
	प्रति (i = 0; i < o->अङ्कः_permitted_cnames; i++) {
		प्रारूप_लिख(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	प्रारूप_लिख("\n");

	/* oControlPersist */
	यदि (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	अन्यथा
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	यदि (o->escape_char == SSH_ESCAPECHAR_NONE)
		प्रारूप_लिख("escapechar none\n");
	अन्यथा {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		प्रारूप_लिख("escapechar %s\n", buf);
	}

	/* oIPQoS */
	प्रारूप_लिख("ipqos %s ", iptos2str(o->ip_qos_interactive));
	प्रारूप_लिख("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	प्रारूप_लिख("rekeylimit %llu %d\n",
	    (अचिह्नित दीर्घ दीर्घ)o->rekey_सीमा, o->rekey_interval);

	/* oStreamLocalBindMask */
	प्रारूप_लिख("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_आवरणम्);

	/* oLogFacility */
	प्रारूप_लिख("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	यदि (o->jump_host == रिक्त)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	अन्यथा {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != रिक्त ||
		    strspn(o->jump_host, "1234567890.") == वाक्यदैर्घ्यम्(o->jump_host);
		snprintf(buf, परिमाण(buf), "%d", o->jump_पत्तनम्);
		प्रारूप_लिख("proxyjump %s%s%s%s%s%s%s%s%s\n",
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
		    o->jump_पत्तनम् <= 0 ? "" : ":",
		    o->jump_पत्तनम् <= 0 ? "" : buf);
	}
}
