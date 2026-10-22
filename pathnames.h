/* $OpenBSD: pathnames.h,v 1.38 2026/09/16 00:25:50 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#परिभाषय ETCDIR				"/etc"

#यदि_अपरिभाषितम् SSHDIR
#परिभाषय SSHDIR				ETCDIR "/ssh"
#यदि_अन्तः

#यदि_अपरिभाषितम् मार्गः_SSH_PIDDIR
#परिभाषय मार्गः_SSH_PIDDIR		"/var/run"
#यदि_अन्तः

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#परिभाषय मार्गः_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#परिभाषय मार्गः_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#परिभाषय मार्गः_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#परिभाषय मार्गः_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#परिभाषय मार्गः_HOST_ECDSA_कुञ्चिका_FILE	SSHDIR "/ssh_host_ecdsa_key"
#परिभाषय मार्गः_HOST_RSA_कुञ्चिका_FILE		SSHDIR "/ssh_host_rsa_key"
#परिभाषय मार्गः_HOST_ED25519_कुञ्चिका_FILE	SSHDIR "/ssh_host_ed25519_key"
#परिभाषय मार्गः_HOST_MLDSA44_ED25519_कुञ्चिका_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#परिभाषय मार्गः_DH_MODULI			SSHDIR "/moduli"

#यदि_अपरिभाषितम् मार्गः_SSH_क्रमादेशः
#परिभाषय मार्गः_SSH_क्रमादेशः		"/usr/bin/ssh"
#यदि_अन्तः

/* Binary paths for the sshd components */
#यदि_अपरिभाषितम् मार्गः_SSHD_SESSION
#परिभाषय मार्गः_SSHD_SESSION		"/usr/libexec/sshd-session"
#यदि_अन्तः
#यदि_अपरिभाषितम् मार्गः_SSHD_AUTH
#परिभाषय मार्गः_SSHD_AUTH			"/usr/libexec/sshd-auth"
#यदि_अन्तः

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#परिभाषय मार्गः_SSH_DAEMON_PID_FILE	मार्गः_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#परिभाषय मार्गः_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#परिभाषय मार्गः_SSH_AGENT_SOCKET_DIR	"user:" मार्गः_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#परिभाषय मार्गः_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#परिभाषय मार्गः_SSH_USER_HOSTFILE		"~/" मार्गः_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#परिभाषय मार्गः_SSH_USER_HOSTFILE2	"~/" मार्गः_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#परिभाषय मार्गः_SSH_CLIENT_ID_ECDSA	मार्गः_SSH_USER_DIR "/id_ecdsa"
#परिभाषय मार्गः_SSH_CLIENT_ID_RSA		मार्गः_SSH_USER_DIR "/id_rsa"
#परिभाषय मार्गः_SSH_CLIENT_ID_ED25519	मार्गः_SSH_USER_DIR "/id_ed25519"
#परिभाषय मार्गः_SSH_CLIENT_ID_ECDSA_SK	मार्गः_SSH_USER_DIR "/id_ecdsa_sk"
#परिभाषय मार्गः_SSH_CLIENT_ID_ED25519_SK	मार्गः_SSH_USER_DIR "/id_ed25519_sk"
#परिभाषय मार्गः_SSH_CLIENT_ID_MLDSA44_ED25519 मार्गः_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#परिभाषय मार्गः_SSH_USER_CONFFILE		मार्गः_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#परिभाषय मार्गः_SSH_USER_PERMITTED_कुञ्चिकाः	मार्गः_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#परिभाषय मार्गः_SSH_USER_PERMITTED_KEYS2	मार्गः_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#परिभाषय मार्गः_SSH_USER_RC		मार्गः_SSH_USER_DIR "/rc"
#परिभाषय मार्गः_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#परिभाषय मार्गः_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#परिभाषय मार्गः_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#यदि_अपरिभाषितम् मार्गः_SSH_ASKPASS_DEFAULT
#परिभाषय मार्गः_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#यदि_अन्तः

/* Location of ssh-keysign for hostbased authentication */
#यदि_अपरिभाषितम् मार्गः_SSH_कुञ्चिका_SIGN
#परिभाषय मार्गः_SSH_कुञ्चिका_SIGN		"/usr/libexec/ssh-keysign"
#यदि_अन्तः

/* Location of ssh-pkcs11-helper to support keys in tokens */
#यदि_अपरिभाषितम् मार्गः_SSH_PKCS11_HELPER
#परिभाषय मार्गः_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#यदि_अन्तः

/* Location of ssh-sk-helper to support keys in security keys */
#यदि_अपरिभाषितम् मार्गः_SSH_SK_HELPER
#परिभाषय मार्गः_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#यदि_अन्तः

/* xauth for X11 forwarding */
#यदि_अपरिभाषितम् मार्गः_XAUTH
#परिभाषय मार्गः_XAUTH			"/usr/X11R6/bin/xauth"
#यदि_अन्तः

/* UNIX domain socket for X11 server; displaynum will replace %u */
#यदि_अपरिभाषितम् मार्गः_UNIX_X
#परिभाषय मार्गः_UNIX_X "/tmp/.X11-unix/X%u"
#यदि_अन्तः

/* for scp */
#यदि_अपरिभाषितम् मार्गः_CP
#परिभाषय मार्गः_CP			"cp"
#यदि_अन्तः

/* for sftp */
#यदि_अपरिभाषितम् मार्गः_SFTP_SERVER
#परिभाषय मार्गः_SFTP_SERVER		"/usr/libexec/sftp-server"
#यदि_अन्तः
#यदि_अपरिभाषितम् मार्गः_LS
#परिभाषय मार्गः_LS			"ls"
#यदि_अन्तः

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#यदि_अपरिभाषितम् मार्गः_PRIVSEP_CHROOT_DIR
#परिभाषय मार्गः_PRIVSEP_CHROOT_DIR	"/var/empty"
#यदि_अन्तः

/* for passwd change */
#यदि_अपरिभाषितम् मार्गः_PASSWD_PROG
#परिभाषय मार्गः_PASSWD_PROG		"/usr/bin/passwd"
#यदि_अन्तः

/* Askpass program define */
#यदि_अपरिभाषितम् ASKPASS_क्रमादेशः
#परिभाषय ASKPASS_क्रमादेशः         "/usr/lib/ssh/ssh-askpass"
#यदि_अन्तः /* ASKPASS_PROGRAM */
