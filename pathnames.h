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

#ವ್ಯಾಖ್ಯಾನಿಸು ETCDIR				"/etc"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSHDIR
#ವ್ಯಾಖ್ಯಾನಿಸು SSHDIR				ETCDIR "/ssh"
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_PIDDIR
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_PIDDIR		"/var/run"
#ಆದರೆ_ಅಂತ್ಯ

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE	SSHDIR "/ssh_host_ecdsa_key"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE		SSHDIR "/ssh_host_rsa_key"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE	SSHDIR "/ssh_host_ed25519_key"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_DH_MODULI			SSHDIR "/moduli"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_ಕಾರ್ಯಕ್ರಮ
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_ಕಾರ್ಯಕ್ರಮ		"/usr/bin/ssh"
#ಆದರೆ_ಅಂತ್ಯ

/* Binary paths for the sshd components */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSHD_SESSION
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSHD_SESSION		"/usr/libexec/sshd-session"
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSHD_AUTH
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSHD_AUTH			"/usr/libexec/sshd-auth"
#ಆದರೆ_ಅಂತ್ಯ

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_DAEMON_PID_FILE	ಮಾರ್ಗ_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_AGENT_SOCKET_DIR	"user:" ಮಾರ್ಗ_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_HOSTFILE		"~/" ಮಾರ್ಗ_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_HOSTFILE2	"~/" ಮಾರ್ಗ_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA	ಮಾರ್ಗ_SSH_USER_DIR "/id_ecdsa"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_RSA		ಮಾರ್ಗ_SSH_USER_DIR "/id_rsa"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519	ಮಾರ್ಗ_SSH_USER_DIR "/id_ed25519"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA_SK	ಮಾರ್ಗ_SSH_USER_DIR "/id_ecdsa_sk"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519_SK	ಮಾರ್ಗ_SSH_USER_DIR "/id_ed25519_sk"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_CLIENT_ID_MLDSA44_ED25519 ಮಾರ್ಗ_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_CONFFILE		ಮಾರ್ಗ_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_PERMITTED_ಕೀಲಿಗಳು	ಮಾರ್ಗ_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_PERMITTED_KEYS2	ಮಾರ್ಗ_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_USER_RC		ಮಾರ್ಗ_SSH_USER_DIR "/rc"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_ASKPASS_DEFAULT
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#ಆದರೆ_ಅಂತ್ಯ

/* Location of ssh-keysign for hostbased authentication */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN		"/usr/libexec/ssh-keysign"
#ಆದರೆ_ಅಂತ್ಯ

/* Location of ssh-pkcs11-helper to support keys in tokens */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_PKCS11_HELPER
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#ಆದರೆ_ಅಂತ್ಯ

/* Location of ssh-sk-helper to support keys in security keys */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SSH_SK_HELPER
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#ಆದರೆ_ಅಂತ್ಯ

/* xauth for X11 forwarding */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_XAUTH
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_XAUTH			"/usr/X11R6/bin/xauth"
#ಆದರೆ_ಅಂತ್ಯ

/* UNIX domain socket for X11 server; displaynum will replace %u */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_UNIX_X
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_UNIX_X "/tmp/.X11-unix/X%u"
#ಆದರೆ_ಅಂತ್ಯ

/* for scp */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_CP
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_CP			"cp"
#ಆದರೆ_ಅಂತ್ಯ

/* for sftp */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_SFTP_SERVER
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_SFTP_SERVER		"/usr/libexec/sftp-server"
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_LS
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_LS			"ls"
#ಆದರೆ_ಅಂತ್ಯ

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_PRIVSEP_CHROOT_DIR	"/var/empty"
#ಆದರೆ_ಅಂತ್ಯ

/* for passwd change */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮಾರ್ಗ_PASSWD_PROG
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_PASSWD_PROG		"/usr/bin/passwd"
#ಆದರೆ_ಅಂತ್ಯ

/* Askpass program define */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ASKPASS_ಕಾರ್ಯಕ್ರಮ
#ವ್ಯಾಖ್ಯಾನಿಸು ASKPASS_ಕಾರ್ಯಕ್ರಮ         "/usr/lib/ssh/ssh-askpass"
#ಆದರೆ_ಅಂತ್ಯ /* ASKPASS_PROGRAM */
