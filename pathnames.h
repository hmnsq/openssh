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

#నిర్వచించు ETCDIR				"/etc"

#నిర్వచితం_కాకపోతే SSHDIR
#నిర్వచించు SSHDIR				ETCDIR "/ssh"
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే మార్గం_SSH_PIDDIR
#నిర్వచించు మార్గం_SSH_PIDDIR		"/var/run"
#అయితే_ముగింపు

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#నిర్వచించు మార్గం_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#నిర్వచించు మార్గం_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#నిర్వచించు మార్గం_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#నిర్వచించు మార్గం_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#నిర్వచించు మార్గం_HOST_ECDSA_కీలకం_FILE	SSHDIR "/ssh_host_ecdsa_key"
#నిర్వచించు మార్గం_HOST_RSA_కీలకం_FILE		SSHDIR "/ssh_host_rsa_key"
#నిర్వచించు మార్గం_HOST_ED25519_కీలకం_FILE	SSHDIR "/ssh_host_ed25519_key"
#నిర్వచించు మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#నిర్వచించు మార్గం_DH_MODULI			SSHDIR "/moduli"

#నిర్వచితం_కాకపోతే మార్గం_SSH_కార్యక్రమం
#నిర్వచించు మార్గం_SSH_కార్యక్రమం		"/usr/bin/ssh"
#అయితే_ముగింపు

/* Binary paths for the sshd components */
#నిర్వచితం_కాకపోతే మార్గం_SSHD_SESSION
#నిర్వచించు మార్గం_SSHD_SESSION		"/usr/libexec/sshd-session"
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే మార్గం_SSHD_AUTH
#నిర్వచించు మార్గం_SSHD_AUTH			"/usr/libexec/sshd-auth"
#అయితే_ముగింపు

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#నిర్వచించు మార్గం_SSH_DAEMON_PID_FILE	మార్గం_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#నిర్వచించు మార్గం_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#నిర్వచించు మార్గం_SSH_AGENT_SOCKET_DIR	"user:" మార్గం_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#నిర్వచించు మార్గం_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#నిర్వచించు మార్గం_SSH_USER_HOSTFILE		"~/" మార్గం_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#నిర్వచించు మార్గం_SSH_USER_HOSTFILE2	"~/" మార్గం_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#నిర్వచించు మార్గం_SSH_CLIENT_ID_ECDSA	మార్గం_SSH_USER_DIR "/id_ecdsa"
#నిర్వచించు మార్గం_SSH_CLIENT_ID_RSA		మార్గం_SSH_USER_DIR "/id_rsa"
#నిర్వచించు మార్గం_SSH_CLIENT_ID_ED25519	మార్గం_SSH_USER_DIR "/id_ed25519"
#నిర్వచించు మార్గం_SSH_CLIENT_ID_ECDSA_SK	మార్గం_SSH_USER_DIR "/id_ecdsa_sk"
#నిర్వచించు మార్గం_SSH_CLIENT_ID_ED25519_SK	మార్గం_SSH_USER_DIR "/id_ed25519_sk"
#నిర్వచించు మార్గం_SSH_CLIENT_ID_MLDSA44_ED25519 మార్గం_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#నిర్వచించు మార్గం_SSH_USER_CONFFILE		మార్గం_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#నిర్వచించు మార్గం_SSH_USER_PERMITTED_కీలకాలు	మార్గం_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#నిర్వచించు మార్గం_SSH_USER_PERMITTED_KEYS2	మార్గం_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#నిర్వచించు మార్గం_SSH_USER_RC		మార్గం_SSH_USER_DIR "/rc"
#నిర్వచించు మార్గం_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#నిర్వచించు మార్గం_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#నిర్వచించు మార్గం_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#నిర్వచితం_కాకపోతే మార్గం_SSH_ASKPASS_DEFAULT
#నిర్వచించు మార్గం_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#అయితే_ముగింపు

/* Location of ssh-keysign for hostbased authentication */
#నిర్వచితం_కాకపోతే మార్గం_SSH_కీలకం_SIGN
#నిర్వచించు మార్గం_SSH_కీలకం_SIGN		"/usr/libexec/ssh-keysign"
#అయితే_ముగింపు

/* Location of ssh-pkcs11-helper to support keys in tokens */
#నిర్వచితం_కాకపోతే మార్గం_SSH_PKCS11_HELPER
#నిర్వచించు మార్గం_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#అయితే_ముగింపు

/* Location of ssh-sk-helper to support keys in security keys */
#నిర్వచితం_కాకపోతే మార్గం_SSH_SK_HELPER
#నిర్వచించు మార్గం_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#అయితే_ముగింపు

/* xauth for X11 forwarding */
#నిర్వచితం_కాకపోతే మార్గం_XAUTH
#నిర్వచించు మార్గం_XAUTH			"/usr/X11R6/bin/xauth"
#అయితే_ముగింపు

/* UNIX domain socket for X11 server; displaynum will replace %u */
#నిర్వచితం_కాకపోతే మార్గం_UNIX_X
#నిర్వచించు మార్గం_UNIX_X "/tmp/.X11-unix/X%u"
#అయితే_ముగింపు

/* for scp */
#నిర్వచితం_కాకపోతే మార్గం_CP
#నిర్వచించు మార్గం_CP			"cp"
#అయితే_ముగింపు

/* for sftp */
#నిర్వచితం_కాకపోతే మార్గం_SFTP_SERVER
#నిర్వచించు మార్గం_SFTP_SERVER		"/usr/libexec/sftp-server"
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే మార్గం_LS
#నిర్వచించు మార్గం_LS			"ls"
#అయితే_ముగింపు

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#నిర్వచితం_కాకపోతే మార్గం_PRIVSEP_CHROOT_DIR
#నిర్వచించు మార్గం_PRIVSEP_CHROOT_DIR	"/var/empty"
#అయితే_ముగింపు

/* for passwd change */
#నిర్వచితం_కాకపోతే మార్గం_PASSWD_PROG
#నిర్వచించు మార్గం_PASSWD_PROG		"/usr/bin/passwd"
#అయితే_ముగింపు

/* Askpass program define */
#నిర్వచితం_కాకపోతే ASKPASS_కార్యక్రమం
#నిర్వచించు ASKPASS_కార్యక్రమం         "/usr/lib/ssh/ssh-askpass"
#అయితే_ముగింపు /* ASKPASS_PROGRAM */
