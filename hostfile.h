/* $OpenBSD: hostfile.h,v 1.29 2021/01/26 00:51:30 djm Exp $ */

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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HOSTFILE_H
#ವ್ಯಾಖ್ಯಾನಿಸು HOSTFILE_H

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	HOST_OK, HOST_NEW, HOST_ಬದಲಾಯಿತು, HOST_REVOKED, HOST_ಸಿಕ್ಕಿತು
}       Host_ಸ್ಥಿತಿ;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ರಚನೆ hostkey_ನಮೂದು {
	ಅಕ್ಷರ *host;
	ಅಕ್ಷರ *file;
	u_long ಸಾಲು;
	ರಚನೆ sshkey *ಕೀಲಿ;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ರಚನೆ hostkeys {
	ರಚನೆ hostkey_ನಮೂದು *entries;
	u_int ಅಂಕೆ_entries;
};

ರಚನೆ hostkeys *init_hostkeys(ಶೂನ್ಯ);
ಶೂನ್ಯ	 ತುಂಬು_hostkeys(ರಚನೆ hostkeys *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int);
ಶೂನ್ಯ	 ತುಂಬು_hostkeys_file(ರಚನೆ hostkeys *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, FILE *, u_int note);
ಶೂನ್ಯ	 free_hostkeys(ರಚನೆ hostkeys *);

Host_ಸ್ಥಿತಿ check_ಕೀಲಿ_ಒಳ_hostkeys(ರಚನೆ hostkeys *, ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು **);
ಪೂರ್ಣಾಂಕ	 lookup_ಕೀಲಿ_ಒಳ_hostkeys_by_type(ರಚನೆ hostkeys *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು **);
ಪೂರ್ಣಾಂಕ	 lookup_marker_ಒಳ_hostkeys(ರಚನೆ hostkeys *, ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 hostfile_read_ಕೀಲಿ(ಅಕ್ಷರ **, u_int *, ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 hostfile_replace_entries(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, ರಚನೆ sshkey **ಕೀಲಿಗಳು, ಗಾತ್ರ_t nkeys,
    ಪೂರ್ಣಾಂಕ store_hash, ಪೂರ್ಣಾಂಕ quiet, ಪೂರ್ಣಾಂಕ hash_alg);

#ವ್ಯಾಖ್ಯಾನಿಸು HASH_MAGIC	"|1|"
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_DELIM	'|'

#ವ್ಯಾಖ್ಯಾನಿಸು CA_MARKER	"@cert-authority"
#ವ್ಯಾಖ್ಯಾನಿಸು REVOKE_MARKER	"@revoked"

ಅಕ್ಷರ	*host_hash(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_WANT_ಹೊಂದಿಕೆ		(1)	/* return only matching hosts/addrs */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_WANT_PARSE_ಕೀಲಿ	(1<<1)	/* need key parsed */

#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಸ್ಥಿತಿ_OK		0	/* Line parsed, didn't match host */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಸ್ಥಿತಿ_INVALID	1	/* line had parse error */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಸ್ಥಿತಿ_COMMENT	2	/* valid line contained no key */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಸ್ಥಿತಿ_MATCHED	3	/* hostname or IP matched */

#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಹೊಂದಿಕೆ_HOST		(1)	/* hostname matched */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಹೊಂದಿಕೆ_IP		(1<<1)	/* address matched */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಹೊಂದಿಕೆ_HOST_HASHED	(1<<2)	/* hostname was hashed */
#ವ್ಯಾಖ್ಯಾನಿಸು HKF_ಹೊಂದಿಕೆ_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
ರಚನೆ hostkey_foreach_ಸಾಲು {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ; /* Path of file */
	u_long linenum;	/* Line number */
	u_int ಸ್ಥಿತಿ_2;	/* One of HKF_STATUS_* */
	u_int ಹೊಂದಿಕೆ;	/* Zero or more of HKF_MATCH_* OR'd together */
	ಅಕ್ಷರ *ಸಾಲು;	/* Entire key line; mutable by callback */
	ಪೂರ್ಣಾಂಕ marker;	/* CA/revocation markers; indicated by MRK_* value */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hosts; /* Raw hosts text, may be hashed or list multiple */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rawkey; /* Text of key and any comment following it */
	ಪೂರ್ಣಾಂಕ keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ರಚನೆ sshkey *ಕೀಲಿ; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ hostkeys_foreach_fn(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *ctx);

/* Iterate over a hostkeys file */
ಪೂರ್ಣಾಂಕ hostkeys_foreach(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, u_int options, u_int note);
ಪೂರ್ಣಾಂಕ hostkeys_foreach_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, FILE *f,
    hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, u_int options, u_int note);

ಶೂನ್ಯ hostfile_create_user_ssh_dir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ
