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
#ifndef HOSTFILE_H
#define HOSTFILE_H

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ಸಂರಚನಾ hostkey_entry {
	ವರ್ಣ *host;
	ವರ್ಣ *file;
	u_long ಸಾಲು;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ಸಂರಚನಾ hostkeys {
	ಸಂರಚನಾ hostkey_entry *entries;
	u_int ಅಂಕೆ_entries;
};

ಸಂರಚನಾ hostkeys *init_hostkeys(ಶೂನ್ಯ);
ಶೂನ್ಯ	 load_hostkeys(ಸಂರಚನಾ hostkeys *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, u_int);
ಶೂನ್ಯ	 load_hostkeys_file(ಸಂರಚನಾ hostkeys *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, FILE *, u_int note);
ಶೂನ್ಯ	 free_hostkeys(ಸಂರಚನಾ hostkeys *);

HostStatus check_ಕೀಲಿ_in_hostkeys(ಸಂರಚನಾ hostkeys *, ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ಸಂರಚನಾ hostkey_entry **);
ಪೂರ್ಣಾಙ್ಕ	 lookup_ಕೀಲಿ_in_hostkeys_by_type(ಸಂರಚನಾ hostkeys *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ,
    ಧ್ರುವ ಸಂರಚನಾ hostkey_entry **);
ಪೂರ್ಣಾಙ್ಕ	 lookup_marker_in_hostkeys(ಸಂರಚನಾ hostkeys *, ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 hostfile_read_ಕೀಲಿ(ವರ್ಣ **, u_int *, ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 add_host_to_hostfile(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 hostfile_replace_entries(ಧ್ರುವ ವರ್ಣ *filename,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು, size_t nkeys,
    ಪೂರ್ಣಾಙ್ಕ store_hash, ಪೂರ್ಣಾಙ್ಕ quiet, ಪೂರ್ಣಾಙ್ಕ hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

ವರ್ಣ	*host_hash(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_ಕೀಲಿ	(1<<1)	/* need key parsed */

#define HKF_STATUS_OK		0	/* Line parsed, didn't match host */
#define HKF_STATUS_INVALID	1	/* line had parse error */
#define HKF_STATUS_COMMENT	2	/* valid line contained no key */
#define HKF_STATUS_MATCHED	3	/* hostname or IP matched */

#define HKF_MATCH_HOST		(1)	/* hostname matched */
#define HKF_MATCH_IP		(1<<1)	/* address matched */
#define HKF_MATCH_HOST_HASHED	(1<<2)	/* hostname was hashed */
#define HKF_MATCH_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
ಸಂರಚನಾ hostkey_foreach_ಸಾಲು {
	ಧ್ರುವ ವರ್ಣ *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	ವರ್ಣ *ಸಾಲು;	/* Entire key line; mutable by callback */
	ಪೂರ್ಣಾಙ್ಕ marker;	/* CA/revocation markers; indicated by MRK_* value */
	ಧ್ರುವ ವರ್ಣ *hosts; /* Raw hosts text, may be hashed or list multiple */
	ಧ್ರುವ ವರ್ಣ *rawkey; /* Text of key and any comment following it */
	ಪೂರ್ಣಾಙ್ಕ keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ಸಂರಚನಾ sshkey *ಕೀಲಿ; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ಧ್ರುವ ವರ್ಣ *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ hostkeys_foreach_fn(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *ctx);

/* Iterate over a hostkeys file */
ಪೂರ್ಣಾಙ್ಕ hostkeys_foreach(ಧ್ರುವ ವರ್ಣ *path,
    hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, u_int options, u_int note);
ಪೂರ್ಣಾಙ್ಕ hostkeys_foreach_file(ಧ್ರುವ ವರ್ಣ *path, FILE *f,
    hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, u_int options, u_int note);

ಶೂನ್ಯ hostfile_create_user_ssh_dir(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);

#endif
