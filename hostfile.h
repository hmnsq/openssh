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

تعریفنوع شمارش {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

تعریفنوع شمارش {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ساختار hostkey_entry {
	نویسه *host;
	نویسه *file;
	u_long سطر;
	ساختار sshkey *کلید;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ساختار hostkeys {
	ساختار hostkey_entry *entries;
	u_int رقم_entries;
};

ساختار hostkeys *init_hostkeys(تهی);
تهی	 load_hostkeys(ساختار hostkeys *, ثابت نویسه *,
    ثابت نویسه *, u_int);
تهی	 load_hostkeys_file(ساختار hostkeys *, ثابت نویسه *,
    ثابت نویسه *, FILE *, u_int note);
تهی	 free_hostkeys(ساختار hostkeys *);

HostStatus check_کلید_in_hostkeys(ساختار hostkeys *, ساختار sshkey *,
    ثابت ساختار hostkey_entry **);
صحیح	 lookup_کلید_in_hostkeys_by_type(ساختار hostkeys *, صحیح, صحیح,
    ثابت ساختار hostkey_entry **);
صحیح	 lookup_marker_in_hostkeys(ساختار hostkeys *, صحیح);

صحیح	 hostfile_read_کلید(نویسه **, u_int *, ساختار sshkey *);
صحیح	 add_host_to_hostfile(ثابت نویسه *, ثابت نویسه *,
    ثابت ساختار sshkey *, صحیح);

صحیح	 hostfile_replace_entries(ثابت نویسه *filename,
    ثابت نویسه *host, ثابت نویسه *ip, ساختار sshkey **کلیدها, size_t nkeys,
    صحیح store_hash, صحیح quiet, صحیح hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

نویسه	*host_hash(ثابت نویسه *, ثابت نویسه *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_کلید	(1<<1)	/* need key parsed */

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
ساختار hostkey_foreach_سطر {
	ثابت نویسه *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	نویسه *سطر;	/* Entire key line; mutable by callback */
	صحیح marker;	/* CA/revocation markers; indicated by MRK_* value */
	ثابت نویسه *hosts; /* Raw hosts text, may be hashed or list multiple */
	ثابت نویسه *rawkey; /* Text of key and any comment following it */
	صحیح keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ساختار sshkey *کلید; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ثابت نویسه *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
تعریفنوع صحیح hostkeys_foreach_fn(ساختار hostkey_foreach_سطر *l, تهی *ctx);

/* Iterate over a hostkeys file */
صحیح hostkeys_foreach(ثابت نویسه *path,
    hostkeys_foreach_fn *callback, تهی *ctx,
    ثابت نویسه *host, ثابت نویسه *ip, u_int options, u_int note);
صحیح hostkeys_foreach_file(ثابت نویسه *path, FILE *f,
    hostkeys_foreach_fn *callback, تهی *ctx,
    ثابت نویسه *host, ثابت نویسه *ip, u_int options, u_int note);

تهی hostfile_create_user_ssh_dir(ثابت نویسه *, صحیح);

#endif
