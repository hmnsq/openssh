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
#अगर_अघोषित HOSTFILE_H
#घोषणा HOSTFILE_H

प्रकार क्रमागत {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

प्रकार क्रमागत {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

काष्ठा hostkey_entry {
	अक्षर *host;
	अक्षर *file;
	u_long पंक्ति;
	काष्ठा sshkey *कुंजी;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
काष्ठा hostkeys {
	काष्ठा hostkey_entry *entries;
	u_int अंक_entries;
};

काष्ठा hostkeys *init_hostkeys(व्योम);
व्योम	 load_hostkeys(काष्ठा hostkeys *, स्थिर अक्षर *,
    स्थिर अक्षर *, u_int);
व्योम	 load_hostkeys_file(काष्ठा hostkeys *, स्थिर अक्षर *,
    स्थिर अक्षर *, खाता *, u_int note);
व्योम	 free_hostkeys(काष्ठा hostkeys *);

HostStatus check_कुंजी_in_hostkeys(काष्ठा hostkeys *, काष्ठा sshkey *,
    स्थिर काष्ठा hostkey_entry **);
पूर्णांक	 lookup_कुंजी_in_hostkeys_by_type(काष्ठा hostkeys *, पूर्णांक, पूर्णांक,
    स्थिर काष्ठा hostkey_entry **);
पूर्णांक	 lookup_marker_in_hostkeys(काष्ठा hostkeys *, पूर्णांक);

पूर्णांक	 hostfile_read_कुंजी(अक्षर **, u_int *, काष्ठा sshkey *);
पूर्णांक	 add_host_to_hostfile(स्थिर अक्षर *, स्थिर अक्षर *,
    स्थिर काष्ठा sshkey *, पूर्णांक);

पूर्णांक	 hostfile_replace_entries(स्थिर अक्षर *filename,
    स्थिर अक्षर *host, स्थिर अक्षर *ip, काष्ठा sshkey **कुंजियाँ, माप_प्रकार nkeys,
    पूर्णांक store_hash, पूर्णांक quiet, पूर्णांक hash_alg);

#घोषणा HASH_MAGIC	"|1|"
#घोषणा HASH_DELIM	'|'

#घोषणा CA_MARKER	"@cert-authority"
#घोषणा REVOKE_MARKER	"@revoked"

अक्षर	*host_hash(स्थिर अक्षर *, स्थिर अक्षर *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#घोषणा HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#घोषणा HKF_WANT_PARSE_कुंजी	(1<<1)	/* need key parsed */

#घोषणा HKF_STATUS_OK		0	/* Line parsed, didn't match host */
#घोषणा HKF_STATUS_INVALID	1	/* line had parse error */
#घोषणा HKF_STATUS_COMMENT	2	/* valid line contained no key */
#घोषणा HKF_STATUS_MATCHED	3	/* hostname or IP matched */

#घोषणा HKF_MATCH_HOST		(1)	/* hostname matched */
#घोषणा HKF_MATCH_IP		(1<<1)	/* address matched */
#घोषणा HKF_MATCH_HOST_HASHED	(1<<2)	/* hostname was hashed */
#घोषणा HKF_MATCH_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
काष्ठा hostkey_foreach_पंक्ति {
	स्थिर अक्षर *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	अक्षर *पंक्ति;	/* Entire key line; mutable by callback */
	पूर्णांक marker;	/* CA/revocation markers; indicated by MRK_* value */
	स्थिर अक्षर *hosts; /* Raw hosts text, may be hashed or list multiple */
	स्थिर अक्षर *rawkey; /* Text of key and any comment following it */
	पूर्णांक keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	काष्ठा sshkey *कुंजी; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	स्थिर अक्षर *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
प्रकार पूर्णांक hostkeys_foreach_fn(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *ctx);

/* Iterate over a hostkeys file */
पूर्णांक hostkeys_foreach(स्थिर अक्षर *path,
    hostkeys_foreach_fn *callback, व्योम *ctx,
    स्थिर अक्षर *host, स्थिर अक्षर *ip, u_int options, u_int note);
पूर्णांक hostkeys_foreach_file(स्थिर अक्षर *path, खाता *f,
    hostkeys_foreach_fn *callback, व्योम *ctx,
    स्थिर अक्षर *host, स्थिर अक्षर *ip, u_int options, u_int note);

व्योम hostfile_create_user_ssh_dir(स्थिर अक्षर *, पूर्णांक);

#पूर्ण_अगर
