#அந்தர்பாவ "fixed-keys.h"
#அந்தர்பாவ <assert.h>

#define முதன்மை(ac, av) xxxmain(ac, av)
#அந்தர்பாவ "../../../ssh-agent.c"

வெறுமை test_one(மாறிலி uint8_t* s, size_t slen);

நிலையான முழு
devnull_or_die(வெறுமை)
{
	முழு fd;

	எனில் ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	திரும்பு fd;
}

நிலையான கட்டமைப்பு sshkey *
pubkey_or_die(மாறிலி எழுத்து *s)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *pubkey;
	முழு r;

	tmp = cp = xstrdup(s);
	எனில் ((pubkey = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		abort();
	எனில் ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	விடுவி(tmp);
	திரும்பு pubkey;
}

நிலையான கட்டமைப்பு sshkey *
privkey_or_die(மாறிலி எழுத்து *s)
{
	முழு r;
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு sshkey *privkey;

	எனில் ((b = sshbuf_from(s, strlen(s))) == வெற்று) {
		error_f("sshbuf_from failed");
		abort();
	}
	எனில் ((r = sshkey_parse_private_fileblob(b, "", &privkey, வெற்று)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	திரும்பு privkey;
}

நிலையான வெறுமை
add_சாவி(மாறிலி எழுத்து *privkey, மாறிலி எழுத்து *certpath)
{
	Identity *id;
	முழு r;
	கட்டமைப்பு sshkey *cert;

	id = xcalloc(1, அளவு(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->சாவி = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	எனில் (sshkey_is_sk(id->சாவி))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, அளவு(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->சாவி = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	எனில் ((r = sshkey_to_certified(id->சாவி)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	எனில் ((r = sshkey_cert_copy(cert, id->சாவி)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	எனில் (sshkey_is_sk(id->சாவி))
		id->sk_provider = xstrdup("internal");
}

நிலையான வெறுமை
cleanup_idtab(வெறுமை)
{
	Identity *id;

	எனில் (idtab == வெற்று) திரும்பு;
	க்கு (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	விடுவி(idtab);
	idtab = வெற்று;
}

நிலையான வெறுமை
reset_idtab(வெறுமை)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_சாவி(PRIV_RSA, CERT_RSA);
	add_சாவி(PRIV_ECDSA, CERT_ECDSA);
	add_சாவி(PRIV_ED25519, CERT_ED25519);
	add_சாவி(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_சாவி(PRIV_ED25519_SK, CERT_ED25519_SK);
}

நிலையான வெறுமை
cleanup_sockettab(வெறுமை)
{
	u_int i;
	க்கு (i = 0; i < sockets_alloc; i++) {
		எனில் (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	விடுவி(sockets);
	sockets = வெற்று;
	sockets_alloc = 0;
}

நிலையான வெறுமை
reset_sockettab(முழு devnull)
{
	முழு fd;

	cleanup_sockettab();
	எனில் ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	ப்ரதிஜ்ஞா(sockets[0].type == AUTH_CONNECTION);
	ப்ரதிஜ்ஞா(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
வெறுமை
test_one(மாறிலி uint8_t* s, size_t slen)
{
	நிலையான முழு devnull = -1;
	size_t i, olen, nlen;

	எனில் (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(வெறுமை)sshbuf_put(sockets[0].உள்ளீடு, s, slen);
	க்கு (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].உள்ளீடு);
		process_message(0);
		nlen = sshbuf_len(sockets[0].உள்ளீடு);
		எனில் (nlen == 0 || nlen == olen)
			நிறுத்து;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
