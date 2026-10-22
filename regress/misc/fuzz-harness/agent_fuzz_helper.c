#شامل "fixed-keys.h"
#شامل <assert.h>

#define اصلی(ac, av) xxxmain(ac, av)
#شامل "../../../ssh-agent.c"

تهی test_one(ثابت uint8_t* s, size_t slen);

ایستا صحیح
devnull_or_die(تهی)
{
	صحیح fd;

	اگر ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	بازگشت fd;
}

ایستا ساختار sshkey *
pubkey_or_die(ثابت نویسه *s)
{
	نویسه *tmp, *cp;
	ساختار sshkey *pubkey;
	صحیح r;

	tmp = cp = xstrdup(s);
	اگر ((pubkey = sshkey_new(کلید_UNSPEC)) == پوچ)
		abort();
	اگر ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	آزاد(tmp);
	بازگشت pubkey;
}

ایستا ساختار sshkey *
privkey_or_die(ثابت نویسه *s)
{
	صحیح r;
	ساختار sshbuf *b;
	ساختار sshkey *privkey;

	اگر ((b = sshbuf_from(s, strlen(s))) == پوچ) {
		error_f("sshbuf_from failed");
		abort();
	}
	اگر ((r = sshkey_parse_private_fileblob(b, "", &privkey, پوچ)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	بازگشت privkey;
}

ایستا تهی
add_کلید(ثابت نویسه *privkey, ثابت نویسه *certpath)
{
	Identity *id;
	صحیح r;
	ساختار sshkey *cert;

	id = xcalloc(1, اندازه(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	اگر (sshkey_is_sk(id->کلید))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, اندازه(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	اگر ((r = sshkey_to_certified(id->کلید)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	اگر ((r = sshkey_cert_copy(cert, id->کلید)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	اگر (sshkey_is_sk(id->کلید))
		id->sk_provider = xstrdup("internal");
}

ایستا تهی
cleanup_idtab(تهی)
{
	Identity *id;

	اگر (idtab == پوچ) بازگشت;
	برای (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	آزاد(idtab);
	idtab = پوچ;
}

ایستا تهی
reset_idtab(تهی)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_کلید(PRIV_RSA, CERT_RSA);
	add_کلید(PRIV_ECDSA, CERT_ECDSA);
	add_کلید(PRIV_ED25519, CERT_ED25519);
	add_کلید(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_کلید(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ایستا تهی
cleanup_sockettab(تهی)
{
	u_int i;
	برای (i = 0; i < sockets_alloc; i++) {
		اگر (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	آزاد(sockets);
	sockets = پوچ;
	sockets_alloc = 0;
}

ایستا تهی
reset_sockettab(صحیح devnull)
{
	صحیح fd;

	cleanup_sockettab();
	اگر ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	أكد(sockets[0].type == AUTH_CONNECTION);
	أكد(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
تهی
test_one(ثابت uint8_t* s, size_t slen)
{
	ایستا صحیح devnull = -1;
	size_t i, olen, nlen;

	اگر (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(تهی)sshbuf_put(sockets[0].درون_داد, s, slen);
	برای (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].درون_داد);
		process_message(0);
		nlen = sshbuf_len(sockets[0].درون_داد);
		اگر (nlen == 0 || nlen == olen)
			بشکن;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
