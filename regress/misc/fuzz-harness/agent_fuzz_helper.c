#شامل "fixed-keys.h"
#شامل <assert.h>

#تعریف_کرو مین(ac, av) xxxmain(ac, av)
#شامل "../../../ssh-agent.c"

خالی test_one(ثابت uint8_t* s, سائز_t slen);

ساکن صحیح
devnull_or_die(خالی)
{
	صحیح fd;

	اگر ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	واپس fd;
}

ساکن ساخت sshkey *
pubkey_or_die(ثابت حرف *s)
{
	حرف *tmp, *cp;
	ساخت sshkey *pubkey;
	صحیح r;

	tmp = cp = xstrdup(s);
	اگر ((pubkey = sshkey_new(کلید_UNSPEC)) == تہی)
		abort();
	اگر ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	آزاد(tmp);
	واپس pubkey;
}

ساکن ساخت sshkey *
privkey_or_die(ثابت حرف *s)
{
	صحیح r;
	ساخت sshbuf *b;
	ساخت sshkey *privkey;

	اگر ((b = sshbuf_from(s, لڑی_لمبائی(s))) == تہی) {
		error_f("sshbuf_from failed");
		abort();
	}
	اگر ((r = sshkey_parse_نجی_fileblob(b, "", &privkey, تہی)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	واپس privkey;
}

ساکن خالی
جوڑو_کلید(ثابت حرف *privkey, ثابت حرف *certpath)
{
	شناختی_عنصر *id;
	صحیح r;
	ساخت sshkey *cert;

	id = xcalloc(1, حجم(شناختی_عنصر));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, اگلا);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	اگر (sshkey_is_sk(id->کلید))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, حجم(شناختی_عنصر));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, اگلا);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	اگر ((r = sshkey_مقصد_certified(id->کلید)) != 0) {
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

ساکن خالی
cleanup_idtab(خالی)
{
	شناختی_عنصر *id;

	اگر (idtab == تہی) واپس;
	برائے (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, اگلا);
		free_شناختی_عنصر(id);
	}
	آزاد(idtab);
	idtab = تہی;
}

ساکن خالی
reset_idtab(خالی)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	جوڑو_کلید(PRIV_RSA, CERT_RSA);
	جوڑو_کلید(PRIV_ECDSA, CERT_ECDSA);
	جوڑو_کلید(PRIV_ED25519, CERT_ED25519);
	جوڑو_کلید(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	جوڑو_کلید(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ساکن خالی
cleanup_sockettab(خالی)
{
	u_int i;
	برائے (i = 0; i < sockets_alloc; i++) {
		اگر (sockets[i].type != AUTH_غیر_مستعمل)
			close_socket(sockets + i);
	}
	آزاد(sockets);
	sockets = تہی;
	sockets_alloc = 0;
}

ساکن خالی
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

#تعریف_کرو MAX_MESSAGES 256
خالی
test_one(ثابت uint8_t* s, سائز_t slen)
{
	ساکن صحیح devnull = -1;
	سائز_t i, olen, nlen;

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
	(خالی)sshbuf_put(sockets[0].داخلہ, s, slen);
	برائے (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].داخلہ);
		process_پیغام(0);
		nlen = sshbuf_len(sockets[0].داخلہ);
		اگر (nlen == 0 || nlen == olen)
			توڑو;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
