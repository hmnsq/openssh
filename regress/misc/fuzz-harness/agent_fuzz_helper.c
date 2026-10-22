#ضمن "fixed-keys.h"
#ضمن <assert.h>

#تعریف_کن اصلی(ac, av) xxxmain(ac, av)
#ضمن "../../../ssh-agent.c"

فراغ test_one(ثابت uint8_t* s, اندازه_t slen);

ساكن صحيح
devnull_or_die(فراغ)
{
	صحيح fd;

	إذا ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	أرجع fd;
}

ساكن بنية sshkey *
pubkey_or_die(ثابت حرف *s)
{
	حرف *tmp, *cp;
	بنية sshkey *pubkey;
	صحيح r;

	tmp = cp = xstrdup(s);
	إذا ((pubkey = sshkey_new(کلید_UNSPEC)) == عدم)
		abort();
	إذا ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	حرر(tmp);
	أرجع pubkey;
}

ساكن بنية sshkey *
privkey_or_die(ثابت حرف *s)
{
	صحيح r;
	بنية sshbuf *b;
	بنية sshkey *privkey;

	إذا ((b = sshbuf_from(s, طول_رشته(s))) == عدم) {
		error_f("sshbuf_from failed");
		abort();
	}
	إذا ((r = sshkey_parse_خصوصی_fileblob(b, "", &privkey, عدم)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	أرجع privkey;
}

ساكن فراغ
جمع_کن_کلید(ثابت حرف *privkey, ثابت حرف *certpath)
{
	عنصر_خنثی *id;
	صحيح r;
	بنية sshkey *cert;

	id = xcalloc(1, حجم(عنصر_خنثی));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, بعدی);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	إذا (sshkey_is_sk(id->کلید))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, حجم(عنصر_خنثی));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, بعدی);
	idtab->nentries++;
	id->کلید = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	إذا ((r = sshkey_مقصد_certified(id->کلید)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	إذا ((r = sshkey_cert_copy(cert, id->کلید)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	إذا (sshkey_is_sk(id->کلید))
		id->sk_provider = xstrdup("internal");
}

ساكن فراغ
cleanup_idtab(فراغ)
{
	عنصر_خنثی *id;

	إذا (idtab == عدم) أرجع;
	لكل (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, بعدی);
		free_عنصر_خنثی(id);
	}
	حرر(idtab);
	idtab = عدم;
}

ساكن فراغ
reset_idtab(فراغ)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	جمع_کن_کلید(PRIV_RSA, CERT_RSA);
	جمع_کن_کلید(PRIV_ECDSA, CERT_ECDSA);
	جمع_کن_کلید(PRIV_ED25519, CERT_ED25519);
	جمع_کن_کلید(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	جمع_کن_کلید(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ساكن فراغ
cleanup_sockettab(فراغ)
{
	u_int i;
	لكل (i = 0; i < sockets_alloc; i++) {
		إذا (sockets[i].type != AUTH_استفادهنشده)
			close_socket(sockets + i);
	}
	حرر(sockets);
	sockets = عدم;
	sockets_alloc = 0;
}

ساكن فراغ
reset_sockettab(صحيح devnull)
{
	صحيح fd;

	cleanup_sockettab();
	إذا ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	أكد(sockets[0].type == AUTH_CONNECTION);
	أكد(sockets[0].fd == fd);
}

#تعریف_کن MAX_MESSAGES 256
فراغ
test_one(ثابت uint8_t* s, اندازه_t slen)
{
	ساكن صحيح devnull = -1;
	اندازه_t i, olen, nlen;

	إذا (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(فراغ)sshbuf_put(sockets[0].درون_داد, s, slen);
	لكل (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].درون_داد);
		process_پیام(0);
		nlen = sshbuf_len(sockets[0].درون_داد);
		إذا (nlen == 0 || nlen == olen)
			اكسر;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
