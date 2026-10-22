#ضمن "fixed-keys.h"
#ضمن <assert.h>

#define main(ac, av) xxxmain(ac, av)
#ضمن "../../../ssh-agent.c"

فراغ test_one(ثابت uint8_t* s, size_t slen);

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
	إذا ((pubkey = sshkey_new(کلیل_UNSPEC)) == عدم)
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

	إذا ((b = sshbuf_from(s, strlen(s))) == عدم) {
		error_f("sshbuf_from failed");
		abort();
	}
	إذا ((r = sshkey_parse_private_fileblob(b, "", &privkey, عدم)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	أرجع privkey;
}

ساكن فراغ
add_کلیل(ثابت حرف *privkey, ثابت حرف *certpath)
{
	Identity *id;
	صحيح r;
	بنية sshkey *cert;

	id = xcalloc(1, حجم(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->کلیل = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	إذا (sshkey_is_sk(id->کلیل))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, حجم(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->کلیل = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	إذا ((r = sshkey_to_certified(id->کلیل)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	إذا ((r = sshkey_cert_copy(cert, id->کلیل)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	إذا (sshkey_is_sk(id->کلیل))
		id->sk_provider = xstrdup("internal");
}

ساكن فراغ
cleanup_idtab(فراغ)
{
	Identity *id;

	إذا (idtab == عدم) أرجع;
	لكل (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
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
	add_کلیل(PRIV_RSA, CERT_RSA);
	add_کلیل(PRIV_ECDSA, CERT_ECDSA);
	add_کلیل(PRIV_ED25519, CERT_ED25519);
	add_کلیل(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_کلیل(PRIV_ED25519_SK, CERT_ED25519_SK);
}

ساكن فراغ
cleanup_sockettab(فراغ)
{
	u_int i;
	لكل (i = 0; i < sockets_alloc; i++) {
		إذا (sockets[i].type != AUTH_UNUSED)
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

#define MAX_MESSAGES 256
فراغ
test_one(ثابت uint8_t* s, size_t slen)
{
	ساكن صحيح devnull = -1;
	size_t i, olen, nlen;

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
	(فراغ)sshbuf_put(sockets[0].تێخستن, s, slen);
	لكل (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].تێخستن);
		process_message(0);
		nlen = sshbuf_len(sockets[0].تێخستن);
		إذا (nlen == 0 || nlen == olen)
			اكسر;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
