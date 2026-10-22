// libfuzzer driver for key exchange fuzzing.


#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی "C" {

#شامل "includes.h"
#شامل "ssherr.h"
#شامل "ssh_api.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "myproposal.h"
#شامل "xmalloc.h"
#شامل "authfile.h"
#شامل "log.h"

#شامل "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

ایستا صحیح prepare_کلید(ساختار shared_state *st, صحیح keytype, صحیح bits);

ساختار shared_state {
	size_t nkeys;
	ساختار sshkey **privkeys, **pubkeys;
};

ساختار test_state {
	ساختار sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ساختار sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	ساختار sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ساختار kex_overrides {
	ثابت نویسه *cipher;
	ثابت نویسه *mac;
	ثابت نویسه *comp;
};

ایستا صحیح
do_send_and_receive(ساختار ssh *from, ساختار ssh *to,
    ساختار sshbuf *store, صحیح clobber, size_t *n)
{
	u_char type;
	size_t len;
	ثابت u_char *buf;
	صحیح r;

	برای (*n = 0;; (*n)++) {
		اگر ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			بازگشت r;
		}
		اگر (type != 0)
			بازگشت 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		اگر (len == 0)
			بازگشت 0;
		اگر ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			بازگشت r;
		}
		اگر (store != پوچ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			بازگشت r;
		}
		اگر (!clobber && (r = ssh_درون_داد_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			بازگشت r;
		}
	}
}

ایستا صحیح
run_kex(ساختار test_state *ts, ساختار ssh *client, ساختار ssh *server)
{
	صحیح r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	اگر (ts->sin != پوچ) {
		اگر ((r = ssh_درون_داد_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			بازگشت r;
		}
		sshbuf_reset(ts->sin);
	}
	اگر (ts->cin != پوچ) {
		اگر ((r = ssh_درون_داد_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			بازگشت r;
		}
		sshbuf_reset(ts->cin);
	}
	وقتی (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		اگر ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != پوچ, &sn)) != 0) {
			debug_fr(r, "S->C");
			بشکن;
		}
		debug_f("C:");
		اگر ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != پوچ, &cn)) != 0) {
			debug_fr(r, "C->S");
			بشکن;
		}
		اگر (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			بشکن;
		}
	}
	debug_fr(r, "done");
	بازگشت r;
}

ایستا تهی
store_کلید(ساختار shared_state *st, ساختار sshkey *pubkey,
    ساختار sshkey *privkey)
{
	اگر (st == پوچ || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != پوچ))
		abort();
	اگر ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ساختار sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, اندازه(*st->pubkeys));
		st->privkeys = (ساختار sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, اندازه(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ایستا صحیح
prepare_کلیدها(ساختار shared_state *st)
{
	اگر (prepare_کلید(st, کلید_RSA, 2048) != 0 ||
	    prepare_کلید(st, کلید_ECDSA, 256) != 0 ||
	    prepare_کلید(st, کلید_ED25519, 256) != 0) {
		error_f("key prepare failed");
		بازگشت -1;
	}
	بازگشت 0;
}

ایستا ساختار sshkey *
get_pubkey(ساختار shared_state *st, صحیح keytype)
{
	اگر (st == پوچ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == پوچ || st->pubkeys[keytype] == پوچ)
		abort();
	بازگشت st->pubkeys[keytype];
}

ایستا ساختار sshkey *
get_privkey(ساختار shared_state *st, صحیح keytype)
{
	اگر (st == پوچ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == پوچ || st->privkeys[keytype] == پوچ)
		abort();
	بازگشت st->privkeys[keytype];
}

ایستا صحیح
build_proposal_side(نویسه **out, ثابت نویسه *defaults[PROPOSAL_MAX],
    ثابت نویسه *kex, ثابت نویسه *keyname,
    ثابت نویسه *cipher, ثابت نویسه *mac, ثابت نویسه *comp)
{
	صحیح i;
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت نویسه *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			ccp = keyname;
		وگرنه اگر (i == PROPOSAL_KEX_ALGS && kex != پوچ)
			ccp = kex;
		وگرنه اگر ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != پوچ)
			ccp = cipher;
		وگرنه اگر ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != پوچ)
			ccp = mac;
		وگرنه اگر ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != پوچ)
			ccp = comp;
		اگر ((out[i] = strdup(ccp)) == پوچ)
			بازگشت -1;
	}
	بازگشت 0;
}

ایستا صحیح
do_kex_with_کلید(ساختار shared_state *st, ساختار test_state *ts,
    ثابت نویسه *kex, صحیح keytype, ثابت ساختار kex_overrides *ov)
{
	ساختار ssh *client = پوچ, *server = پوچ;
	ساختار sshkey *privkey = پوچ, *pubkey = پوچ;
	ساختار sshbuf *state = پوچ;
	ساختار kex_params kex_params;
	ثابت نویسه *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	نویسه *myproposal[PROPOSAL_MAX] = {0};
	نویسه *keyname = پوچ;
	صحیح i, r;

	ts->cin = ts->sin = پوچ;
	اگر (ts->c_template != پوچ &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == پوچ)
		abort();
	اگر (ts->s_template != پوچ &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == پوچ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	اگر (ts->cin != پوچ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} وگرنه اگر (ts->sin != پوچ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} وگرنه
		debug_f("%s %s noclobber", kex, keyname);

	اگر (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : پوچ,
	    ov ? ov->mac : پوچ,
	    ov ? ov->comp : پوچ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		برو fail;
	}
	memcpy(kex_params.proposal, myproposal, اندازه(myproposal));
	اگر ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		برو fail;
	}
	اگر ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		برو fail;
	}
	اگر ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		برو fail;
	}
	اگر ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		برو fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	آزاد(keyname);
	بازگشت r;
}

ایستا صحیح
prepare_کلید(ساختار shared_state *st, صحیح kt, صحیح bits)
{
	ثابت نویسه *pubstr = پوچ;
	ثابت نویسه *privstr = پوچ;
	نویسه *tmp, *cp;
	ساختار sshkey *privkey = پوچ, *pubkey = پوچ;
	ساختار sshbuf *b = پوچ;
	صحیح r;

	انتخاب (kt) {
	حالت کلید_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		بشکن;
	حالت کلید_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		بشکن;
	حالت کلید_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		بشکن;
	پیشفرض:
		abort();
	}
	اگر ((b = sshbuf_from(privstr, strlen(privstr))) == پوچ)
		abort();
	اگر ((r = sshkey_parse_private_fileblob(b, "", &privkey, پوچ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	اگر ((pubkey = sshkey_new(کلید_UNSPEC)) == پوچ)
		abort();
	اگر ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	آزاد(tmp);

	store_کلید(st, pubkey, privkey);
	بازگشت 0;
}

#اگر defined(STANDALONE)

#اگر 0 /* use this if generating new keys to embed above */
ایستا صحیح
prepare_کلید(ساختار shared_state *st, صحیح keytype, صحیح bits)
{
	ساختار sshkey *privkey = پوچ, *pubkey = پوچ;
	صحیح r;

	اگر ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	اگر ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_کلید(st, pubkey, privkey);
	بازگشت 0;
}
#endif

صحیح اصلی(تهی)
{
	ایستا ساختار shared_state *st;
	ساختار test_state *ts;
	ثابت صحیح keytypes[] = { کلید_RSA, کلید_ECDSA, کلید_ED25519, -1 };
	ایستا ثابت نویسه * ثابت kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		پوچ,
	};
	صحیح i, j;
	نویسه *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	اگر (st == پوچ) {
		st = (ساختار shared_state *)xcalloc(1, اندازه(*st));
		prepare_کلیدها(st);
	}
	/* Run each kex method for each key and save client/server packets */
	برای (i = 0; keytypes[i] != -1; i++) {
		برای (j = 0; kextypes[j] != پوچ; j++) {
			ts = (ساختار test_state *)xcalloc(1, اندازه(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_کلید(st, ts, kextypes[j], keytypes[i], پوچ);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			اگر ((f = fopen(path, "wb+")) == پوچ)
				abort();
			اگر (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			آزاد(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			اگر ((f = fopen(path, "wb+")) == پوچ)
				abort();
			اگر (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			آزاد(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			آزاد(ts);
		}
	}
	برای (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		اگر (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, پوچ, 0) != 0)
			abort();
		آزاد(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		اگر (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		آزاد(path);
	}
}
#وگرنه /* !STANDALONE */
ایستا تهی
do_kex(ساختار shared_state *st, ساختار test_state *ts, ثابت نویسه *kex)
{
	do_kex_with_کلید(st, ts, kex, کلید_RSA, پوچ);
	do_kex_with_کلید(st, ts, kex, کلید_ECDSA, پوچ);
	do_kex_with_کلید(st, ts, kex, کلید_ED25519, پوچ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ایستا تهی
kex_extras(ساختار shared_state *st, ساختار test_state *ts)
{
	ایستا ثابت نویسه * ثابت ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		پوچ,
	};
	ایستا ثابت نویسه * ثابت macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		پوچ,
	};
	ایستا ثابت نویسه * ثابت comps[] = {
		"zlib@openssh.com",
		"zlib",
		پوچ,
	};
	ثابت نویسه *kex = "curve25519-sha256@libssh.org";
	صحیح i;

	برای (i = 0; ciphers[i] != پوچ; i++) {
		ساختار kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
	برای (i = 0; macs[i] != پوچ; i++) {
		ساختار kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
	برای (i = 0; comps[i] != پوچ; i++) {
		ساختار kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
}

ایستا تهی
kex_tests(ساختار shared_state *st, ساختار test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	ایستا ساختار shared_state *st;
	ساختار test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_سطرها * 4];
	u_char zbuf[4096] = {0};
	ایستا LogLevel loglevel = SYSLOG_LEVEL_INFO;

	اگر (st == پوچ) {
		اگر (getenv("DEBUG") != پوچ || getenv("KEX_FUZZ_DEBUG") != پوچ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ساختار shared_state *)xcalloc(1, اندازه(*st));
		prepare_کلیدها(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', اندازه(crbuf));

	ts = (ساختار test_state *)xcalloc(1, اندازه(*ts));
	اگر ((ts->s_template = sshbuf_new()) == پوچ ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, اندازه(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, اندازه(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	آزاد(ts);

	ts = (ساختار test_state *)xcalloc(1, اندازه(*ts));
	اگر ((ts->c_template = sshbuf_new()) == پوچ ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, اندازه(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, اندازه(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	آزاد(ts);

	بازگشت 0;
}
#endif /* STANDALONE */
} /* extern "C" */
