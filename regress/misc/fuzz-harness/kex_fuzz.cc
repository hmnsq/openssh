// libfuzzer driver for key exchange fuzzing.


#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

خارجی "C" {

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

ساکن صحیح prepare_کلید(ساخت shared_state *st, صحیح keytype, صحیح بٹ);

ساخت shared_state {
	سائز_t nkeys;
	ساخت sshkey **privkeys, **pubkeys;
};

ساخت test_state {
	ساخت sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ساخت sshbuf *جیب, *داخل; /* input; setup per-test in do_kex_with_key */
	ساخت sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ساخت kex_overrides {
	ثابت حرف *cipher;
	ثابت حرف *mac;
	ثابت حرف *comp;
};

ساکن صحیح
do_send_and_receive(ساخت ssh *from, ساخت ssh *مقصد,
    ساخت sshbuf *store, صحیح clobber, سائز_t *n)
{
	u_char type;
	سائز_t len;
	ثابت u_char *buf;
	صحیح r;

	برائے (*n = 0;; (*n)++) {
		اگر ((r = ssh_packet_اگلا(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			واپس r;
		}
		اگر (type != 0)
			واپس 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		اگر (len == 0)
			واپس 0;
		اگر ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			واپس r;
		}
		اگر (store != تہی && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			واپس r;
		}
		اگر (!clobber && (r = ssh_داخلہ_append(مقصد, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			واپس r;
		}
	}
}

ساکن صحیح
تسلسل_kex(ساخت test_state *ts, ساخت ssh *client, ساخت ssh *server)
{
	صحیح r = 0;
	سائز_t cn, sn;

	/* If fuzzing, replace server/client input */
	اگر (ts->جیب != تہی) {
		اگر ((r = ssh_داخلہ_append(server, sshbuf_ptr(ts->جیب),
		    sshbuf_len(ts->جیب))) != 0) {
			error_fr(r, "ssh_input_append");
			واپس r;
		}
		sshbuf_reset(ts->جیب);
	}
	اگر (ts->داخل != تہی) {
		اگر ((r = ssh_داخلہ_append(client, sshbuf_ptr(ts->داخل),
		    sshbuf_len(ts->داخل))) != 0) {
			error_fr(r, "ssh_input_append");
			واپس r;
		}
		sshbuf_reset(ts->داخل);
	}
	جب (!server->kex->مکمل || !client->kex->مکمل) {
		cn = sn = 0;
		debug_f("S:");
		اگر ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->داخل != تہی, &sn)) != 0) {
			debug_fr(r, "S->C");
			توڑو;
		}
		debug_f("C:");
		اگر ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->جیب != تہی, &cn)) != 0) {
			debug_fr(r, "C->S");
			توڑو;
		}
		اگر (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			توڑو;
		}
	}
	debug_fr(r, "done");
	واپس r;
}

ساکن خالی
store_کلید(ساخت shared_state *st, ساخت sshkey *pubkey,
    ساخت sshkey *privkey)
{
	اگر (st == تہی || pubkey->type < 0 || pubkey->type > زیادہ_سے_زیادہ_عدد ||
	    privkey->type != pubkey->type ||
	    ((سائز_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != تہی))
		abort();
	اگر ((سائز_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ساخت sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, حجم(*st->pubkeys));
		st->privkeys = (ساخت sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, حجم(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ساکن صحیح
prepare_کلیدیں(ساخت shared_state *st)
{
	اگر (prepare_کلید(st, کلید_RSA, 2048) != 0 ||
	    prepare_کلید(st, کلید_ECDSA, 256) != 0 ||
	    prepare_کلید(st, کلید_ED25519, 256) != 0) {
		error_f("key prepare failed");
		واپس -1;
	}
	واپس 0;
}

ساکن ساخت sshkey *
get_pubkey(ساخت shared_state *st, صحیح keytype)
{
	اگر (st == تہی || keytype < 0 || (سائز_t)keytype >= st->nkeys ||
	    st->pubkeys == تہی || st->pubkeys[keytype] == تہی)
		abort();
	واپس st->pubkeys[keytype];
}

ساکن ساخت sshkey *
get_privkey(ساخت shared_state *st, صحیح keytype)
{
	اگر (st == تہی || keytype < 0 || (سائز_t)keytype >= st->nkeys ||
	    st->privkeys == تہی || st->privkeys[keytype] == تہی)
		abort();
	واپس st->privkeys[keytype];
}

ساکن صحیح
build_proposal_side(حرف **برآمد, ثابت حرف *defaults[PROPOSAL_MAX],
    ثابت حرف *kex, ثابت حرف *keyname,
    ثابت حرف *cipher, ثابت حرف *mac, ثابت حرف *comp)
{
	صحیح i;
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *ccp = defaults[i];
#اگر_تعریف_شدہ CIPHER_NONE_AVAIL
		اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#اگر_ختم
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			ccp = keyname;
		ورنہ اگر (i == PROPOSAL_KEX_ALGS && kex != تہی)
			ccp = kex;
		ورنہ اگر ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != تہی)
			ccp = cipher;
		ورنہ اگر ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != تہی)
			ccp = mac;
		ورنہ اگر ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != تہی)
			ccp = comp;
		اگر ((برآمد[i] = strdup(ccp)) == تہی)
			واپس -1;
	}
	واپس 0;
}

ساکن صحیح
do_kex_with_کلید(ساخت shared_state *st, ساخت test_state *ts,
    ثابت حرف *kex, صحیح keytype, ثابت ساخت kex_overrides *ov)
{
	ساخت ssh *client = تہی, *server = تہی;
	ساخت sshkey *privkey = تہی, *pubkey = تہی;
	ساخت sshbuf *state = تہی;
	ساخت kex_params kex_params;
	ثابت حرف *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *myproposal[PROPOSAL_MAX] = {0};
	حرف *keyname = تہی;
	صحیح i, r;

	ts->داخل = ts->جیب = تہی;
	اگر (ts->c_template != تہی &&
	    (ts->داخل = sshbuf_fromb(ts->c_template)) == تہی)
		abort();
	اگر (ts->s_template != تہی &&
	    (ts->جیب = sshbuf_fromb(ts->s_template)) == تہی)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	اگر (ts->داخل != تہی) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->داخل));
	} ورنہ اگر (ts->جیب != تہی) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->جیب));
	} ورنہ
		debug_f("%s %s noclobber", kex, keyname);

	اگر (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : تہی,
	    ov ? ov->mac : تہی,
	    ov ? ov->comp : تہی) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ fail;
	}
	حافظہ_نقل(kex_params.proposal, myproposal, حجم(myproposal));
	اگر ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		جاؤ fail;
	}
	اگر ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		جاؤ fail;
	}
	اگر ((r = ssh_جوڑو_hostkey(server, privkey)) != 0 ||
	    (r = ssh_جوڑو_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		جاؤ fail;
	}
	اگر ((r = تسلسل_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		جاؤ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(myproposal[i]);
	sshbuf_free(ts->جیب);
	sshbuf_free(ts->داخل);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	آزاد(keyname);
	واپس r;
}

ساکن صحیح
prepare_کلید(ساخت shared_state *st, صحیح kt, صحیح بٹ)
{
	ثابت حرف *pubstr = تہی;
	ثابت حرف *privstr = تہی;
	حرف *tmp, *cp;
	ساخت sshkey *privkey = تہی, *pubkey = تہی;
	ساخت sshbuf *b = تہی;
	صحیح r;

	انتخاب (kt) {
	حالت کلید_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		توڑو;
	حالت کلید_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		توڑو;
	حالت کلید_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		توڑو;
	طےشدہ:
		abort();
	}
	اگر ((b = sshbuf_from(privstr, لڑی_لمبائی(privstr))) == تہی)
		abort();
	اگر ((r = sshkey_parse_نجی_fileblob(b, "", &privkey, تہی)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	اگر ((pubkey = sshkey_new(کلید_UNSPEC)) == تہی)
		abort();
	اگر ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	آزاد(tmp);

	store_کلید(st, pubkey, privkey);
	واپس 0;
}

#اگر defined(STANDALONE)

#اگر 0 /* use this if generating new keys to embed above */
ساکن صحیح
prepare_کلید(ساخت shared_state *st, صحیح keytype, صحیح بٹ)
{
	ساخت sshkey *privkey = تہی, *pubkey = تہی;
	صحیح r;

	اگر ((r = sshkey_generate(keytype, بٹ, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	اگر ((r = sshkey_from_نجی(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_کلید(st, pubkey, privkey);
	واپس 0;
}
#اگر_ختم

صحیح مین(خالی)
{
	ساکن ساخت shared_state *st;
	ساخت test_state *ts;
	ثابت صحیح keytypes[] = { کلید_RSA, کلید_ECDSA, کلید_ED25519, -1 };
	ساکن ثابت حرف * ثابت kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		تہی,
	};
	صحیح i, j;
	حرف *راستہ;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	اگر (st == تہی) {
		st = (ساخت shared_state *)xcalloc(1, حجم(*st));
		prepare_کلیدیں(st);
	}
	/* Run each kex method for each key and save client/server packets */
	برائے (i = 0; keytypes[i] != -1; i++) {
		برائے (j = 0; kextypes[j] != تہی; j++) {
			ts = (ساخت test_state *)xcalloc(1, حجم(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_کلید(st, ts, kextypes[j], keytypes[i], تہی);
			xasprintf(&راستہ, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", راستہ);
			اگر ((f = fopen(راستہ, "wb+")) == تہی)
				abort();
			اگر (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			آزاد(راستہ);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&راستہ, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", راستہ);
			اگر ((f = fopen(راستہ, "wb+")) == تہی)
				abort();
			اگر (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			آزاد(راستہ);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			آزاد(ts);
		}
	}
	برائے (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&راستہ, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", راستہ);
		اگر (sshkey_save_نجی(st->privkeys[keytypes[i]], راستہ,
		    "", "", SSHKEY_نجی_OPENSSH, تہی, 0) != 0)
			abort();
		آزاد(راستہ);
		xasprintf(&راستہ, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", راستہ);
		اگر (sshkey_save_عوامی(st->pubkeys[keytypes[i]], راستہ, "") != 0)
			abort();
		آزاد(راستہ);
	}
}
#ورنہ /* !STANDALONE */
ساکن خالی
do_kex(ساخت shared_state *st, ساخت test_state *ts, ثابت حرف *kex)
{
	do_kex_with_کلید(st, ts, kex, کلید_RSA, تہی);
	do_kex_with_کلید(st, ts, kex, کلید_ECDSA, تہی);
	do_kex_with_کلید(st, ts, kex, کلید_ED25519, تہی);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ساکن خالی
kex_extras(ساخت shared_state *st, ساخت test_state *ts)
{
	ساکن ثابت حرف * ثابت ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		تہی,
	};
	ساکن ثابت حرف * ثابت macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		تہی,
	};
	ساکن ثابت حرف * ثابت comps[] = {
		"zlib@openssh.com",
		"zlib",
		تہی,
	};
	ثابت حرف *kex = "curve25519-sha256@libssh.org";
	صحیح i;

	برائے (i = 0; ciphers[i] != تہی; i++) {
		ساخت kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
	برائے (i = 0; macs[i] != تہی; i++) {
		ساخت kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
	برائے (i = 0; comps[i] != تہی; i++) {
		ساخت kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_کلید(st, ts, kex, کلید_ED25519, &ov);
	}
}

ساکن خالی
kex_tests(ساخت shared_state *st, ساخت test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	ساکن ساخت shared_state *st;
	ساخت test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_سطریں * 4];
	u_char zbuf[4096] = {0};
	ساکن LogLevel loglevel = SYSLOG_LEVEL_INFO;

	اگر (st == تہی) {
		اگر (getenv("DEBUG") != تہی || getenv("KEX_FUZZ_DEBUG") != تہی)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ساخت shared_state *)xcalloc(1, حجم(*st));
		prepare_کلیدیں(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', حجم(crbuf));

	ts = (ساخت test_state *)xcalloc(1, حجم(*ts));
	اگر ((ts->s_template = sshbuf_new()) == تہی ||
	    sshbuf_put(ts->s_template, ڈیٹا, سائز) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, حجم(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, حجم(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	آزاد(ts);

	ts = (ساخت test_state *)xcalloc(1, حجم(*ts));
	اگر ((ts->c_template = sshbuf_new()) == تہی ||
	    sshbuf_put(ts->c_template, ڈیٹا, سائز) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, حجم(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, حجم(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	آزاد(ts);

	واپس 0;
}
#اگر_ختم /* STANDALONE */
} /* extern "C" */
