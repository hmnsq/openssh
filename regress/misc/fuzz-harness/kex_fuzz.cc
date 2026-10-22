// libfuzzer driver for key exchange fuzzing.


#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي "C" {

#ضمن "includes.h"
#ضمن "ssherr.h"
#ضمن "ssh_api.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "xmalloc.h"
#ضمن "authfile.h"
#ضمن "log.h"

#ضمن "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

ساكن صحيح prepare_ئاچقۇچ(بنية shared_state *st, صحيح keytype, صحيح bits);

بنية shared_state {
	size_t nkeys;
	بنية sshkey **privkeys, **pubkeys;
};

بنية test_state {
	بنية sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	بنية sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	بنية sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
بنية kex_overrides {
	ثابت حرف *cipher;
	ثابت حرف *mac;
	ثابت حرف *comp;
};

ساكن صحيح
do_send_and_receive(بنية ssh *from, بنية ssh *to,
    بنية sshbuf *store, صحيح clobber, size_t *n)
{
	u_char type;
	size_t len;
	ثابت u_char *buf;
	صحيح r;

	لكل (*n = 0;; (*n)++) {
		إذا ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			أرجع r;
		}
		إذا (type != 0)
			أرجع 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		إذا (len == 0)
			أرجع 0;
		إذا ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			أرجع r;
		}
		إذا (store != عدم && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			أرجع r;
		}
		إذا (!clobber && (r = ssh_كىرگۈزۈش_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			أرجع r;
		}
	}
}

ساكن صحيح
run_kex(بنية test_state *ts, بنية ssh *client, بنية ssh *server)
{
	صحيح r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	إذا (ts->sin != عدم) {
		إذا ((r = ssh_كىرگۈزۈش_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			أرجع r;
		}
		sshbuf_reset(ts->sin);
	}
	إذا (ts->cin != عدم) {
		إذا ((r = ssh_كىرگۈزۈش_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			أرجع r;
		}
		sshbuf_reset(ts->cin);
	}
	طالما (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		إذا ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != عدم, &sn)) != 0) {
			debug_fr(r, "S->C");
			اكسر;
		}
		debug_f("C:");
		إذا ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != عدم, &cn)) != 0) {
			debug_fr(r, "C->S");
			اكسر;
		}
		إذا (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			اكسر;
		}
	}
	debug_fr(r, "done");
	أرجع r;
}

ساكن فراغ
store_ئاچقۇچ(بنية shared_state *st, بنية sshkey *pubkey,
    بنية sshkey *privkey)
{
	إذا (st == عدم || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != عدم))
		abort();
	إذا ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (بنية sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, حجم(*st->pubkeys));
		st->privkeys = (بنية sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, حجم(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ساكن صحيح
prepare_ئاچقۇچلار(بنية shared_state *st)
{
	إذا (prepare_ئاچقۇچ(st, ئاچقۇچ_RSA, 2048) != 0 ||
	    prepare_ئاچقۇچ(st, ئاچقۇچ_ECDSA, 256) != 0 ||
	    prepare_ئاچقۇچ(st, ئاچقۇچ_ED25519, 256) != 0) {
		error_f("key prepare failed");
		أرجع -1;
	}
	أرجع 0;
}

ساكن بنية sshkey *
get_pubkey(بنية shared_state *st, صحيح keytype)
{
	إذا (st == عدم || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == عدم || st->pubkeys[keytype] == عدم)
		abort();
	أرجع st->pubkeys[keytype];
}

ساكن بنية sshkey *
get_privkey(بنية shared_state *st, صحيح keytype)
{
	إذا (st == عدم || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == عدم || st->privkeys[keytype] == عدم)
		abort();
	أرجع st->privkeys[keytype];
}

ساكن صحيح
build_proposal_side(حرف **out, ثابت حرف *defaults[PROPOSAL_MAX],
    ثابت حرف *kex, ثابت حرف *keyname,
    ثابت حرف *cipher, ثابت حرف *mac, ثابت حرف *comp)
{
	صحيح i;
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		إذا (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		إذا (i == PROPOSAL_SERVER_HOST_ئاچقۇچ_ALGS)
			ccp = keyname;
		وإلا إذا (i == PROPOSAL_KEX_ALGS && kex != عدم)
			ccp = kex;
		وإلا إذا ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != عدم)
			ccp = cipher;
		وإلا إذا ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != عدم)
			ccp = mac;
		وإلا إذا ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != عدم)
			ccp = comp;
		إذا ((out[i] = strdup(ccp)) == عدم)
			أرجع -1;
	}
	أرجع 0;
}

ساكن صحيح
do_kex_with_ئاچقۇچ(بنية shared_state *st, بنية test_state *ts,
    ثابت حرف *kex, صحيح keytype, ثابت بنية kex_overrides *ov)
{
	بنية ssh *client = عدم, *server = عدم;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	بنية sshbuf *state = عدم;
	بنية kex_params kex_params;
	ثابت حرف *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *myproposal[PROPOSAL_MAX] = {0};
	حرف *keyname = عدم;
	صحيح i, r;

	ts->cin = ts->sin = عدم;
	إذا (ts->c_template != عدم &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == عدم)
		abort();
	إذا (ts->s_template != عدم &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == عدم)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	إذا (ts->cin != عدم) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} وإلا إذا (ts->sin != عدم) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} وإلا
		debug_f("%s %s noclobber", kex, keyname);

	إذا (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : عدم,
	    ov ? ov->mac : عدم,
	    ov ? ov->comp : عدم) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب fail;
	}
	memcpy(kex_params.proposal, myproposal, حجم(myproposal));
	إذا ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		اذهب fail;
	}
	إذا ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		اذهب fail;
	}
	إذا ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		اذهب fail;
	}
	إذا ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		اذهب fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	حرر(keyname);
	أرجع r;
}

ساكن صحيح
prepare_ئاچقۇچ(بنية shared_state *st, صحيح kt, صحيح bits)
{
	ثابت حرف *pubstr = عدم;
	ثابت حرف *privstr = عدم;
	حرف *tmp, *cp;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	بنية sshbuf *b = عدم;
	صحيح r;

	بدل (kt) {
	حالة ئاچقۇچ_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		اكسر;
	حالة ئاچقۇچ_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		اكسر;
	حالة ئاچقۇچ_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		اكسر;
	افتراضي:
		abort();
	}
	إذا ((b = sshbuf_from(privstr, strlen(privstr))) == عدم)
		abort();
	إذا ((r = sshkey_parse_private_fileblob(b, "", &privkey, عدم)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	إذا ((pubkey = sshkey_new(ئاچقۇچ_UNSPEC)) == عدم)
		abort();
	إذا ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	حرر(tmp);

	store_ئاچقۇچ(st, pubkey, privkey);
	أرجع 0;
}

#إذا defined(STANDALONE)

#إذا 0 /* use this if generating new keys to embed above */
ساكن صحيح
prepare_ئاچقۇچ(بنية shared_state *st, صحيح keytype, صحيح bits)
{
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	صحيح r;

	إذا ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	إذا ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ئاچقۇچ(st, pubkey, privkey);
	أرجع 0;
}
#endif

صحيح main(فراغ)
{
	ساكن بنية shared_state *st;
	بنية test_state *ts;
	ثابت صحيح keytypes[] = { ئاچقۇچ_RSA, ئاچقۇچ_ECDSA, ئاچقۇچ_ED25519, -1 };
	ساكن ثابت حرف * ثابت kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		عدم,
	};
	صحيح i, j;
	حرف *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	إذا (st == عدم) {
		st = (بنية shared_state *)xcalloc(1, حجم(*st));
		prepare_ئاچقۇچلار(st);
	}
	/* Run each kex method for each key and save client/server packets */
	لكل (i = 0; keytypes[i] != -1; i++) {
		لكل (j = 0; kextypes[j] != عدم; j++) {
			ts = (بنية test_state *)xcalloc(1, حجم(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ئاچقۇچ(st, ts, kextypes[j], keytypes[i], عدم);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			إذا ((f = fopen(path, "wb+")) == عدم)
				abort();
			إذا (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			حرر(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			إذا ((f = fopen(path, "wb+")) == عدم)
				abort();
			إذا (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			حرر(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			حرر(ts);
		}
	}
	لكل (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		إذا (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, عدم, 0) != 0)
			abort();
		حرر(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		إذا (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		حرر(path);
	}
}
#وإلا /* !STANDALONE */
ساكن فراغ
do_kex(بنية shared_state *st, بنية test_state *ts, ثابت حرف *kex)
{
	do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_RSA, عدم);
	do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_ECDSA, عدم);
	do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_ED25519, عدم);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ساكن فراغ
kex_extras(بنية shared_state *st, بنية test_state *ts)
{
	ساكن ثابت حرف * ثابت ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		عدم,
	};
	ساكن ثابت حرف * ثابت macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		عدم,
	};
	ساكن ثابت حرف * ثابت comps[] = {
		"zlib@openssh.com",
		"zlib",
		عدم,
	};
	ثابت حرف *kex = "curve25519-sha256@libssh.org";
	صحيح i;

	لكل (i = 0; ciphers[i] != عدم; i++) {
		بنية kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_ED25519, &ov);
	}
	لكل (i = 0; macs[i] != عدم; i++) {
		بنية kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_ED25519, &ov);
	}
	لكل (i = 0; comps[i] != عدم; i++) {
		بنية kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ئاچقۇچ(st, ts, kex, ئاچقۇچ_ED25519, &ov);
	}
}

ساكن فراغ
kex_tests(بنية shared_state *st, بنية test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

صحيح LLVMFuzzer_Test_One_كىرگۈزۈش(ثابت uint8_t* data, size_t size)
{
	ساكن بنية shared_state *st;
	بنية test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_قۇرلار * 4];
	u_char zbuf[4096] = {0};
	ساكن LogLevel loglevel = SYSLOG_LEVEL_INFO;

	إذا (st == عدم) {
		إذا (getenv("DEBUG") != عدم || getenv("KEX_FUZZ_DEBUG") != عدم)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (بنية shared_state *)xcalloc(1, حجم(*st));
		prepare_ئاچقۇچلار(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', حجم(crbuf));

	ts = (بنية test_state *)xcalloc(1, حجم(*ts));
	إذا ((ts->s_template = sshbuf_new()) == عدم ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, حجم(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, حجم(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	حرر(ts);

	ts = (بنية test_state *)xcalloc(1, حجم(*ts));
	إذا ((ts->c_template = sshbuf_new()) == عدم ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, حجم(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, حجم(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	حرر(ts);

	أرجع 0;
}
#endif /* STANDALONE */
} /* extern "C" */
