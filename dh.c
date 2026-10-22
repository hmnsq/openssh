/* $OpenBSD: dh.c,v 1.76 2026/02/08 19:54:31 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव "dh.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "ssherr.h"

स्थिर ध्रुव वर्ण *moduli_filename;

शून्य dh_set_moduli_file(ध्रुव वर्ण *filename)
{
	moduli_filename = filename;
}

स्थिर ध्रुव वर्ण * get_moduli_filename(शून्य)
{
	प्रत्यागम moduli_filename ? moduli_filename : _PATH_DH_MODULI;
}

स्थिर पूर्णाङ्क
parse_अभाज्य(पूर्णाङ्क linenum, वर्ण *पंक्ति, संरचना dhgroup *dhg)
{
	वर्ण *cp, *arg;
	वर्ण *strsize, *gen, *अभाज्य;
	ध्रुव वर्ण *errstr = रिक्त;
	long long n;

	dhg->p = dhg->g = रिक्त;
	cp = पंक्ति;
	यदि ((arg = strdelim(&cp)) == रिक्त)
		प्रत्यागम 0;
	/* Ignore leading whitespace */
	यदि (*arg == '\0')
		arg = strdelim(&cp);
	यदि (!arg || !*arg || *arg == '#')
		प्रत्यागम 0;

	/* time */
	यदि (cp == रिक्त || *arg == '\0')
		गच्छ truncated;
	arg = strsep(&cp, " "); /* type */
	यदि (cp == रिक्त || *arg == '\0')
		गच्छ truncated;
	/* Ensure this is a safe prime */
	n = strtonum(arg, 0, 5, &errstr);
	यदि (errstr != रिक्त || n != MODULI_TYPE_SAFE) {
		error("moduli:%d: type is not %d", linenum, MODULI_TYPE_SAFE);
		गच्छ fail;
	}
	arg = strsep(&cp, " "); /* tests */
	यदि (cp == रिक्त || *arg == '\0')
		गच्छ truncated;
	/* Ensure prime has been tested and is not composite */
	n = strtonum(arg, 0, 0x1f, &errstr);
	यदि (errstr != रिक्त ||
	    (n & MODULI_TESTS_COMPOSITE) || !(n & ~MODULI_TESTS_COMPOSITE)) {
		error("moduli:%d: invalid moduli tests flag", linenum);
		गच्छ fail;
	}
	arg = strsep(&cp, " "); /* tries */
	यदि (cp == रिक्त || *arg == '\0')
		गच्छ truncated;
	n = strtonum(arg, 0, 1<<30, &errstr);
	यदि (errstr != रिक्त || n == 0) {
		error("moduli:%d: invalid primality trial count", linenum);
		गच्छ fail;
	}
	strsize = strsep(&cp, " "); /* size */
	यदि (cp == रिक्त || *strsize == '\0' ||
	    (dhg->size = (पूर्णाङ्क)strtonum(strsize, 0, 64*1024, &errstr)) == 0 ||
	    errstr) {
		error("moduli:%d: invalid prime length", linenum);
		गच्छ fail;
	}
	/* The whole group is one bit larger */
	dhg->size++;
	gen = strsep(&cp, " "); /* gen */
	यदि (cp == रिक्त || *gen == '\0')
		गच्छ truncated;
	अभाज्य = strsep(&cp, " "); /*अभाज्य*/
	यदि (cp != रिक्त || *अभाज्य == '\0') {
 truncated:
		error("moduli:%d: truncated", linenum);
		गच्छ fail;
	}

	यदि ((dhg->g = BN_new()) == रिक्त ||
	    (dhg->p = BN_new()) == रिक्त) {
		error("parse_prime: BN_new failed");
		गच्छ fail;
	}
	यदि (BN_hex2bn(&dhg->g, gen) == 0) {
		error("moduli:%d: could not parse generator value", linenum);
		गच्छ fail;
	}
	यदि (BN_hex2bn(&dhg->p, अभाज्य) == 0) {
		error("moduli:%d: could not parse prime value", linenum);
		गच्छ fail;
	}
	यदि (BN_अंक_bits(dhg->p) != dhg->size) {
		error("moduli:%d: prime has wrong size: actual %d listed %d",
		    linenum, BN_अंक_bits(dhg->p), dhg->size - 1);
		गच्छ fail;
	}
	यदि (BN_cmp(dhg->g, BN_मूल्य_one()) <= 0) {
		error("moduli:%d: generator is invalid", linenum);
		गच्छ fail;
	}
	प्रत्यागम 1;

 fail:
	BN_clear_free(dhg->g);
	BN_clear_free(dhg->p);
	dhg->g = dhg->p = रिक्त;
	प्रत्यागम 0;
}

DH *
choose_dh(पूर्णाङ्क min, पूर्णाङ्क wantbits, पूर्णाङ्क max)
{
	FILE *f;
	वर्ण *पंक्ति = रिक्त;
	size_t linesize = 0;
	पूर्णाङ्क best, bestcount, which, linenum;
	संरचना dhgroup dhg;

	यदि ((f = fopen(get_moduli_filename(), "r")) == रिक्त) {
		logit("WARNING: could not open %s (%s), using fixed modulus",
		    get_moduli_filename(), strerror(errno));
		प्रत्यागम (dh_new_group_fallback(max));
	}

	linenum = 0;
	best = bestcount = 0;
	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		यदि (!parse_अभाज्य(linenum, पंक्ति, &dhg))
			अनुवर्त;
		BN_clear_free(dhg.g);
		BN_clear_free(dhg.p);

		यदि (dhg.size > max || dhg.size < min)
			अनुवर्त;

		यदि ((dhg.size > wantbits && dhg.size < best) ||
		    (dhg.size > best && best < wantbits)) {
			best = dhg.size;
			bestcount = 0;
		}
		यदि (dhg.size == best)
			bestcount++;
	}
	मुक्त(पंक्ति);
	पंक्ति = रिक्त;
	linesize = 0;
	rewind(f);

	यदि (bestcount == 0) {
		fclose(f);
		logit("WARNING: no suitable primes (size %d/%d/%d) in %s",
		    min, wantbits, max, get_moduli_filename());
		प्रत्यागम रिक्त;
	}
	which = arc4random_uniform(bestcount);

	linenum = 0;
	bestcount = 0;
	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		यदि (!parse_अभाज्य(linenum, पंक्ति, &dhg))
			अनुवर्त;
		यदि ((dhg.size > max || dhg.size < min) ||
		    dhg.size != best ||
		    bestcount++ != which) {
			BN_clear_free(dhg.g);
			BN_clear_free(dhg.p);
			अनुवर्त;
		}
		भङ्ग;
	}
	मुक्त(पंक्ति);
	पंक्ति = रिक्त;
	fclose(f);
	यदि (bestcount != which + 1) {
		logit("WARNING: selected prime disappeared in %s, giving up",
		    get_moduli_filename());
		प्रत्यागम (dh_new_group_fallback(max));
	}

	प्रत्यागम (dh_new_group(dhg.g, dhg.p));
}

/* diffie-hellman-groupN-sha1 */

पूर्णाङ्क
dh_pub_is_valid(ध्रुव DH *dh, ध्रुव BIGNUM *dh_pub)
{
	पूर्णाङ्क i;
	पूर्णाङ्क n = BN_अंक_bits(dh_pub);
	पूर्णाङ्क bits_set = 0;
	BIGNUM *tmp;
	ध्रुव BIGNUM *dh_p;

	DH_get0_pqg(dh, &dh_p, रिक्त, रिक्त);

	यदि (BN_is_negative(dh_pub)) {
		logit("invalid public DH value: negative");
		प्रत्यागम 0;
	}
	यदि (BN_cmp(dh_pub, BN_मूल्य_one()) != 1) {	/* pub_exp <= 1 */
		logit("invalid public DH value: <= 1");
		प्रत्यागम 0;
	}

	यदि ((tmp = BN_new()) == रिक्त) {
		error_f("BN_new failed");
		प्रत्यागम 0;
	}
	यदि (!BN_sub(tmp, dh_p, BN_मूल्य_one()) ||
	    BN_cmp(dh_pub, tmp) != -1) {		/* pub_exp > p-2 */
		BN_clear_free(tmp);
		logit("invalid public DH value: >= p-1");
		प्रत्यागम 0;
	}
	BN_clear_free(tmp);

	प्रति (i = 0; i <= n; i++)
		यदि (BN_is_bit_set(dh_pub, i))
			bits_set++;
	debug2("bits set: %d/%d", bits_set, BN_अंक_bits(dh_p));

	/*
	 * if g==2 and bits_set==1 then computing log_g(dh_pub) is trivial
	 */
	यदि (bits_set < 4) {
		logit("invalid public DH value (%d/%d)",
		    bits_set, BN_अंक_bits(dh_p));
		प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

पूर्णाङ्क
dh_gen_कुंजी(DH *dh, पूर्णाङ्क need)
{
	पूर्णाङ्क pbits;
	ध्रुव BIGNUM *dh_p, *pub_कुंजी;

	DH_get0_pqg(dh, &dh_p, रिक्त, रिक्त);

	यदि (need < 0 || dh_p == रिक्त ||
	    (pbits = BN_अंक_bits(dh_p)) <= 0 ||
	    need > INT_MAX / 2 || 2 * need > pbits)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (need < 256)
		need = 256;
	/*
	 * Pollard Rho, Big step/Little Step attacks are O(sqrt(n)),
	 * so double requested need here.
	 */
	यदि (!DH_set_length(dh, MINIMUM(need * 2, pbits - 1)))
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;

	यदि (DH_generate_कुंजी(dh) == 0)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	DH_get0_कुंजी(dh, &pub_कुंजी, रिक्त);
	यदि (!dh_pub_is_valid(dh, pub_कुंजी))
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम 0;
}

DH *
dh_new_group_asc(ध्रुव वर्ण *gen, ध्रुव वर्ण *modulus)
{
	DH *dh;
	BIGNUM *dh_p = रिक्त, *dh_g = रिक्त;

	यदि ((dh = DH_new()) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (BN_hex2bn(&dh_p, modulus) == 0 ||
	    BN_hex2bn(&dh_g, gen) == 0)
		गच्छ fail;
	यदि (!DH_set0_pqg(dh, dh_p, रिक्त, dh_g))
		गच्छ fail;
	प्रत्यागम dh;
 fail:
	DH_free(dh);
	BN_clear_free(dh_p);
	BN_clear_free(dh_g);
	प्रत्यागम रिक्त;
}

/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */
DH *
dh_new_group(BIGNUM *gen, BIGNUM *modulus)
{
	DH *dh;

	यदि ((dh = DH_new()) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (!DH_set0_pqg(dh, modulus, रिक्त, gen)) {
		DH_free(dh);
		प्रत्यागम रिक्त;
	}

	प्रत्यागम dh;
}

/* rfc2409 "Second Oakley Group" (1024 bits) */
DH *
dh_new_group1(शून्य)
{
	स्थिर वर्ण *gen = "2", *group1 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

	प्रत्यागम (dh_new_group_asc(gen, group1));
}

/* rfc3526 group 14 "2048-bit MODP Group" */
DH *
dh_new_group14(शून्य)
{
	स्थिर वर्ण *gen = "2", *group14 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF";

	प्रत्यागम (dh_new_group_asc(gen, group14));
}

/* rfc3526 group 16 "4096-bit MODP Group" */
DH *
dh_new_group16(शून्य)
{
	स्थिर वर्ण *gen = "2", *group16 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34063199"
	    "FFFFFFFF" "FFFFFFFF";

	प्रत्यागम (dh_new_group_asc(gen, group16));
}

/* rfc3526 group 18 "8192-bit MODP Group" */
DH *
dh_new_group18(शून्य)
{
	स्थिर वर्ण *gen = "2", *group18 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34028492"
	    "36C3FAB4" "D27C7026" "C1D4DCB2" "602646DE" "C9751E76" "3DBA37BD"
	    "F8FF9406" "AD9E530E" "E5DB382F" "413001AE" "B06A53ED" "9027D831"
	    "179727B0" "865A8918" "DA3EDBEB" "CF9B14ED" "44CE6CBA" "CED4BB1B"
	    "DB7F1447" "E6CC254B" "33205151" "2BD7AF42" "6FB8F401" "378CD2BF"
	    "5983CA01" "C64B92EC" "F032EA15" "D1721D03" "F482D7CE" "6E74FEF6"
	    "D55E702F" "46980C82" "B5A84031" "900B1C9E" "59E7C97F" "BEC7E8F3"
	    "23A97A7E" "36CC88BE" "0F1D45B7" "FF585AC5" "4BD407B2" "2B4154AA"
	    "CC8F6D7E" "BF48E1D8" "14CC5ED2" "0F8037E0" "A79715EE" "F29BE328"
	    "06A1D58B" "B7C5DA76" "F550AA3D" "8A1FBFF0" "EB19CCB1" "A313D55C"
	    "DA56C9EC" "2EF29632" "387FE8D7" "6E3C0468" "043E8F66" "3F4860EE"
	    "12BF2D5B" "0B7474D6" "E694F91E" "6DBE1159" "74A3926F" "12FEE5E4"
	    "38777CB6" "A932DF8C" "D8BEC4D0" "73B931BA" "3BC832B6" "8D9DD300"
	    "741FA7BF" "8AFC47ED" "2576F693" "6BA42466" "3AAB639C" "5AE4F568"
	    "3423B474" "2BF1C978" "238F16CB" "E39D652D" "E3FDB8BE" "FC848AD9"
	    "22222E04" "A4037C07" "13EB57A8" "1A23F0C7" "3473FC64" "6CEA306B"
	    "4BCBC886" "2F8385DD" "FA9D4B7F" "A2C087E8" "79683303" "ED5BDD3A"
	    "062B3CF5" "B3A278A6" "6D2A13F8" "3F44F82D" "DF310EE0" "74AB6A36"
	    "4597E899" "A0255DC1" "64F31CC5" "0846851D" "F9AB4819" "5DED7EA1"
	    "B1D510BD" "7EE74D73" "FAF36BC3" "1ECFA268" "359046F4" "EB879F92"
	    "4009438B" "481C6CD7" "889A002E" "D5EE382B" "C9190DA6" "FC026E47"
	    "9558E447" "5677E9AA" "9E3050E2" "765694DF" "C81F56E8" "80B96E71"
	    "60C980DD" "98EDD3DF" "FFFFFFFF" "FFFFFFFF";

	प्रत्यागम (dh_new_group_asc(gen, group18));
}

/* Select fallback group used by DH-GEX if moduli file cannot be read. */
DH *
dh_new_group_fallback(पूर्णाङ्क max)
{
	debug3_f("requested max size %d", max);
	यदि (max < 3072) {
		debug3("using 2k bit group 14");
		प्रत्यागम dh_new_group14();
	} अन्यथा यदि (max < 6144) {
		debug3("using 4k bit group 16");
		प्रत्यागम dh_new_group16();
	}
	debug3("using 8k bit group 18");
	प्रत्यागम dh_new_group18();
}

/*
 * Estimates the group order for a Diffie-Hellman group that has an
 * attack complexity approximately the same as O(2**bits).
 * Values from NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 (rev 3) limited by the recommended maximum value
 * from RFC4419 section 3.
 */
u_int
dh_estimate(पूर्णाङ्क bits)
{
	यदि (bits <= 112)
		प्रत्यागम 2048;
	यदि (bits <= 128)
		प्रत्यागम 3072;
	यदि (bits <= 192)
		प्रत्यागम 7680;
	प्रत्यागम 8192;
}

#endif /* WITH_OPENSSL */
