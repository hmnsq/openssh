/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for small string-input parsers across OpenSSH
 *
 * Targets: misc.c, addr.c, addrmatch.c, match.c
 *
 * Threat model:
 * - User-supplied CLI arguments (user@host:port, ssh:// URIs, port and
 *   tunnel numbers)
 * - Admin-supplied patterns in sshd_config / ssh_config (Match Address
 *   CIDR lists, AllowUsers / DenyUsers, AllowGroups, hostname patterns)
 *
 * All targeted functions are pure (no inter-call state). Each iteration
 * invokes every parser exactly once on the same fuzz body in a fixed
 * source order. The body is split into two substrings at the first
 * embedded NUL so two-argument matchers can mutate either side.
 *
 * Parsers covered:
 * - parse_user_host_port, parse_uri, convtime, a2port, a2tun,
 *   argv_split + argv_assemble, valid_domain, valid_env_name,
 *   parse_absolute_time (misc.c)
 * - addr_pton, addr_pton_cidr (addr.c)
 * - addr_match_list, addr_match_cidr_list (addrmatch.c)
 * - match_pattern, match_pattern_list, match_hostname,
 *   match_host_and_ip, match_user (match.c)
 */

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <sys/types.h>

બાહ્ય "C" {
#અન્તર્ભાવ "addr.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"
}

સ્થિર પૂર્ણાંક log_initialized = 0;

સ્થિર અક્ષર *
dup_n(અચલ uint8_t *body, size_t blen)
{
	અક્ષર *s = (અક્ષર *)malloc(blen + 1);
	જો (s == ખાલી)
		પાછા ખાલી;
	memcpy(s, body, blen);
	s[blen] = '\0';
	પાછા s;
}

સ્થિર શૂન્ય
split_two(અચલ uint8_t *body, size_t blen, અક્ષર **a, અક્ષર **b)
{
	અચલ uint8_t *nul = (અચલ uint8_t *)memchr(body, 0, blen);
	*a = ખાલી;
	*b = ખાલી;
	જો (nul == ખાલી) {
		*a = dup_n(body, blen);
		*b = strdup("");
		પાછા;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

બાહ્ય "C" પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	જો (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	જો (size == 0)
		પાછા 0;

	અક્ષર *s = dup_n(data, size);
	અક્ષર *a = ખાલી, *b = ખાલી;
	split_two(data, size, &a, &b);
	જો (s == ખાલી || a == ખાલી || b == ખાલી) {
		મુક્ત(s);
		મુક્ત(a);
		મુક્ત(b);
		પાછા 0;
	}

	{
		અક્ષર *u = ખાલી, *h = ખાલી;
		પૂર્ણાંક port = 0;
		જો (parse_user_host_port(s, &u, &h, &port) == 0) {
			મુક્ત(u);
			મુક્ત(h);
		}
	}
	{
		અક્ષર *u = ખાલી, *h = ખાલી, *p = ખાલી;
		પૂર્ણાંક port = 0;
		જો (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			મુક્ત(u);
			મુક્ત(h);
			મુક્ત(p);
		}
	}
	(શૂન્ય)convtime(s);
	(શૂન્ય)a2port(s);
	{
		પૂર્ણાંક tun = 0;
		(શૂન્ય)a2tun(s, &tun);
	}
	{
		પૂર્ણાંક ac = 0;
		અક્ષર **av = ખાલી;
		જો (argv_split(s, &ac, &av, 1) == 0) {
			અક્ષર *back = argv_assemble(ac, av);
			મુક્ત(back);
			argv_free(av, ac);
		}
	}
	{
		અચલ અક્ષર *err = ખાલી;
		(શૂન્ય)valid_domain(s, 0, &err);
	}
	(શૂન્ય)valid_env_name(s);
	{
		uint64_t t = 0;
		(શૂન્ય)parse_absolute_time(s, &t);
	}

	{
		સંરચના xaddr n;
		(શૂન્ય)addr_pton(s, &n);
	}
	{
		સંરચના xaddr n;
		u_int prefix = 0;
		(શૂન્ય)addr_pton_cidr(s, &n, &prefix);
	}

	(શૂન્ય)addr_match_list(a, b);
	(શૂન્ય)addr_match_cidr_list(a, b);
	(શૂન્ય)match_pattern(a, b);
	(શૂન્ય)match_pattern_list(a, b, 0);
	(શૂન્ય)match_hostname(a, b);
	(શૂન્ય)match_host_and_ip(a, "127.0.0.1", b);
	(શૂન્ય)match_user("fuzz", a, "127.0.0.1", b);

	મુક્ત(s);
	મુક્ત(a);
	મુક્ત(b);
	પાછા 0;
}
