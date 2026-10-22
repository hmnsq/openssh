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

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

ਬਾਹਰੀ "C" {
#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
}

ਸਥਿਰ ਪੂਰਨ log_initialized = 0;

ਸਥਿਰ ਅੱਖਰ *
dup_n(ਅਚਲ uint8_t *body, ਮਾਪ_t blen)
{
	ਅੱਖਰ *s = (ਅੱਖਰ *)ਸਮ੍ਰਿਤੀ_ਦਿਓ(blen + 1);
	ਜੇ (s == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(s, body, blen);
	s[blen] = '\0';
	ਵਾਪਸ s;
}

ਸਥਿਰ ਖਾਲੀ
ਵੰਡੋ_two(ਅਚਲ uint8_t *body, ਮਾਪ_t blen, ਅੱਖਰ **a, ਅੱਖਰ **b)
{
	ਅਚਲ uint8_t *nul = (ਅਚਲ uint8_t *)memchr(body, 0, blen);
	*a = ਨਿਰਾ;
	*b = ਨਿਰਾ;
	ਜੇ (nul == ਨਿਰਾ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ਵਾਪਸ;
	}
	ਮਾਪ_t alen = (ਮਾਪ_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

ਬਾਹਰੀ "C" ਪੂਰਨ
LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	ਜੇ (ਮਾਪ == 0)
		ਵਾਪਸ 0;

	ਅੱਖਰ *s = dup_n(ਅੰਕੜੇ, ਮਾਪ);
	ਅੱਖਰ *a = ਨਿਰਾ, *b = ਨਿਰਾ;
	ਵੰਡੋ_two(ਅੰਕੜੇ, ਮਾਪ, &a, &b);
	ਜੇ (s == ਨਿਰਾ || a == ਨਿਰਾ || b == ਨਿਰਾ) {
		ਮੁਕਤ(s);
		ਮੁਕਤ(a);
		ਮੁਕਤ(b);
		ਵਾਪਸ 0;
	}

	{
		ਅੱਖਰ *u = ਨਿਰਾ, *h = ਨਿਰਾ;
		ਪੂਰਨ ਪੋਰਟ = 0;
		ਜੇ (parse_user_host_ਪੋਰਟ(s, &u, &h, &ਪੋਰਟ) == 0) {
			ਮੁਕਤ(u);
			ਮੁਕਤ(h);
		}
	}
	{
		ਅੱਖਰ *u = ਨਿਰਾ, *h = ਨਿਰਾ, *p = ਨਿਰਾ;
		ਪੂਰਨ ਪੋਰਟ = 0;
		ਜੇ (parse_uri("ssh", s, &u, &h, &ਪੋਰਟ, &p) == 0) {
			ਮੁਕਤ(u);
			ਮੁਕਤ(h);
			ਮੁਕਤ(p);
		}
	}
	(ਖਾਲੀ)convtime(s);
	(ਖਾਲੀ)a2port(s);
	{
		ਪੂਰਨ tun = 0;
		(ਖਾਲੀ)a2tun(s, &tun);
	}
	{
		ਪੂਰਨ ac = 0;
		ਅੱਖਰ **av = ਨਿਰਾ;
		ਜੇ (argv_ਵੰਡੋ(s, &ac, &av, 1) == 0) {
			ਅੱਖਰ *ਪਿੱਠ = argv_assemble(ac, av);
			ਮੁਕਤ(ਪਿੱਠ);
			argv_free(av, ac);
		}
	}
	{
		ਅਚਲ ਅੱਖਰ *err = ਨਿਰਾ;
		(ਖਾਲੀ)valid_domain(s, 0, &err);
	}
	(ਖਾਲੀ)valid_env_name(s);
	{
		uint64_t t = 0;
		(ਖਾਲੀ)parse_absolute_ਸਮਾਂ(s, &t);
	}

	{
		ਬਣਤਰ xaddr n;
		(ਖਾਲੀ)addr_pton(s, &n);
	}
	{
		ਬਣਤਰ xaddr n;
		u_int ਅਗੇਤਰ = 0;
		(ਖਾਲੀ)addr_pton_cidr(s, &n, &ਅਗੇਤਰ);
	}

	(ਖਾਲੀ)addr_ਮੇਲ_list(a, b);
	(ਖਾਲੀ)addr_ਮੇਲ_cidr_list(a, b);
	(ਖਾਲੀ)ਮੇਲ_ਨਮੂਨਾ(a, b);
	(ਖਾਲੀ)ਮੇਲ_ਨਮੂਨਾ_list(a, b, 0);
	(ਖਾਲੀ)ਮੇਲ_hostname(a, b);
	(ਖਾਲੀ)ਮੇਲ_host_and_ip(a, "127.0.0.1", b);
	(ਖਾਲੀ)ਮੇਲ_user("fuzz", a, "127.0.0.1", b);

	ਮੁਕਤ(s);
	ਮੁਕਤ(a);
	ਮੁਕਤ(b);
	ਵਾਪਸ 0;
}
