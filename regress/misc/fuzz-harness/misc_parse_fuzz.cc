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

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "addr.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_initialized = 0;

ಸ್ಥಿರ ವರ್ಣ *
dup_n(ಧ್ರುವ uint8_t *body, size_t blen)
{
	ವರ್ಣ *s = (ವರ್ಣ *)malloc(blen + 1);
	ಯದಿ (s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	memcpy(s, body, blen);
	s[blen] = '\0';
	ಪ್ರತ್ಯಾಗಮ s;
}

ಸ್ಥಿರ ಶೂನ್ಯ
split_two(ಧ್ರುವ uint8_t *body, size_t blen, ವರ್ಣ **a, ವರ್ಣ **b)
{
	ಧ್ರುವ uint8_t *nul = (ಧ್ರುವ uint8_t *)memchr(body, 0, blen);
	*a = ರಿಕ್ತ;
	*b = ರಿಕ್ತ;
	ಯದಿ (nul == ರಿಕ್ತ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		ಪ್ರತ್ಯಾಗಮ;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	ಯದಿ (size == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	ವರ್ಣ *s = dup_n(data, size);
	ವರ್ಣ *a = ರಿಕ್ತ, *b = ರಿಕ್ತ;
	split_two(data, size, &a, &b);
	ಯದಿ (s == ರಿಕ್ತ || a == ರಿಕ್ತ || b == ರಿಕ್ತ) {
		ಮುಕ್ತ(s);
		ಮುಕ್ತ(a);
		ಮುಕ್ತ(b);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	{
		ವರ್ಣ *u = ರಿಕ್ತ, *h = ರಿಕ್ತ;
		ಪೂರ್ಣಾಙ್ಕ port = 0;
		ಯದಿ (parse_user_host_port(s, &u, &h, &port) == 0) {
			ಮುಕ್ತ(u);
			ಮುಕ್ತ(h);
		}
	}
	{
		ವರ್ಣ *u = ರಿಕ್ತ, *h = ರಿಕ್ತ, *p = ರಿಕ್ತ;
		ಪೂರ್ಣಾಙ್ಕ port = 0;
		ಯದಿ (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			ಮುಕ್ತ(u);
			ಮುಕ್ತ(h);
			ಮುಕ್ತ(p);
		}
	}
	(ಶೂನ್ಯ)convtime(s);
	(ಶೂನ್ಯ)a2port(s);
	{
		ಪೂರ್ಣಾಙ್ಕ tun = 0;
		(ಶೂನ್ಯ)a2tun(s, &tun);
	}
	{
		ಪೂರ್ಣಾಙ್ಕ ac = 0;
		ವರ್ಣ **av = ರಿಕ್ತ;
		ಯದಿ (argv_split(s, &ac, &av, 1) == 0) {
			ವರ್ಣ *back = argv_assemble(ac, av);
			ಮುಕ್ತ(back);
			argv_free(av, ac);
		}
	}
	{
		ಧ್ರುವ ವರ್ಣ *err = ರಿಕ್ತ;
		(ಶೂನ್ಯ)valid_domain(s, 0, &err);
	}
	(ಶೂನ್ಯ)valid_env_name(s);
	{
		uint64_t t = 0;
		(ಶೂನ್ಯ)parse_absolute_time(s, &t);
	}

	{
		ಸಂರಚನಾ xaddr n;
		(ಶೂನ್ಯ)addr_pton(s, &n);
	}
	{
		ಸಂರಚನಾ xaddr n;
		u_int prefix = 0;
		(ಶೂನ್ಯ)addr_pton_cidr(s, &n, &prefix);
	}

	(ಶೂನ್ಯ)addr_match_list(a, b);
	(ಶೂನ್ಯ)addr_match_cidr_list(a, b);
	(ಶೂನ್ಯ)match_pattern(a, b);
	(ಶೂನ್ಯ)match_pattern_list(a, b, 0);
	(ಶೂನ್ಯ)match_hostname(a, b);
	(ಶೂನ್ಯ)match_host_and_ip(a, "127.0.0.1", b);
	(ಶೂನ್ಯ)match_user("fuzz", a, "127.0.0.1", b);

	ಮುಕ್ತ(s);
	ಮುಕ್ತ(a);
	ಮುಕ್ತ(b);
	ಪ್ರತ್ಯಾಗಮ 0;
}
