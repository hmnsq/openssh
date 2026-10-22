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

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <sys/types.h>

ബാഹ്യ "C" {
#അന്തര്ഭാവ "addr.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"
}

സ്ഥിതം പൂർണ്ണസംഖ്യ log_initialized = 0;

സ്ഥിതം അക്ഷരം *
dup_n(സ്ഥിരം uint8_t *body, size_t blen)
{
	അക്ഷരം *s = (അക്ഷരം *)malloc(blen + 1);
	എങ്കിൽ (s == ശൂന്യ)
		തിരികെ ശൂന്യ;
	memcpy(s, body, blen);
	s[blen] = '\0';
	തിരികെ s;
}

സ്ഥിതം ശൂന്യം
split_two(സ്ഥിരം uint8_t *body, size_t blen, അക്ഷരം **a, അക്ഷരം **b)
{
	സ്ഥിരം uint8_t *nul = (സ്ഥിരം uint8_t *)memchr(body, 0, blen);
	*a = ശൂന്യ;
	*b = ശൂന്യ;
	എങ്കിൽ (nul == ശൂന്യ) {
		*a = dup_n(body, blen);
		*b = strdup("");
		തിരികെ;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	എങ്കിൽ (size == 0)
		തിരികെ 0;

	അക്ഷരം *s = dup_n(data, size);
	അക്ഷരം *a = ശൂന്യ, *b = ശൂന്യ;
	split_two(data, size, &a, &b);
	എങ്കിൽ (s == ശൂന്യ || a == ശൂന്യ || b == ശൂന്യ) {
		സ്വതന്ത്രം(s);
		സ്വതന്ത്രം(a);
		സ്വതന്ത്രം(b);
		തിരികെ 0;
	}

	{
		അക്ഷരം *u = ശൂന്യ, *h = ശൂന്യ;
		പൂർണ്ണസംഖ്യ port = 0;
		എങ്കിൽ (parse_user_host_port(s, &u, &h, &port) == 0) {
			സ്വതന്ത്രം(u);
			സ്വതന്ത്രം(h);
		}
	}
	{
		അക്ഷരം *u = ശൂന്യ, *h = ശൂന്യ, *p = ശൂന്യ;
		പൂർണ്ണസംഖ്യ port = 0;
		എങ്കിൽ (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			സ്വതന്ത്രം(u);
			സ്വതന്ത്രം(h);
			സ്വതന്ത്രം(p);
		}
	}
	(ശൂന്യം)convtime(s);
	(ശൂന്യം)a2port(s);
	{
		പൂർണ്ണസംഖ്യ tun = 0;
		(ശൂന്യം)a2tun(s, &tun);
	}
	{
		പൂർണ്ണസംഖ്യ ac = 0;
		അക്ഷരം **av = ശൂന്യ;
		എങ്കിൽ (argv_split(s, &ac, &av, 1) == 0) {
			അക്ഷരം *back = argv_assemble(ac, av);
			സ്വതന്ത്രം(back);
			argv_free(av, ac);
		}
	}
	{
		സ്ഥിരം അക്ഷരം *err = ശൂന്യ;
		(ശൂന്യം)valid_domain(s, 0, &err);
	}
	(ശൂന്യം)valid_env_name(s);
	{
		uint64_t t = 0;
		(ശൂന്യം)parse_absolute_time(s, &t);
	}

	{
		ഘടന xaddr n;
		(ശൂന്യം)addr_pton(s, &n);
	}
	{
		ഘടന xaddr n;
		u_int prefix = 0;
		(ശൂന്യം)addr_pton_cidr(s, &n, &prefix);
	}

	(ശൂന്യം)addr_match_list(a, b);
	(ശൂന്യം)addr_match_cidr_list(a, b);
	(ശൂന്യം)match_pattern(a, b);
	(ശൂന്യം)match_pattern_list(a, b, 0);
	(ശൂന്യം)match_hostname(a, b);
	(ശൂന്യം)match_host_and_ip(a, "127.0.0.1", b);
	(ശൂന്യം)match_user("fuzz", a, "127.0.0.1", b);

	സ്വതന്ത്രം(s);
	സ്വതന്ത്രം(a);
	സ്വതന്ത്രം(b);
	തിരികെ 0;
}
