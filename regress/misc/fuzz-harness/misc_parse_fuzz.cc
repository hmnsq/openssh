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

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <sys/types.h>

வெளி "C" {
#அந்தர்பாவ "addr.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "log.h"
}

நிலையான முழு log_initialized = 0;

நிலையான எழுத்து *
dup_n(மாறிலி uint8_t *body, size_t blen)
{
	எழுத்து *s = (எழுத்து *)malloc(blen + 1);
	எனில் (s == வெற்று)
		திரும்பு வெற்று;
	memcpy(s, body, blen);
	s[blen] = '\0';
	திரும்பு s;
}

நிலையான வெறுமை
split_two(மாறிலி uint8_t *body, size_t blen, எழுத்து **a, எழுத்து **b)
{
	மாறிலி uint8_t *nul = (மாறிலி uint8_t *)memchr(body, 0, blen);
	*a = வெற்று;
	*b = வெற்று;
	எனில் (nul == வெற்று) {
		*a = dup_n(body, blen);
		*b = strdup("");
		திரும்பு;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

வெளி "C" முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	எனில் (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	எனில் (size == 0)
		திரும்பு 0;

	எழுத்து *s = dup_n(data, size);
	எழுத்து *a = வெற்று, *b = வெற்று;
	split_two(data, size, &a, &b);
	எனில் (s == வெற்று || a == வெற்று || b == வெற்று) {
		விடுவி(s);
		விடுவி(a);
		விடுவி(b);
		திரும்பு 0;
	}

	{
		எழுத்து *u = வெற்று, *h = வெற்று;
		முழு port = 0;
		எனில் (parse_user_host_port(s, &u, &h, &port) == 0) {
			விடுவி(u);
			விடுவி(h);
		}
	}
	{
		எழுத்து *u = வெற்று, *h = வெற்று, *p = வெற்று;
		முழு port = 0;
		எனில் (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			விடுவி(u);
			விடுவி(h);
			விடுவி(p);
		}
	}
	(வெறுமை)convtime(s);
	(வெறுமை)a2port(s);
	{
		முழு tun = 0;
		(வெறுமை)a2tun(s, &tun);
	}
	{
		முழு ac = 0;
		எழுத்து **av = வெற்று;
		எனில் (argv_split(s, &ac, &av, 1) == 0) {
			எழுத்து *back = argv_assemble(ac, av);
			விடுவி(back);
			argv_free(av, ac);
		}
	}
	{
		மாறிலி எழுத்து *err = வெற்று;
		(வெறுமை)valid_domain(s, 0, &err);
	}
	(வெறுமை)valid_env_name(s);
	{
		uint64_t t = 0;
		(வெறுமை)parse_absolute_time(s, &t);
	}

	{
		கட்டமைப்பு xaddr n;
		(வெறுமை)addr_pton(s, &n);
	}
	{
		கட்டமைப்பு xaddr n;
		u_int prefix = 0;
		(வெறுமை)addr_pton_cidr(s, &n, &prefix);
	}

	(வெறுமை)addr_match_list(a, b);
	(வெறுமை)addr_match_cidr_list(a, b);
	(வெறுமை)match_pattern(a, b);
	(வெறுமை)match_pattern_list(a, b, 0);
	(வெறுமை)match_hostname(a, b);
	(வெறுமை)match_host_and_ip(a, "127.0.0.1", b);
	(வெறுமை)match_user("fuzz", a, "127.0.0.1", b);

	விடுவி(s);
	விடுவி(a);
	விடுவி(b);
	திரும்பு 0;
}
