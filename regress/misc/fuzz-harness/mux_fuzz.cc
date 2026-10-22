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

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>

ബാഹ്യ "C" ശൂന്യം fuzz_mux_one(സ്ഥിരം uint8_t *data, size_t size);

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	fuzz_mux_one(data, size);
	തിരികെ 0;
}
