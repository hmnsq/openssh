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

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>

બાહ્ય "C" શૂન્ય fuzz_userauth_one(અચલ uint8_t *data, size_t size);

બાહ્ય "C" પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	fuzz_userauth_one(data, size);
	પાછા 0;
}
