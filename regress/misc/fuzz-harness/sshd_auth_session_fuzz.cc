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

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>

வெளி "C" வெறுமை fuzz_userauth_one(மாறிலி uint8_t *data, size_t size);

வெளி "C" முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	fuzz_userauth_one(data, size);
	திரும்பு 0;
}
