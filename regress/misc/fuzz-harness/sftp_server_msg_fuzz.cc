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

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>

বাহ্য "C" শূন্য fuzz_server_one(ধ্রুব uint8_t *data, size_t size);

বাহ্য "C" পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t *data, size_t size)
{
	fuzz_server_one(data, size);
	প্রত্যাগম 0;
}
